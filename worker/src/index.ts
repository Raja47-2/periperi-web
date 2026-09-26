/**
 * Periperi API on Cloudflare Workers.
 *
 * Mirrors the FastAPI prototype's routes and response shapes. Capabilities the
 * Workers runtime cannot provide (native OpenSSL parsing, Syft/Trivy) are
 * reported explicitly through the `engines` field instead of failing silently.
 */

import { buildCbom, buildSummary } from './cbom'
import { extractZip, ScanError, MAX_UPLOAD_SIZE } from './archive'
import { engineStatus, scanFiles, scanUpload, type ScanOptions } from './scanner'
import { getScan, initialize, listScans, saveScan } from './storage'
import { SAMPLE_ZIP_BASE64 } from './sample-data'

export interface Env {
  DB: D1Database
  ALLOWED_ORIGIN?: string
}

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' }

const SENSITIVITY = new Set(['ephemeral', 'internal', 'pii', 'financial', 'high_sensitivity'])
const COMPLEXITY = new Set(['small_project', 'standard_application', 'legacy_application', 'complex_system'])

function corsHeaders(env: Env, request: Request): Record<string, string> {
  const origin = env.ALLOWED_ORIGIN ?? request.headers.get('origin') ?? '*'
  return {
    'access-control-allow-origin': origin,
    'access-control-allow-credentials': 'true',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'vary': 'Origin',
  }
}

function json(data: unknown, status = 200, env?: Env, request?: Request): Response {
  const cors = env && request ? corsHeaders(env, request) : {}
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...cors } })
}

function fail(detail: string, status: number, env: Env, request: Request): Response {
  return json({ detail }, status, env, request)
}

function readOptions(sensitivity: string, migrationComplexity: string, timeline: string): ScanOptions {
  if (!SENSITIVITY.has(sensitivity)) throw new ScanError('Unsupported data sensitivity value.')
  if (!COMPLEXITY.has(migrationComplexity)) throw new ScanError('Unsupported migration complexity value.')
  const threatTimeline = Number(timeline)
  if (!Number.isInteger(threatTimeline) || threatTimeline < 5 || threatTimeline > 50) {
    throw new ScanError('Threat timeline must be between 5 and 50 years.')
  }
  return { sensitivity, migration_complexity: migrationComplexity, threat_timeline: threatTimeline }
}

function completeScan(result: Record<string, unknown>): Record<string, unknown> {
  result.id = crypto.randomUUID()
  result.created_at = new Date().toISOString()
  const findings = (result.findings ?? []) as never[]
  result.summary = buildSummary(
    findings,
    (result.files_scanned as number) ?? 0,
    (result.files_skipped as number) ?? 0,
  )
  return result
}

async function handleHealth(env: Env, request: Request): Promise<Response> {
  return json({ status: 'ok', service: 'periperi', engines: engineStatus() }, 200, env, request)
}

async function handleListScans(env: Env, request: Request): Promise<Response> {
  return json(await listScans(env), 200, env, request)
}

async function handleSampleScan(url: URL, env: Env, request: Request): Promise<Response> {
  const options = readOptions(
    url.searchParams.get('sensitivity') ?? 'pii',
    url.searchParams.get('migration_complexity') ?? 'standard_application',
    url.searchParams.get('threat_timeline') ?? '15',
  )
  const bytes = Uint8Array.from(atob(SAMPLE_ZIP_BASE64), (char) => char.charCodeAt(0))
  const files = await extractZip(bytes)
  const result = await scanFiles(files, 'demo-project', options)
  result.input_type = 'project-directory'
  return json(completeScan(result), 200, env, request)
}

async function handleUploadScan(request: Request, env: Env): Promise<Response> {
  let form: FormData
  try {
    form = await request.formData()
  } catch {
    return fail('Expected a multipart form upload.', 400, env, request)
  }

  const file = form.get('file')
  if (!(file instanceof File) || !file.name) {
    return fail('Choose a repository archive, container archive, binary, certificate or key.', 400, env, request)
  }
  if (file.size > MAX_UPLOAD_SIZE) {
    return fail('Upload exceeds the 100 MB limit.', 400, env, request)
  }

  const options = readOptions(
    String(form.get('sensitivity') ?? 'pii'),
    String(form.get('migration_complexity') ?? 'standard_application'),
    String(form.get('threat_timeline') ?? '15'),
  )

  const bytes = new Uint8Array(await file.arrayBuffer())
  return json(completeScan(await scanUpload(bytes, file.name, options)), 200, env, request)
}

async function handleScanDetail(scanId: string, env: Env, request: Request): Promise<Response> {
  const scan = await getScan(env, scanId)
  if (!scan) return fail('Scan not found.', 404, env, request)
  return json(scan, 200, env, request)
}

async function handleReport(scanId: string, env: Env, request: Request): Promise<Response> {
  const scan = await getScan(env, scanId)
  if (!scan) return fail('Scan not found.', 404, env, request)
  return json(buildCbom(scan), 200, env, request)
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(env, request) })
    }

    try {
      initialize(env)
    } catch {
      // The table may already exist; a failure here must not block requests.
    }

    try {
      if (request.method === 'GET' && url.pathname === '/api/health') {
        return await handleHealth(env, request)
      }
      if (request.method === 'GET' && url.pathname === '/api/scans') {
        return await handleListScans(env, request)
      }
      if (request.method === 'POST' && url.pathname === '/api/scan') {
        return await handleUploadScan(request, env)
      }
      if (request.method === 'POST' && url.pathname === '/api/scan/sample') {
        return await handleSampleScan(url, env, request)
      }

      const detail = url.pathname.match(/^\/api\/scan\/([^/]+)$/)
      if (request.method === 'GET' && detail) {
        return await handleScanDetail(detail[1], env, request)
      }

      const report = url.pathname.match(/^\/api\/scan\/([^/]+)\/report$/)
      if (request.method === 'GET' && report) {
        return await handleReport(report[1], env, request)
      }

      return fail('Not found.', 404, env, request)
    } catch (error) {
      if (error instanceof ScanError) {
        return fail(error.message, 400, env, request)
      }
      const detail = error instanceof Error ? error.message : 'Unexpected error.'
      return fail(detail, 422, env, request)
    }
  },
}
