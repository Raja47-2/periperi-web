/** Scan orchestration over in-memory extracted files. */

import { buildSummary, type Summary } from './cbom'
import { detectFile, CERTIFICATE_SUFFIXES, KEY_SUFFIXES } from './detector'
import { makeFinding, type Finding } from './finding'
import {
  BINARY_SUFFIXES,
  engineDetails,
  inspectBinary,
  inspectCryptoArtifact,
  type ScanOptionsLike,
} from './inspector'
import {
  MAX_BINARY_SIZE,
  MAX_EXTRACTED_SIZE,
  MAX_FILES,
  MAX_TEXT_SIZE,
  MAX_UPLOAD_SIZE,
  ScanError,
  extractTar,
  extractZip,
  isSkipped,
  looksLikeContainer,
  type ExtractedFile,
} from './archive'

export interface ScanOptions extends ScanOptionsLike {}

const TEXT_SUFFIXES = new Set([
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp',
  '.go', '.rs', '.php', '.rb', '.cs', '.kt', '.swift', '.yaml', '.yml',
  '.json', '.xml', '.conf', '.config', '.ini', '.env', '.txt', '.md', '.toml',
  '.properties', '.gradle', '.lock', '.sh', '.ps1', '.dockerfile',
])
const SPECIAL_FILENAMES = new Set(['dockerfile', 'makefile', 'requirements.txt', 'package-lock.json'])

function suffixOf(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(dot).toLowerCase() : ''
}

function isSupported(name: string): boolean {
  const suffix = suffixOf(name)
  return (
    TEXT_SUFFIXES.has(suffix) ||
    CERTIFICATE_SUFFIXES.has(suffix) ||
    KEY_SUFFIXES.has(suffix) ||
    BINARY_SUFFIXES.has(suffix) ||
    SPECIAL_FILENAMES.has(name.toLowerCase())
  )
}

function isBinaryData(data: Uint8Array): boolean {
  const window = data.subarray(0, 8192)
  return window.includes(0)
}

/** Scan an in-memory file set and produce the same result shape as the prototype. */
export async function scanFiles(
  files: ExtractedFile[],
  projectName: string,
  options: ScanOptions,
): Promise<Record<string, unknown>> {
  let filesScanned = 0
  let filesSkipped = 0
  const findings: Finding[] = []

  for (const file of files) {
    if (filesScanned + filesSkipped >= MAX_FILES) {
      throw new ScanError(`Project exceeds the ${MAX_FILES.toLocaleString()}-file scan limit.`)
    }
    if (!isSupported(file.name)) {
      filesSkipped += 1
      continue
    }
    const isBinary = BINARY_SUFFIXES.has(suffixOf(file.name))
    const limit = isBinary ? MAX_BINARY_SIZE : MAX_TEXT_SIZE
    if (file.data.length > limit) {
      filesSkipped += 1
      continue
    }

    const artifactFindings = await inspectCryptoArtifact(file.name, file.path, file.data, options)
    findings.push(...artifactFindings)

    if (isBinary || isBinaryData(file.data)) {
      findings.push(...inspectBinary(file.path, file.data, options))
    } else if (artifactFindings.length === 0) {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(file.data)
      findings.push(
        ...detectFile(
          file.name,
          file.path,
          text,
          options.sensitivity,
          options.migration_complexity,
          options.threat_timeline,
        ),
      )
    }
    filesScanned += 1
  }

  findings.forEach((finding, index) => {
    finding.id = `F-${String(index + 1).padStart(4, '0')}`
  })

  return {
    project_name: projectName,
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    findings,
    assumptions: {
      sensitivity: options.sensitivity,
      migration_complexity: options.migration_complexity,
      threat_timeline: options.threat_timeline,
    },
    engines: engineStatus(),
  }
}

/**
 * Container tool status. Syft and Trivy require native binaries, which the
 * Workers runtime cannot execute, so both are reported as unavailable.
 */
export function engineStatus(): Record<string, unknown> {
  return {
    openssl: engineDetails(),
    syft: { available: false, version: null, scan: 'unavailable', note: 'Native CLI execution is not supported in the Workers runtime.' },
    trivy: { available: false, version: null, scan: 'unavailable', note: 'Native CLI execution is not supported in the Workers runtime.' },
  }
}

/** Expand any nested layer TARs so container image archives are scanned. */
export async function expandContainerLayers(
  files: ExtractedFile[],
): Promise<{ files: ExtractedFile[]; layerCount: number }> {
  const layers = files.filter((file) => file.name.toLowerCase().endsWith('.tar')).slice(0, 100)
  const expanded: ExtractedFile[] = []
  let layerCount = 0

  for (const [index, layer] of layers.entries()) {
    try {
      const contents = await extractTar(layer.data, false)
      expanded.push(
        ...contents.map((entry) => ({
          ...entry,
          path: `ecdat_layers/layer-${String(index + 1).padStart(3, '0')}/${entry.path}`,
        })),
      )
      layerCount += 1
    } catch {
      continue
    }
  }

  return { files: [...files, ...expanded], layerCount }
}

/** Scan an uploaded repository ZIP, container archive, binary, certificate or key. */
export async function scanUpload(
  upload: Uint8Array,
  filename: string,
  options: ScanOptions,
): Promise<Record<string, unknown>> {
  if (upload.length > MAX_UPLOAD_SIZE) throw new ScanError('Upload exceeds the 100 MB limit.')

  const lower = filename.toLowerCase()

  if (lower.endsWith('.zip')) {
    const files = await extractZip(upload)
    const result = await scanFiles(files, stemOf(filename), options)
    result.input_type = 'repository-archive'
    return result
  }

  if (lower.endsWith('.tar') || lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) {
    const gzipped = lower.endsWith('.tar.gz') || lower.endsWith('.tgz')
    const files = await extractTar(upload, gzipped)
    const isContainer = looksLikeContainer(files.map((file) => file.path))
    let layerCount = 0
    let working = files
    if (isContainer) {
      const expanded = await expandContainerLayers(files)
      working = expanded.files
      layerCount = expanded.layerCount
    }
    const result = await scanFiles(working, filename, options)
    result.input_type = isContainer ? 'container-image' : 'repository-archive'
    result.container_layers_scanned = layerCount
    return result
  }

  const result = await scanFiles(
    [{ path: filename, name: filename, data: upload }],
    filename,
    options,
  )
  result.input_type = 'binary-or-cryptographic-artifact'
  return result
}

function stemOf(filename: string): string {
  const base = filename.split('/').pop() ?? filename
  return base.replace(/\.[^.]+$/, '') || 'uploaded-project'
}

export { MAX_EXTRACTED_SIZE, isSkipped }
export type { Summary }
export { buildSummary, makeFinding }
