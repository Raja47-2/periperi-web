/** D1-backed scan history, replacing the prototype's local SQLite file. */

import { buildSummary } from './cbom'
import type { Finding } from './finding'
import type { Summary } from './cbom'

export interface StoredScan {
  id: string
  project_name: string
  created_at: string
  result_json: string
}

export interface ScanListItem {
  id: string
  project_name: string
  created_at: string
  summary: Summary
}

export function initialize(env: Env): void {
  // D1 has no migrate-on-boot hook, so the table is created idempotently here.
  env.DB.exec(
    `CREATE TABLE IF NOT EXISTS scans (
       id TEXT PRIMARY KEY,
       project_name TEXT NOT NULL,
       created_at TEXT NOT NULL,
       result_json TEXT NOT NULL
     )`,
  )
}

export async function saveScan(env: Env, scan: Record<string, unknown>): Promise<void> {
  await env.DB.prepare(
    'INSERT OR REPLACE INTO scans (id, project_name, created_at, result_json) VALUES (?, ?, ?, ?)',
  )
    .bind(scan.id as string, scan.project_name as string, scan.created_at as string, JSON.stringify(scan))
    .run()
}

export async function getScan(env: Env, scanId: string): Promise<Record<string, unknown> | null> {
  const row = await env.DB.prepare('SELECT result_json FROM scans WHERE id = ?').bind(scanId).first<StoredScan>()
  return row ? (JSON.parse(row.result_json) as Record<string, unknown>) : null
}

export async function listScans(env: Env, limit = 20): Promise<ScanListItem[]> {
  const { results } = await env.DB.prepare(
    'SELECT result_json FROM scans ORDER BY created_at DESC LIMIT ?',
  )
    .bind(limit)
    .all<StoredScan>()

  return results.map((row) => {
    const item = JSON.parse(row.result_json) as Record<string, unknown>
    return {
      id: item.id as string,
      project_name: item.project_name as string,
      created_at: item.created_at as string,
      summary: item.summary as Summary,
    }
  })
}

export { buildSummary }
export type { Finding }
