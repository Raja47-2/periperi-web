/** CBOM-style report generation from a completed scan. */

import type { Finding } from './finding'

export interface Summary {
  files_scanned: number
  files_skipped: number
  findings: number
  critical: number
  high: number
  medium: number
  low: number
  info: number
  risk_distribution: Record<string, number>
  quantum_distribution: Record<string, number>
  category_distribution: Record<string, number>
}

export function buildSummary(findings: Finding[], filesScanned: number, filesSkipped = 0): Summary {
  const risks: Record<string, number> = {}
  const quantum: Record<string, number> = {}
  const categories: Record<string, number> = {}
  for (const item of findings) {
    risks[item.risk] = (risks[item.risk] ?? 0) + 1
    quantum[item.quantum_risk] = (quantum[item.quantum_risk] ?? 0) + 1
    const key = item.category.toLowerCase()
    categories[key] = (categories[key] ?? 0) + 1
  }
  return {
    files_scanned: filesScanned,
    files_skipped: filesSkipped,
    findings: findings.length,
    critical: risks.critical ?? 0,
    high: risks.high ?? 0,
    medium: risks.medium ?? 0,
    low: risks.low ?? 0,
    info: risks.info ?? 0,
    risk_distribution: risks,
    quantum_distribution: quantum,
    category_distribution: categories,
  }
}

export function buildCbom(scan: Record<string, unknown>): Record<string, unknown> {
  const findings = scan.findings as Finding[]
  const byCategory: Record<string, string[]> = {}
  for (const category of ['Algorithm', 'Library', 'Certificate', 'Key', 'HSM']) {
    const names = findings
      .filter((item) => item.category === category)
      .map((item) => item.name)
    byCategory[`${category.toLowerCase()}s`] = [...new Set(names)].sort()
  }
  return {
    specification: 'Periperi CBOM Prototype 1.0',
    disclaimer: 'Rule-based prototype inventory; validate findings before security decisions.',
    scan_id: scan.id,
    project_name: scan.project_name,
    generated_at: new Date().toISOString(),
    scan_created_at: scan.created_at,
    summary: scan.summary,
    assumptions: scan.assumptions,
    input_type: scan.input_type ?? 'project-directory',
    engines: scan.engines ?? {},
    inventory: byCategory,
    findings,
  }
}
