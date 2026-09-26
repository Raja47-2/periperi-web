/** Finding construction shared by the source, binary and artifact inspectors. */

import { recommendation } from './recommendations'
import { classicalRisk, quantumRisk, type QuantumRisk } from './risk'

export interface Finding {
  type: string
  category: string
  name: string
  algorithm: string | null
  file: string
  line: number
  evidence: string
  risk: string
  reason: string
  quantum_risk: string
  quantum: QuantumRisk
  recommendation: string
}

export interface FindingInput {
  category: string
  name: string
  path: string
  line: number
  evidence: string
  sensitivity: string
  migration_complexity: string
  threat_timeline: number
}

export function makeFinding(input: FindingInput): Finding {
  const [risk, why] = classicalRisk(input.name, input.category)
  const quantum = quantumRisk(
    input.category === 'Algorithm' ? input.name : null,
    input.sensitivity,
    input.migration_complexity,
    input.threat_timeline,
  )
  return {
    type: input.category.toLowerCase(),
    category: input.category,
    name: input.name,
    algorithm: input.category === 'Algorithm' ? input.name : null,
    file: input.path.replace(/\\/g, '/'),
    line: input.line,
    evidence: input.evidence,
    risk,
    reason: why,
    quantum_risk: quantum.level,
    quantum,
    recommendation: recommendation(input.name, input.category, risk),
  }
}
