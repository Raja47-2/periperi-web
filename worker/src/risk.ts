/** Transparent prototype risk and quantum-readiness rules. */

export interface QuantumRisk {
  level: string
  reason: string
  x: number | null
  y: number | null
  z: number
  margin: number | null
}

export const DATA_LIFETIME_YEARS: Record<string, number> = {
  ephemeral: 1,
  internal: 5,
  pii: 10,
  financial: 12,
  high_sensitivity: 20,
}

export const MIGRATION_YEARS: Record<string, number> = {
  small_project: 1,
  standard_application: 3,
  legacy_application: 5,
  complex_system: 7,
}

const QUANTUM_VULNERABLE = ["RSA", "ECC", "ECDSA", "ECDH", "DSA", "DH"]

/** Return a deliberately conservative, explainable classical risk rating. */
export function classicalRisk(name: string, category: string): [string, string] {
  const upper = name.toUpperCase()
  if (category === 'Key' && upper.includes('PRIVATE')) {
    return ['critical', 'Private-key material appears to be stored with the project.']
  }
  if (['MD5', 'SHA-1', 'SHA1', 'RSA-1024', 'DES', 'RC4'].some((token) => upper.includes(token))) {
    return ['high', 'The detected primitive is deprecated or below modern security expectations.']
  }
  if (category === 'Certificate') {
    return ['medium', 'The certificate should be checked for expiry, trust and key strength.']
  }
  if (['ECB', 'RSA-2048', 'DSA', 'DH'].some((token) => upper.includes(token))) {
    return ['medium', 'The configuration is usable in some contexts but needs security review.']
  }
  if (category === 'HSM' || category === 'Library') {
    return ['info', 'Inventory signal detected; configuration determines the actual risk.']
  }
  return ['low', 'No immediate classical weakness is identified by the prototype rule set.']
}

/** Apply Mosca's X + Y > Z inequality using explicit prototype assumptions. */
export function quantumRisk(
  algorithm: string | null,
  sensitivity = 'pii',
  migrationComplexity = 'standard_application',
  threatTimeline = 15,
): QuantumRisk {
  const normalized = (algorithm ?? '').toUpperCase()
  const family = QUANTUM_VULNERABLE.find((item) => normalized.includes(item))
  if (!family) {
    return {
      level: 'not_applicable',
      reason: 'Mosca timeline scoring is reserved for quantum-vulnerable public-key algorithms.',
      x: null,
      y: null,
      z: threatTimeline,
      margin: null,
    }
  }

  const x = DATA_LIFETIME_YEARS[sensitivity] ?? DATA_LIFETIME_YEARS.pii
  const y = MIGRATION_YEARS[migrationComplexity] ?? MIGRATION_YEARS.standard_application
  const margin = threatTimeline - (x + y)
  let level: string
  if (margin < 0) level = 'critical'
  else if (margin <= 3) level = 'high'
  else if (margin <= 7) level = 'medium'
  else level = 'low'

  return {
    level,
    reason:
      `${family} is vulnerable to sufficiently capable quantum attacks. ` +
      `The prototype margin is ${margin} years under the selected assumptions.`,
    x,
    y,
    z: threatTimeline,
    margin,
  }
}
