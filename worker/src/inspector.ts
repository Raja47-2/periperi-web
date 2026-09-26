/**
 * Cryptographic artefact inspection and binary fingerprinting.
 *
 * The Python prototype parses artefacts with the OpenSSL backend. Cloudflare
 * Workers cannot load native OpenSSL, so this port uses WebCrypto where the
 * runtime supports it and reports the cases it cannot inspect rather than
 * silently skipping them.
 */

import { makeFinding, type Finding } from './finding'

export const BINARY_SUFFIXES = new Set([
  '.exe', '.dll', '.so', '.dylib', '.a', '.lib', '.o', '.obj', '.class',
  '.jar', '.war', '.ear', '.wasm', '.bin', '.apk', '.ipa',
])

interface Signature {
  category: string
  name: string
  expression: RegExp
}

export const BINARY_SIGNATURES: Signature[] = [
  { category: 'Library', name: 'OpenSSL', expression: /(?:OpenSSL|libcrypto|libssl|EVP_[A-Za-z0-9_]+)/i },
  { category: 'Library', name: 'libsodium', expression: /(?:libsodium|sodium_init|crypto_secretbox)/i },
  { category: 'Algorithm', name: 'MD5', expression: /(?:EVP_md5|MD5_(?:Init|Update|Final)|\bMD5\b)/i },
  { category: 'Algorithm', name: 'SHA-1', expression: /(?:EVP_sha1|SHA1_(?:Init|Update|Final)|\bSHA-?1\b)/i },
  { category: 'Algorithm', name: 'SHA-256', expression: /(?:EVP_sha256|SHA256_(?:Init|Update|Final)|\bSHA-?256\b)/i },
  { category: 'Algorithm', name: 'AES-256-GCM', expression: /(?:EVP_aes_256_gcm|AES-?256-?GCM)/i },
  { category: 'Algorithm', name: 'AES-ECB', expression: /(?:EVP_aes_(?:128|192|256)_ecb|AES-?(?:128|192|256)?-?ECB)/i },
  { category: 'Algorithm', name: 'RSA', expression: /(?:EVP_PKEY_RSA|RSA_(?:new|sign|verify)|\bRSA\b)/i },
  { category: 'Algorithm', name: 'ECDSA', expression: /(?:ECDSA_(?:sign|verify)|\bECDSA\b)/i },
  { category: 'Algorithm', name: 'ECDH', expression: /(?:ECDH_compute_key|\bECDH\b)/i },
]

export function engineDetails(): Record<string, string> {
  return {
    provider: 'Cloudflare WebCrypto (no native OpenSSL)',
    version: 'Workers runtime',
  }
}

function artifactFinding(
  category: string,
  name: string,
  relativePath: string,
  evidence: string,
  options: ScanOptionsLike,
): Finding {
  return makeFinding({
    category,
    name,
    path: relativePath,
    line: 0,
    evidence,
    sensitivity: options.sensitivity,
    migration_complexity: options.migration_complexity,
    threat_timeline: options.threat_timeline,
  })
}

export interface ScanOptionsLike {
  sensitivity: string
  migration_complexity: string
  threat_timeline: number
}

function suffixOf(name: string): string {
  const dot = name.lastIndexOf('.')
  return dot > 0 ? name.slice(dot).toLowerCase() : ''
}

function pemBody(text: string, label: string): string | null {
  const pattern = new RegExp(`-----BEGIN ${label}-----([\\s\\S]*?)-----END ${label}-----`)
  const match = text.match(pattern)
  if (!match) return null
  return match[1].replace(/\s+/g, '')
}

/** Derive a human-readable key name from WebCrypto algorithm metadata. */
function keyName(algorithm: KeyAlgorithm | null): string | null {
  if (!algorithm) return null
  const name = (algorithm as { name?: string }).name ?? ''
  const named = algorithm as { namedCurve?: string }
  if (name === 'RSA-PSS' || name === 'RSASSA-PKCS1-v1_5') {
    const bits = (algorithm as { modulusLength?: number }).modulusLength
    return bits ? `RSA-${bits}` : 'RSA'
  }
  if (name === 'ECDSA' || name === 'ECDH') {
    return named.namedCurve ? `ECC ${named.namedCurve}` : 'ECC'
  }
  return null
}

async function tryImport(label: string, format: 'spki' | 'pkcs8', pem: string): Promise<CryptoKey | null> {
  try {
    const raw = Uint8Array.from(atob(pem), (char) => char.charCodeAt(0))
    return await crypto.subtle.importKey(format, raw, undefined, false, ['sign', 'verify'])
  } catch {
    return null
  }
}

/**
 * Inspect certificates and keys without exposing key material.
 * Returns findings for what the runtime can parse; unsupported containers
 * produce an explicit finding rather than a silent gap.
 */
export async function inspectCryptoArtifact(
  filename: string,
  relativePath: string,
  data: Uint8Array,
  options: ScanOptionsLike,
): Promise<Finding[]> {
  const findings: Finding[] = []
  const suffix = suffixOf(filename)
  const asText = new TextDecoder('latin1').decode(data)

  if (suffix === '.p12' || suffix === '.pfx') {
    // PKCS#12 requires PBES/PBKDF2 + ASN.1 parsing; WebCrypto cannot open it.
    return [
      artifactFinding(
        'Key',
        'Uninspectable PKCS#12 key store',
        relativePath,
        'PKCS#12 containers cannot be parsed in the Workers runtime; run the Python backend for full key-store inspection',
        options,
      ),
    ]
  }

  if (asText.includes('-----BEGIN CERTIFICATE-----')) {
    return [
      artifactFinding(
        'Certificate',
        'X.509 certificate',
        relativePath,
        'PEM certificate header detected; issuer, expiry and key strength require the Python OpenSSL backend',
        options,
      ),
    ]
  }

  if (asText.includes('-----BEGIN') && asText.includes('PRIVATE KEY-----')) {
    const body = pemBody(asText, '(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY')
    const imported = body ? await tryImport('private key', 'pkcs8', body) : null
    if (imported) {
      const name = keyName(imported.algorithm)
      findings.push(
        artifactFinding('Key', 'Private key detected', relativePath, '[key material redacted; validated by WebCrypto]', options),
      )
      if (name) {
        findings.push(artifactFinding('Algorithm', name, relativePath, 'WebCrypto parsed private-key parameters', options))
      }
      return findings
    }
    // Encrypted or non-parseable private key: still report the presence.
    findings.push(
      artifactFinding('Key', 'Private key detected', relativePath, '[key material redacted; header only, contents not parsed]', options),
    )
    return findings
  }

  if (asText.includes('-----BEGIN') && asText.includes('PUBLIC KEY-----')) {
    const body = pemBody(asText, '(?:RSA )?PUBLIC KEY')
    const imported = body ? await tryImport('public key', 'spki', body) : null
    if (imported) {
      const name = keyName(imported.algorithm)
      findings.push(artifactFinding('Key', 'Public key detected', relativePath, 'WebCrypto parsed public-key structure', options))
      if (name) {
        findings.push(artifactFinding('Algorithm', name, relativePath, 'WebCrypto parsed public-key parameters', options))
      }
      return findings
    }
    findings.push(artifactFinding('Key', 'Public key detected', relativePath, 'Public-key PEM header detected', options))
    return findings
  }

  return findings
}

/** Find crypto-linked symbols and embedded names without executing the binary. */
export function inspectBinary(relativePath: string, data: Uint8Array, options: ScanOptionsLike): Finding[] {
  const findings: Finding[] = []
  const seen = new Set<string>()
  const text = new TextDecoder('latin1').decode(data)
  for (const { category, name, expression } of BINARY_SIGNATURES) {
    const match = text.match(expression)
    const key = `${category}|${name}`
    if (match && !seen.has(key)) {
      seen.add(key)
      findings.push(
        artifactFinding(category, name, relativePath, `Binary symbol/string: ${match[0].slice(0, 80)}`, options),
      )
    }
  }
  return findings
}
