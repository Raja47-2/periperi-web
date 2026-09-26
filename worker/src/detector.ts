/** Pattern-based cryptographic discovery with secret-safe evidence handling. */

import { makeFinding, type Finding } from './finding'

export interface Pattern {
  category: string
  name: string
  expression: RegExp
}

export const PATTERNS: Pattern[] = [
  { category: 'Algorithm', name: 'AES-256-GCM', expression: /AES[-_ ]?256[-_ ]?GCM|EVP_aes_256_gcm/i },
  { category: 'Algorithm', name: 'AES-GCM', expression: /AES[-_ ]?GCM|AESGCM|AES\.new\([^\n]*MODE_GCM|EVP_aes_(?:128|192)_gcm/i },
  { category: 'Algorithm', name: 'AES-ECB', expression: /AES[-_ ]?ECB|MODE_ECB|EVP_aes_(?:128|192|256)_ecb/i },
  { category: 'Algorithm', name: 'AES', expression: /\bAES(?:[-_ ]?(?:128|192|256))?\b/i },
  { category: 'Algorithm', name: 'RSA-1024', expression: /RSA[^\n]{0,40}(?:1024|key_size\s*=\s*1024)/i },
  { category: 'Algorithm', name: 'RSA-2048', expression: /RSA[^\n]{0,40}(?:2048|key_size\s*=\s*2048)/i },
  { category: 'Algorithm', name: 'RSA', expression: /\bRSA\b|generate_private_key\s*\(|EVP_PKEY_RSA|RSA_(?:new|sign|verify)/i },
  { category: 'Algorithm', name: 'ECDSA', expression: /\bECDSA\b|ECDSA_(?:sign|verify)/i },
  { category: 'Algorithm', name: 'ECDH', expression: /\bECDH\b|ECDH_compute_key/i },
  { category: 'Algorithm', name: 'ECC', expression: /\bECC\b|EllipticCurve/i },
  { category: 'Algorithm', name: 'Diffie-Hellman', expression: /Diffie[- ]Hellman|\bDHParameters\b/i },
  { category: 'Algorithm', name: 'DSA', expression: /\bDSA\b/i },
  { category: 'Algorithm', name: 'SHA-1', expression: /\bSHA[-_ ]?1\b|sha1\s*\(|EVP_sha1|SHA1_(?:Init|Update|Final)/i },
  { category: 'Algorithm', name: 'SHA-256', expression: /\bSHA[-_ ]?256\b|sha256\s*\(|EVP_sha256|SHA256_(?:Init|Update|Final)/i },
  { category: 'Algorithm', name: 'SHA-384', expression: /\bSHA[-_ ]?384\b|sha384\s*\(/i },
  { category: 'Algorithm', name: 'SHA-512', expression: /\bSHA[-_ ]?512\b|sha512\s*\(/i },
  { category: 'Algorithm', name: 'MD5', expression: /\bMD5\b|md5\s*\(|EVP_md5|MD5_(?:Init|Update|Final)/i },
  { category: 'Algorithm', name: 'ChaCha20', expression: /\bChaCha20(?:Poly1305)?\b/i },
  { category: 'Library', name: 'OpenSSL', expression: /\bOpenSSL\b|<openssl\/|\blib(?:crypto|ssl)(?:\.so|\.dll|\.dylib)?\b|\bEVP_[A-Za-z0-9_]+/i },
  { category: 'Library', name: 'PyCryptodome', expression: /(?:from|import)\s+Crypto(?:\.|\b)|PyCryptodome/i },
  { category: 'Library', name: 'Python cryptography', expression: /(?:from|import)\s+cryptography(?:\.|\b)/i },
  { category: 'Library', name: 'libsodium', expression: /\blibsodium\b|\bsodium_(?:init|crypto)/i },
  { category: 'Library', name: 'Bouncy Castle', expression: /Bouncy\s*Castle|org\.bouncycastle/i },
  { category: 'Library', name: 'Web Crypto API', expression: /crypto\.subtle|SubtleCrypto/i },
  { category: 'Library', name: 'Node crypto', expression: /require\(['"]crypto['"]\)|from\s+['"](?:node:)?crypto['"]/i },
  { category: 'HSM', name: 'PKCS#11 / HSM', expression: /PKCS\s*#?11|hardware security module|\bHSM\b|pkcs11/i },
]

export const CERTIFICATE_SUFFIXES = new Set(['.pem', '.crt', '.cer', '.der', '.p7b', '.p12', '.pfx'])
export const KEY_SUFFIXES = new Set(['.key', '.jks', '.keystore'])

const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i
const PUBLIC_KEY_RE = /-----BEGIN (?:RSA )?PUBLIC KEY-----/i
const CREDENTIAL_RE = /(secret|password|token|private[_-]?key)\s*[:=]/i

function safeEvidence(line: string, matched: string, isSecret = false): string {
  if (isSecret) return '[key material redacted]'
  const compact = line.trim().split(/\s+/).join(' ')
  const truncated = compact.length > 150 ? `${compact.slice(0, 147)}...` : compact
  if (CREDENTIAL_RE.test(truncated)) {
    return `Pattern matched: ${matched} (surrounding value redacted)`
  }
  return truncated || `Pattern matched: ${matched}`
}

export function detectFile(
  filename: string,
  relativePath: string,
  text: string,
  sensitivity: string,
  migrationComplexity: string,
  threatTimeline: number,
): Finding[] {
  const findings: Finding[] = []
  const seen = new Set<string>()
  const base = { path: relativePath, sensitivity, migration_complexity: migrationComplexity, threat_timeline: threatTimeline }

  const dot = filename.lastIndexOf('.')
  const suffix = dot > 0 ? filename.slice(dot).toLowerCase() : ''
  const baseName = dot > 0 ? filename.slice(0, dot) : filename

  const isCertificate =
    CERTIFICATE_SUFFIXES.has(suffix) && (suffix !== '.pem' || text.includes('-----BEGIN CERTIFICATE-----'))
  if (isCertificate) {
    findings.push(makeFinding({ ...base, category: 'Certificate', name: 'Certificate file', line: 1, evidence: `Certificate artefact: ${filename}` }))
  }
  if (KEY_SUFFIXES.has(suffix)) {
    findings.push(makeFinding({ ...base, category: 'Key', name: 'Cryptographic key file', line: 1, evidence: '[key file contents not displayed]' }))
  }

  const lines = text.split(/\r?\n/)
  for (let index = 0; index < lines.length; index += 1) {
    const number = index + 1
    const line = lines[index]
    const algorithmsOnLine = new Set<string>()

    if (PRIVATE_KEY_RE.test(line)) {
      const key = `Key|Private key detected|${number}`
      if (!seen.has(key)) {
        seen.add(key)
        findings.push(makeFinding({ ...base, category: 'Key', name: 'Private key detected', line: number, evidence: safeEvidence(line, 'private-key header', true) }))
      }
    } else if (PUBLIC_KEY_RE.test(line)) {
      const key = `Key|Public key detected|${number}`
      if (!seen.has(key)) {
        seen.add(key)
        findings.push(makeFinding({ ...base, category: 'Key', name: 'Public key detected', line: number, evidence: 'Public-key PEM header' }))
      }
    }

    for (const { category, name, expression } of PATTERNS) {
      const match = line.match(expression)
      const key = `${category}|${name}|${number}`
      if (category === 'Algorithm' && match) {
        if (name === 'AES-GCM' && algorithmsOnLine.has('AES-256-GCM')) continue
        if (name === 'AES' && [...algorithmsOnLine].some((item) => item.startsWith('AES-'))) continue
        if (name === 'RSA' && [...algorithmsOnLine].some((item) => item.startsWith('RSA-'))) continue
      }
      if (match && !seen.has(key)) {
        seen.add(key)
        findings.push(makeFinding({ ...base, category, name, line: number, evidence: safeEvidence(line, match[0]) }))
        if (category === 'Algorithm') algorithmsOnLine.add(name)
      }
    }
  }

  return findings
}
