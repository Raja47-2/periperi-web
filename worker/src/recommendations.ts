/** Concise remediation guidance for detected cryptographic artefacts. */

export function recommendation(name: string, category: string, risk: string): string {
  const upper = name.toUpperCase()
  if (category === 'Key' && upper.includes('PRIVATE')) {
    return 'Remove the key from the project, rotate it, and use a managed secret or key store.'
  }
  if (upper.includes('MD5') || upper.includes('SHA-1') || upper.includes('SHA1')) {
    return 'Replace it with SHA-256 or stronger for security-sensitive integrity use.'
  }
  if (upper.includes('RSA-1024')) {
    return 'Replace RSA-1024 immediately and plan a post-quantum or hybrid migration path.'
  }
  if (upper.includes('RSA')) {
    return 'Inventory dependent protocols and plan a post-quantum or hybrid key-establishment migration.'
  }
  if (['ECDSA', 'ECDH', 'ECC'].some((item) => upper.includes(item))) {
    return 'Review retention needs and plan a post-quantum or hybrid migration for long-lived data.'
  }
  if (upper.includes('DSA') || upper === 'DH') {
    return 'Replace legacy public-key usage and include it in the post-quantum migration plan.'
  }
  if (upper.includes('ECB')) {
    return 'Use an authenticated encryption mode such as AES-GCM with safe nonce handling.'
  }
  if (category === 'Certificate') {
    return 'Validate expiry, trust chain, signature algorithm and public-key strength.'
  }
  if (category === 'HSM') {
    return 'Confirm supported algorithms, firmware status and post-quantum migration capabilities.'
  }
  if (category === 'Library') {
    return 'Track the library version and confirm that security updates are maintained.'
  }
  if (risk === 'critical' || risk === 'high') {
    return 'Prioritize review and replace the weak configuration with a modern approved alternative.'
  }
  return 'Retain in the CBOM and review when cryptographic policy or threat assumptions change.'
}
