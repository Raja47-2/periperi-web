/**
 * Safe in-memory ZIP/TAR extraction for Periperi scans.
 *
 * Mirrors the prototype's limits and path-traversal guards, but operates on
 * in-memory entries because the Workers runtime has no filesystem.
 */

export const MAX_FILES = 25_000
export const MAX_TEXT_SIZE = 2 * 1024 * 1024
export const MAX_BINARY_SIZE = 25 * 1024 * 1024
export const MAX_UPLOAD_SIZE = 100 * 1024 * 1024
export const MAX_EXTRACTED_SIZE = 250 * 1024 * 1024

export class ScanError extends Error {}

export interface ExtractedFile {
  path: string
  name: string
  data: Uint8Array
}

const SKIP_DIRS = new Set([
  '.git', '.gradle', '.cache', 'node_modules', 'venv', '.venv', '__pycache__',
  'target', 'dist', 'build', '.idea', '.vscode',
])

/** Normalise an archive member path and reject traversal or absolute paths. */
function safeMemberPath(raw: string): string {
  const normalized = raw.replace(/\\/g, '/')
  if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) {
    throw new ScanError('Archive contains an unsafe path.')
  }
  const parts: string[] = []
  for (const segment of normalized.split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') throw new ScanError('Archive contains an unsafe path.')
    parts.push(segment)
  }
  if (parts.length === 0) throw new ScanError('Archive contains an unsafe path.')
  return parts.join('/')
}

export function isSkipped(relativePath: string): boolean {
  return relativePath.split('/').some((part) => SKIP_DIRS.has(part))
}

/**
 * Extract a ZIP using the runtime DecompressionStream where the entry uses a
 * supported method, and store-only entries directly.
 */
export async function extractZip(data: Uint8Array): Promise<ExtractedFile[]> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)

  // Locate the end-of-central-directory record.
  let eocd = -1
  const minStart = Math.max(0, bytes.length - 66_000)
  for (let i = bytes.length - 22; i >= minStart; i -= 1) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocd = i
      break
    }
  }
  if (eocd < 0) throw new ScanError('The uploaded file is not a valid ZIP archive.')

  const entryCount = view.getUint16(eocd + 10, true)
  let offset = view.getUint32(eocd + 16, true)

  if (entryCount > MAX_FILES) throw new ScanError(`ZIP exceeds the ${MAX_FILES.toLocaleString()}-file limit.`)

  const files: ExtractedFile[] = []
  let totalSize = 0

  for (let index = 0; index < entryCount; index += 1) {
    if (offset + 46 > bytes.length || view.getUint32(offset, true) !== 0x02014b50) {
      throw new ScanError('The uploaded file is not a valid ZIP archive.')
    }
    const method = view.getUint16(offset + 10, true)
    const compressedSize = view.getUint32(offset + 20, true)
    const uncompressedSize = view.getUint32(offset + 24, true)
    const nameLength = view.getUint16(offset + 28, true)
    const extraLength = view.getUint16(offset + 30, true)
    const commentLength = view.getUint16(offset + 32, true)
    const localOffset = view.getUint32(offset + 42, true)
    const nameBytes = bytes.subarray(offset + 46, offset + 46 + nameLength)
    const name = new TextDecoder().decode(nameBytes)

    totalSize += uncompressedSize
    if (totalSize > MAX_EXTRACTED_SIZE) throw new ScanError('ZIP expands beyond the 250 MB safety limit.')

    offset += 46 + nameLength + extraLength + commentLength

    if (name.endsWith('/')) continue
    const relativePath = safeMemberPath(name)
    if (isSkipped(relativePath)) continue

    // Read the local header to find the true data offset (name/extra lengths differ).
    if (localOffset + 30 > bytes.length || view.getUint32(localOffset, true) !== 0x04034b50) {
      throw new ScanError('The uploaded file is not a valid ZIP archive.')
    }
    const localNameLength = view.getUint16(localOffset + 26, true)
    const localExtraLength = view.getUint16(localOffset + 28, true)
    const dataStart = localOffset + 30 + localNameLength + localExtraLength
    const raw = bytes.subarray(dataStart, dataStart + compressedSize)

    let content: Uint8Array
    if (method === 0) {
      content = raw
    } else if (method === 8) {
      content = await inflateRaw(raw, uncompressedSize)
    } else {
      throw new ScanError(`ZIP uses unsupported compression method ${method}.`)
    }

    files.push({
      path: relativePath,
      name: relativePath.split('/').pop() as string,
      data: content,
    })
  }

  return files
}

async function inflateRaw(data: Uint8Array, expectedSize: number): Promise<Uint8Array> {
  const stream = new Blob([data as BufferSource]).stream().pipeThrough(new DecompressionStream('deflate-raw'))
  const buffer = await new Response(stream).arrayBuffer()
  const out = new Uint8Array(buffer)
  if (expectedSize && out.length !== expectedSize) {
    throw new ScanError('ZIP entry size did not match its declared length.')
  }
  return out
}

/** Extract a TAR (optionally gzip-compressed) into a list of files. */
export async function extractTar(data: Uint8Array, gzipped: boolean): Promise<ExtractedFile[]> {
  let bytes = data
  if (gzipped) {
    const stream = new Blob([data as BufferSource]).stream().pipeThrough(new DecompressionStream('gzip'))
    bytes = new Uint8Array(await new Response(stream).arrayBuffer())
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const decoder = new TextDecoder()
  const files: ExtractedFile[] = []
  let offset = 0
  let totalSize = 0
  let names: string[] = []

  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) break

    const name = decoder.decode(header.subarray(0, 100)).replace(/\0.*$/, '').trim()
    const sizeField = decoder.decode(header.subarray(124, 136)).replace(/\0.*$/, '').trim()
    const size = parseInt(sizeField, 8) || 0
    const typeFlag = String.fromCharCode(header[156])
    const prefix = decoder.decode(header.subarray(345, 500)).replace(/\0.*$/, '').trim()

    if (names.length < MAX_FILES) names.push(name)

    if (typeFlag === '0' || typeFlag === '\0') {
      if (files.length + names.length > MAX_FILES) {
        throw new ScanError(`Archive exceeds the ${MAX_FILES.toLocaleString()}-file limit.`)
      }
      totalSize += size
      if (totalSize > MAX_EXTRACTED_SIZE) throw new ScanError('Archive expands beyond the 250 MB safety limit.')

      const start = offset + 512
      const relativePath = safeMemberPath(prefix ? `${prefix}/${name}` : name)
      if (!isSkipped(relativePath)) {
        files.push({
          path: relativePath,
          name: relativePath.split('/').pop() as string,
          data: bytes.slice(start, start + size),
        })
      }
    }
    // Symlinks and hard links are deliberately not followed.
    offset += 512 + Math.ceil(size / 512) * 512
  }

  if (files.length + names.length > MAX_FILES) {
    throw new ScanError(`Archive exceeds the ${MAX_FILES.toLocaleString()}-file limit.`)
  }
  return files
}

/** Detect Docker/OCI image archive layout from extracted member names. */
export function looksLikeContainer(names: string[]): boolean {
  const markers = new Set(['manifest.json', 'index.json', 'oci-layout'])
  return names.some((name) => markers.has(name.split('/').pop() ?? ''))
}
