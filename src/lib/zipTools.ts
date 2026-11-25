import JSZip from 'jszip';

export interface ZipEntryInfo {
  path: string;
  name: string;
  dir: boolean;
  size: number;
  compressedSize: number;
  mimeType: string;
  date: Date;
}

export function guessMimeType(filename: string): string {
  const lower = filename.toLowerCase();
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.gif')) return 'image/gif';
  if (lower.endsWith('.svg')) return 'image/svg+xml';
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.webm')) return 'video/webm';
  if (lower.endsWith('.mov')) return 'video/quicktime';
  if (lower.endsWith('.mkv')) return 'video/x-matroska';
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.zip')) return 'application/zip';
  if (lower.endsWith('.txt') || lower.endsWith('.md') || lower.endsWith('.log')) return 'text/plain';
  if (lower.endsWith('.json')) return 'application/json';
  return 'application/octet-stream';
}

export function detectMediaCategory(
  mimeType: string,
  filename: string
): 'image' | 'video' | 'pdf' | 'zip' | 'other' {
  const lower = filename.toLowerCase();
  const mime = (mimeType || '').toLowerCase();
  if (mime.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp|svg)$/.test(lower)) {
    return 'image';
  }
  if (mime.startsWith('video/') || /\.(mp4|webm|mov|mkv|avi)$/.test(lower)) {
    return 'video';
  }
  if (mime === 'application/pdf' || lower.endsWith('.pdf')) {
    return 'pdf';
  }
  if (mime.includes('zip') || lower.endsWith('.zip')) {
    return 'zip';
  }
  return 'other';
}

/**
 * Inspects a ZIP archive directly in the user's browser without server upload.
 */
export async function inspectZipInBrowser(blob: Blob): Promise<ZipEntryInfo[]> {
  const buffer = await blob.arrayBuffer();
  const zip = await JSZip.loadAsync(buffer);
  const entries: ZipEntryInfo[] = [];

  zip.forEach((relativePath, file) => {
    const internalData = file as unknown as {
      _data?: { uncompressedSize?: number; compressedSize?: number };
    };
    const parts = relativePath.split('/').filter(Boolean);
    const name = parts[parts.length - 1] || relativePath;

    entries.push({
      path: relativePath,
      name,
      dir: file.dir,
      size: internalData._data?.uncompressedSize ?? 0,
      compressedSize: internalData._data?.compressedSize ?? 0,
      mimeType: file.dir ? 'inode/directory' : guessMimeType(name),
      date: file.date,
    });
  });

  return entries.sort((a, b) => {
    if (a.dir !== b.dir) return a.dir ? -1 : 1;
    return a.path.localeCompare(b.path);
  });
}

/**
 * Extracts a single file from a ZIP archive directly in browser memory.
 */
export async function extractZipEntryInBrowser(
  zipBlob: Blob,
  entryPath: string
): Promise<{ fileName: string; mimeType: string; blob: Blob }> {
  const buffer = await zipBlob.arrayBuffer();
  const zip = await JSZip.loadAsync(buffer);
  const entry = zip.file(entryPath);
  if (!entry) {
    throw new Error(`Entry not found in ZIP archive: ${entryPath}`);
  }
  const data = await entry.async('uint8array');
  const fileName = entryPath.split('/').filter(Boolean).pop() || 'extracted-file';
  const mimeType = guessMimeType(fileName);
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return {
    fileName,
    mimeType,
    blob: new Blob([copy.buffer], { type: mimeType }),
  };
}

/**
 * Extracts all non-directory files from a ZIP archive directly in browser memory.
 */
export async function extractAllZipEntriesInBrowser(
  zipBlob: Blob
): Promise<Array<{ path: string; fileName: string; mimeType: string; blob: Blob }>> {
  const buffer = await zipBlob.arrayBuffer();
  const zip = await JSZip.loadAsync(buffer);
  const results: Array<{ path: string; fileName: string; mimeType: string; blob: Blob }> = [];

  const fileEntries: Array<{ path: string; obj: JSZip.JSZipObject }> = [];
  zip.forEach((relativePath, obj) => {
    if (!obj.dir) {
      fileEntries.push({ path: relativePath, obj });
    }
  });

  for (const item of fileEntries) {
    const data = await item.obj.async('uint8array');
    const fileName = item.path.split('/').filter(Boolean).pop() || 'file';
    const mimeType = guessMimeType(fileName);
    const copy = new Uint8Array(data.byteLength);
    copy.set(data);
    results.push({
      path: item.path,
      fileName,
      mimeType,
      blob: new Blob([copy.buffer], { type: mimeType }),
    });
  }

  return results;
}
