/**
 * RoohCloud Client-Side Zero-Knowledge Cryptography Module
 * Uses native browser Web Crypto API (AES-256-GCM + PBKDF2-SHA256).
 *
 * Security guarantee:
 * - The raw Rooh Key never leaves the browser.
 * - File blobs are encrypted in browser memory BEFORE upload.
 * - Downloaded blobs are decrypted in browser memory AFTER download completes.
 * - Authentication verifiers use a separate domain-separated PBKDF2 salt/context
 *   so servers verifying login can never derive the encryption key.
 */

const MAGIC_HEADER = new Uint8Array([0x52, 0x4f, 0x4f, 0x48, 0x31]); // "ROOH1"
const HEADER_BYTES = 32; // 5B magic + 12B IV + 15B flags/reserved
const IV_LENGTH = 12;
const PBKDF2_AUTH_ITERATIONS = 210_000;
const PBKDF2_ENC_ITERATIONS = 310_000;

export interface EncryptedBlobResult {
  encryptedBlob: Blob;
  ivHex: string;
  sha256Hex: string;
  originalSize: number;
  encryptedSize: number;
  durationMs: number;
  throughputMBps: number;
}

export interface DecryptedBlobResult {
  decryptedBlob: Blob;
  sha256Hex: string;
  ivHex: string;
  durationMs: number;
  throughputMBps: number;
}

export interface ShareEncryptionResult {
  encryptedBlob: Blob;
  shareKeyBase64Url: string;
  ivHex: string;
  sha256Hex: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim();
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToBytes(b64u: string): Uint8Array {
  const padLen = (4 - (b64u.length % 4)) % 4;
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLen);
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function generateSaltHex(byteLength = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return bytesToHex(bytes);
}

export async function sha256Hex(buffer: ArrayBuffer | Uint8Array): Promise<string> {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  const digest = await crypto.subtle.digest('SHA-256', copy.buffer);
  return bytesToHex(new Uint8Array(digest));
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

/**
 * Derives a domain-separated login verifier from the Rooh Key.
 * This verifier can be sent to the server for authentication without exposing
 * either the raw Rooh Key or the file encryption key.
 */
export async function deriveRoohAuthVerifier(
  roohKey: string,
  authSaltHex: string
): Promise<string> {
  if (!roohKey || roohKey.length < 4) {
    throw new Error('Rooh Key must be at least 4 characters.');
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`ROOH_AUTH_V1:${roohKey}`),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const saltBytes = hexToBytes(authSaltHex);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(saltBytes),
      iterations: PBKDF2_AUTH_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

/**
 * Derives a non-extractable AES-256-GCM CryptoKey from the user's Rooh Key.
 * Kept strictly in browser memory.
 */
export async function deriveRoohEncryptionKey(
  roohKey: string,
  encSaltHex: string
): Promise<CryptoKey> {
  if (!roohKey || roohKey.length < 4) {
    throw new Error('Rooh Key must be at least 4 characters.');
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`ROOH_ENC_V1:${roohKey}`),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const saltBytes = hexToBytes(encSaltHex);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(saltBytes),
      iterations: PBKDF2_ENC_ITERATIONS,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Computes a short non-sensitive key fingerprint for UI verification only.
 */
export async function computeKeyFingerprint(
  roohKey: string,
  encSaltHex: string
): Promise<string> {
  const digest = await sha256Hex(encoder.encode(`FP:${encSaltHex}:${roohKey}`));
  return `${digest.slice(0, 4)}-${digest.slice(4, 8)}-${digest.slice(8, 12)}`.toUpperCase();
}

/**
 * Encrypts a short UTF-8 metadata string (e.g. original filename) with AES-256-GCM.
 */
export async function encryptMetadataText(
  plaintext: string,
  key: CryptoKey
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(iv) },
    key,
    encoder.encode(plaintext)
  );
  const combined = new Uint8Array(IV_LENGTH + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), IV_LENGTH);
  return bytesToBase64Url(combined);
}

/**
 * Decrypts a UTF-8 metadata string encrypted with encryptMetadataText.
 */
export async function decryptMetadataText(
  encodedPayload: string,
  key: CryptoKey
): Promise<string> {
  const bytes = base64UrlToBytes(encodedPayload);
  if (bytes.length <= IV_LENGTH) {
    throw new Error('Invalid encrypted metadata payload.');
  }
  const iv = bytes.subarray(0, IV_LENGTH);
  const ciphertext = bytes.subarray(IV_LENGTH);
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(iv) },
    key,
    toExactArrayBuffer(ciphertext)
  );
  return decoder.decode(decrypted);
}

/**
 * Encrypts a file or media Blob BEFORE upload using AES-256-GCM.
 * Produces a self-contained binary blob with a 32-byte ROOH1 envelope header.
 */
export async function encryptBlobBeforeUpload(
  file: Blob,
  key: CryptoKey
): Promise<EncryptedBlobResult> {
  const startedAt = performance.now();
  const plainBuffer = await file.arrayBuffer();
  const digestHex = await sha256Hex(plainBuffer);

  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(iv) },
    key,
    plainBuffer
  );

  const header = new Uint8Array(HEADER_BYTES);
  header.set(MAGIC_HEADER, 0);
  header.set(iv, MAGIC_HEADER.length);
  header[17] = 1; // Envelope format version 1

  const encryptedBlob = new Blob([header, cipherBuffer], {
    type: 'application/octet-stream',
  });

  const elapsedMs = Math.max(1, performance.now() - startedAt);
  const throughputMBps =
    plainBuffer.byteLength / (1024 * 1024) / (elapsedMs / 1000);

  return {
    encryptedBlob,
    ivHex: bytesToHex(iv),
    sha256Hex: digestHex,
    originalSize: plainBuffer.byteLength,
    encryptedSize: encryptedBlob.size,
    durationMs: Math.round(elapsedMs),
    throughputMBps: Number(throughputMBps.toFixed(2)),
  };
}

/**
 * Decrypts a downloaded encrypted Blob strictly in browser memory.
 * Parses the ROOH1 header automatically (or falls back to provided ivHex).
 */
export async function decryptBlobAfterDownload(
  encryptedBlob: Blob,
  key: CryptoKey,
  mimeType = 'application/octet-stream',
  fallbackIvHex?: string
): Promise<DecryptedBlobResult> {
  const startedAt = performance.now();
  const rawBuffer = await encryptedBlob.arrayBuffer();
  const rawBytes = new Uint8Array(rawBuffer);

  let ivBytes: Uint8Array;
  let cipherBytes: Uint8Array;

  const hasRoohHeader =
    rawBytes.length > HEADER_BYTES &&
    MAGIC_HEADER.every((b, idx) => rawBytes[idx] === b);

  if (hasRoohHeader) {
    ivBytes = rawBytes.subarray(MAGIC_HEADER.length, MAGIC_HEADER.length + IV_LENGTH);
    cipherBytes = rawBytes.subarray(HEADER_BYTES);
  } else if (fallbackIvHex) {
    ivBytes = hexToBytes(fallbackIvHex);
    cipherBytes = rawBytes;
  } else {
    throw new Error('Encrypted payload is missing ROOH1 envelope header.');
  }

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(ivBytes) },
    key,
    toExactArrayBuffer(cipherBytes)
  );

  const digestHex = await sha256Hex(plainBuffer);
  const decryptedBlob = new Blob([plainBuffer], { type: mimeType });

  const elapsedMs = Math.max(1, performance.now() - startedAt);
  const throughputMBps =
    plainBuffer.byteLength / (1024 * 1024) / (elapsedMs / 1000);

  return {
    decryptedBlob,
    sha256Hex: digestHex,
    ivHex: bytesToHex(ivBytes),
    durationMs: Math.round(elapsedMs),
    throughputMBps: Number(throughputMBps.toFixed(2)),
  };
}

/**
 * Encrypts a plaintext Blob with a fresh random 256-bit ephemeral share key
 * so the decryption key can live exclusively in the URL #k= fragment.
 */
export async function encryptBlobForShareLink(
  plainBlob: Blob
): Promise<ShareEncryptionResult> {
  const shareKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', shareKey));
  const shareKeyBase64Url = bytesToBase64Url(rawKey);

  const res = await encryptBlobBeforeUpload(plainBlob, shareKey);
  return {
    encryptedBlob: res.encryptedBlob,
    shareKeyBase64Url,
    ivHex: res.ivHex,
    sha256Hex: res.sha256Hex,
  };
}

/**
 * Decrypts a shared encrypted Blob in the recipient's browser using the key
 * extracted locally from the URL #k= fragment.
 */
export async function decryptShareBlobInBrowser(
  encryptedBlob: Blob,
  shareKeyBase64Url: string,
  mimeType: string
): Promise<DecryptedBlobResult> {
  const rawKey = base64UrlToBytes(shareKeyBase64Url);
  if (rawKey.length !== 32) {
    throw new Error('Invalid share decryption key length.');
  }
  const shareKey = await crypto.subtle.importKey(
    'raw',
    toExactArrayBuffer(rawKey),
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  return decryptBlobAfterDownload(encryptedBlob, shareKey, mimeType);
}

/**
 * Creates a browser-decodable encrypted recovery cipher block for email delivery.
 * Only the user's verification code + recovery passphrase/PIN can unlock it locally.
 */
export async function createRecoveryCipherBlock(payload: {
  username: string;
  recoveryToken: string;
  hint: string;
  issuedAt: string;
}, verificationCode: string, recoveryPin: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`ROOH_RECOVERY_V1:${verificationCode.trim()}:${recoveryPin.trim()}`),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(salt),
      iterations: 150_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(iv) },
    aesKey,
    encoder.encode(JSON.stringify(payload))
  );

  const packed = new Uint8Array(16 + IV_LENGTH + cipherBuffer.byteLength);
  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(new Uint8Array(cipherBuffer), 16 + IV_LENGTH);

  const body = bytesToBase64Url(packed);
  return [
    '-----BEGIN ROOHCLOUD RECOVERY CIPHER-----',
    body,
    '-----END ROOHCLOUD RECOVERY CIPHER-----',
  ].join('\n');
}

/**
 * Decodes an encrypted recovery email block strictly in the user's browser
 * BEFORE login, verifying both the email cipher and multi-step verification code.
 */
export async function decodeRecoveryCipherBlockInBrowser(
  cipherBlock: string,
  verificationCode: string,
  recoveryPin: string
): Promise<{
  username: string;
  recoveryToken: string;
  hint: string;
  issuedAt: string;
}> {
  const cleaned = cipherBlock
    .replace(/-----BEGIN ROOHCLOUD RECOVERY CIPHER-----/g, '')
    .replace(/-----END ROOHCLOUD RECOVERY CIPHER-----/g, '')
    .replace(/\s+/g, '')
    .trim();

  if (!cleaned) {
    throw new Error('Recovery cipher block is empty.');
  }

  const packed = base64UrlToBytes(cleaned);
  if (packed.length <= 16 + IV_LENGTH) {
    throw new Error('Malformed recovery cipher block.');
  }

  const salt = packed.subarray(0, 16);
  const iv = packed.subarray(16, 16 + IV_LENGTH);
  const ciphertext = packed.subarray(16 + IV_LENGTH);

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(`ROOH_RECOVERY_V1:${verificationCode.trim()}:${recoveryPin.trim()}`),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: toExactArrayBuffer(salt),
      iterations: 150_000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );

  const plainBuffer = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toExactArrayBuffer(iv) },
    aesKey,
    toExactArrayBuffer(ciphertext)
  );

  return JSON.parse(decoder.decode(plainBuffer));
}
