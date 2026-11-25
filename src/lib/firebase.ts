import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  onAuthStateChanged,
  signInWithPopup,
  User,
} from 'firebase/auth';
import {
  doc,
  getDocFromServer,
  getFirestore,
} from 'firebase/firestore';
import firebaseConfig from '../../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/drive.file',
  'https://www.googleapis.com/auth/drive.readonly',
  'https://www.googleapis.com/auth/gmail.send',
];

const googleProvider = new GoogleAuthProvider();
for (const scope of GOOGLE_SCOPES) {
  googleProvider.addScope(scope);
}
googleProvider.setCustomParameters({ prompt: 'consent' });

// Strict in-memory token cache (never persisted to localStorage/sessionStorage)
let isSigningIn = false;
let cachedGoogleAccessToken: string | null = null;

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export async function testFirestoreConnection(): Promise<void> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}

export function initGoogleAuthListener(
  onSignedIn: (user: User, accessToken: string | null) => void,
  onSignedOut: () => void
) {
  return onAuthStateChanged(auth, (user) => {
    if (user) {
      onSignedIn(user, cachedGoogleAccessToken);
    } else if (!isSigningIn) {
      cachedGoogleAccessToken = null;
      onSignedOut();
    }
  });
}

export async function signInWithGoogleWorkspace(): Promise<{
  user: User;
  accessToken: string;
}> {
  isSigningIn = true;
  try {
    const result = await signInWithPopup(auth, googleProvider);
    const credential = GoogleAuthProvider.credentialFromResult(result);
    if (!credential?.accessToken) {
      throw new Error('Google Sign-In succeeded but no Drive/Gmail access token was granted.');
    }
    cachedGoogleAccessToken = credential.accessToken;
    return { user: result.user, accessToken: credential.accessToken };
  } finally {
    isSigningIn = false;
  }
}

export function getGoogleAccessToken(): string | null {
  return cachedGoogleAccessToken;
}

export async function signOutGoogleWorkspace(): Promise<void> {
  cachedGoogleAccessToken = null;
  await auth.signOut();
}

export interface GoogleDriveFileItem {
  id: string;
  name: string;
  mimeType: string;
  size?: string;
  modifiedTime?: string;
  appProperties?: Record<string, string>;
}

export interface GoogleDriveQuota {
  limit: number;
  usage: number;
  usageInDrive: number;
}

export async function fetchGoogleDriveQuota(
  accessToken: string
): Promise<GoogleDriveQuota> {
  const res = await fetch(
    'https://www.googleapis.com/drive/v3/about?fields=storageQuota',
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!res.ok) {
    throw new Error(`Google Drive quota check failed (${res.status}).`);
  }
  const data = await res.json();
  const q = data.storageQuota || {};
  return {
    limit: Number(q.limit || 15 * 1024 * 1024 * 1024),
    usage: Number(q.usage || 0),
    usageInDrive: Number(q.usageInDrive || 0),
  };
}

export async function listGoogleDriveFiles(
  accessToken: string,
  onlyRoohVault = false
): Promise<GoogleDriveFileItem[]> {
  const qParts = ['trashed = false'];
  if (onlyRoohVault) {
    qParts.push("appProperties has { key='roohVault' and value='true' }");
  }
  const params = new URLSearchParams({
    pageSize: '50',
    fields: 'files(id,name,mimeType,size,modifiedTime,appProperties)',
    orderBy: 'modifiedTime desc',
    q: qParts.join(' and '),
  });
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files?${params.toString()}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!res.ok) {
    throw new Error(`Google Drive list failed (${res.status}).`);
  }
  const data = await res.json();
  return data.files || [];
}

/**
 * Uploads an already-encrypted Blob directly to Google Drive using multipart or resumable upload.
 */
export async function uploadEncryptedBlobToDrive(
  accessToken: string,
  encryptedBlob: Blob,
  metadata: {
    displayName: string;
    originalMimeType: string;
    ivHex: string;
    sha256: string;
  },
  onProgress?: (pct: number) => void
): Promise<GoogleDriveFileItem> {
  const driveMetadata = {
    name: `${metadata.displayName}.rooh`,
    mimeType: 'application/octet-stream',
    appProperties: {
      roohVault: 'true',
      originalMimeType: metadata.originalMimeType,
      ivHex: metadata.ivHex,
      sha256: metadata.sha256,
    },
  };

  // Start resumable upload session for high-speed streaming of large media files
  const initRes = await fetch(
    'https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&fields=id,name,mimeType,size,modifiedTime,appProperties',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json; charset=UTF-8',
        'X-Upload-Content-Type': 'application/octet-stream',
        'X-Upload-Content-Length': String(encryptedBlob.size),
      },
      body: JSON.stringify(driveMetadata),
    }
  );

  if (!initRes.ok) {
    const errText = await initRes.text();
    throw new Error(`Failed to initiate Google Drive upload (${initRes.status}): ${errText}`);
  }

  const uploadUrl = initRes.headers.get('Location');
  if (!uploadUrl) {
    throw new Error('Google Drive did not return a resumable upload location.');
  }

  return new Promise<GoogleDriveFileItem>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('PUT', uploadUrl);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable && onProgress) {
        onProgress(Math.round((ev.loaded / ev.total) * 100));
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch {
          reject(new Error('Invalid JSON response from Google Drive upload.'));
        }
      } else {
        reject(new Error(`Google Drive upload failed with status ${xhr.status}.`));
      }
    };
    xhr.onerror = () => reject(new Error('Network error during Google Drive upload.'));
    xhr.send(encryptedBlob);
  });
}

export async function downloadGoogleDriveFileBlob(
  accessToken: string,
  fileId: string,
  onProgress?: (pct: number) => void
): Promise<Blob> {
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?alt=media`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (!res.ok) {
    throw new Error(`Google Drive download failed (${res.status}).`);
  }

  const contentLength = Number(res.headers.get('Content-Length') || 0);
  if (!res.body || !contentLength) {
    if (onProgress) onProgress(100);
    return res.blob();
  }

  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      chunks.push(value);
      received += value.byteLength;
      if (onProgress) {
        onProgress(Math.min(100, Math.round((received / contentLength) * 100)));
      }
    }
  }
  const merged = new Uint8Array(received);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return new Blob([merged.buffer], { type: 'application/octet-stream' });
}

export async function deleteGoogleDriveFile(
  accessToken: string,
  fileId: string
): Promise<void> {
  const res = await fetch(
    `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${accessToken}` },
    }
  );
  if (!res.ok && res.status !== 404) {
    throw new Error(`Google Drive delete failed (${res.status}).`);
  }
}

/**
 * Dispatches the encrypted Rooh Key recovery cipher message via Gmail API.
 */
export async function sendRecoveryCipherEmail(
  accessToken: string,
  toEmail: string,
  username: string,
  cipherBlock: string
): Promise<{ id: string }> {
  const subject = `[RoohCloud] Encrypted Recovery Cipher for @${username}`;
  const body = [
    `Hello @${username},`,
    '',
    'A multi-step Rooh Key recovery was initiated for your RoohCloud vault.',
    'Copy the encrypted block below and paste it into the Pre-Login Browser Recovery Decoder before signing in.',
    'Only your browser can decode this block locally using your verification code and recovery PIN.',
    '',
    cipherBlock,
    '',
    'If you did not request this recovery, you can safely ignore this message.',
  ].join('\r\n');

  const rawMessage = [
    `To: ${toEmail}`,
    `Subject: ${subject}`,
    'Content-Type: text/plain; charset="UTF-8"',
    'MIME-Version: 1.0',
    '',
    body,
  ].join('\r\n');

  const bytes = new TextEncoder().encode(rawMessage);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64Url = btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

  const res = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
    {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ raw: base64Url }),
    }
  );

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Gmail send failed (${res.status}): ${text}`);
  }
  return res.json();
}
