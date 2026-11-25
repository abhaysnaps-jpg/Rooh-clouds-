import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import { createServer as createViteServer } from 'vite';

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const TEN_GB_BYTES = 10 * 1024 * 1024 * 1024; // 10 GB Memory Vault
const TERABOX_QUOTA_BYTES = 1024 * 1024 * 1024 * 1024; // 1024 GB TeraBox Cloud Tier

const SESSION_SECRET =
  process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 16
    ? process.env.SESSION_SECRET
    : crypto.randomBytes(32).toString('hex');

const DATA_ROOT = path.resolve(process.cwd(), '.vault_data');
const BLOBS_DIR = path.resolve(DATA_ROOT, 'blobs');
const TERABOX_STAGE_DIR = path.resolve(DATA_ROOT, 'terabox_pool');
const STATE_FILE = path.resolve(DATA_ROOT, 'state.json');

interface UserRecord {
  id: string;
  username: string;
  email: string;
  authSalt: string;
  encSalt: string;
  verifierSalt: string;
  verifierHash: string;
  recoveryHint: string;
  usedMemoryBytes: number;
  usedTeraboxBytes: number;
  teraboxConfig?: {
    mode: 'webdav' | 'session';
    endpoint?: string;
    username?: string;
    secretEnc?: string; // server-sealed credential
    connectedAt: string;
  };
  createdAt: string;
}

interface FileRecord {
  fileId: string;
  ownerId: string;
  encryptedName: string;
  displayName?: string;
  mimeType: string;
  mediaCategory: 'image' | 'video' | 'pdf' | 'zip' | 'other';
  originalSize: number;
  encryptedSize: number;
  provider: 'memory-vault' | 'google-drive' | 'terabox';
  remoteId: string;
  ivHex: string;
  sha256: string;
  createdAt: string;
}

interface ShareRecord {
  shareId: string;
  ownerId: string;
  blobId: string;
  fileName: string;
  mimeType: string;
  originalSize: number;
  encryptedSize: number;
  sha256: string;
  expiresAt: string;
  maxDownloads: number;
  downloadsCount: number;
  createdAt: string;
}

interface RecoveryChallengeRecord {
  challengeId: string;
  userId: string;
  username: string;
  email: string;
  codeHash: string;
  recoveryTokenHash: string;
  verifiedTicket?: string;
  expiresAt: string;
  used: boolean;
}

interface VaultState {
  users: Record<string, UserRecord>;
  usernameIndex: Record<string, string>;
  files: Record<string, FileRecord>;
  shares: Record<string, ShareRecord>;
  recoveryChallenges: Record<string, RecoveryChallengeRecord>;
}

const DEFAULT_STATE: VaultState = {
  users: {},
  usernameIndex: {},
  files: {},
  shares: {},
  recoveryChallenges: {},
};

let state: VaultState = structuredClone(DEFAULT_STATE);

async function ensureStorageReady() {
  await fsp.mkdir(BLOBS_DIR, { recursive: true });
  await fsp.mkdir(TERABOX_STAGE_DIR, { recursive: true });
  try {
    const raw = await fsp.readFile(STATE_FILE, 'utf8');
    const parsed = JSON.parse(raw) as Partial<VaultState>;
    state = {
      users: parsed.users || {},
      usernameIndex: parsed.usernameIndex || {},
      files: parsed.files || {},
      shares: parsed.shares || {},
      recoveryChallenges: parsed.recoveryChallenges || {},
    };
  } catch {
    await persistState();
  }
}

let writeQueue: Promise<void> = Promise.resolve();
async function persistState(): Promise<void> {
  const snapshot = JSON.stringify(state, null, 2);
  writeQueue = writeQueue.then(async () => {
    const tmp = `${STATE_FILE}.${crypto.randomUUID()}.tmp`;
    await fsp.writeFile(tmp, snapshot, 'utf8');
    await fsp.rename(tmp, STATE_FILE);
  });
  return writeQueue;
}

function isValidId(val: unknown): val is string {
  return (
    typeof val === 'string' &&
    val.length >= 1 &&
    val.length <= 128 &&
    /^[a-zA-Z0-9_-]+$/.test(val)
  );
}

function isValidUsername(val: unknown): val is string {
  return (
    typeof val === 'string' &&
    val.length >= 3 &&
    val.length <= 32 &&
    /^[a-zA-Z0-9_.-]+$/.test(val)
  );
}

function resolveConfinedPath(baseDir: string, fileId: string): string {
  if (!isValidId(fileId)) {
    throw new Error('Invalid file identifier.');
  }
  const resolved = path.resolve(baseDir, `${fileId}.rooh`);
  if (!resolved.startsWith(baseDir + path.sep)) {
    throw new Error('Path traversal rejected.');
  }
  return resolved;
}

function hashVerifier(verifier: string, salt: string): string {
  return crypto.scryptSync(verifier, salt, 64).toString('hex');
}

function safeEqualHex(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'hex');
  const bufB = Buffer.from(b, 'hex');
  if (bufA.length !== bufB.length || bufA.length === 0) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function sealSecret(plaintext: string): string {
  const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64url');
}

function unsealSecret(sealed: string): string {
  const raw = Buffer.from(sealed, 'base64url');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const enc = raw.subarray(28);
  const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

function signSessionToken(userId: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      uid: userId,
      exp: Date.now() + 24 * 60 * 60 * 1000,
    })
  ).toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  return `${payload}.${sig}`;
}

function verifySessionToken(token: string): string | null {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payload, sig] = parts;
  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payload)
    .digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expectedSig);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof parsed.uid !== 'string' || typeof parsed.exp !== 'number') return null;
    if (Date.now() > parsed.exp) return null;
    return parsed.uid;
  } catch {
    return null;
  }
}

function isSafeExternalHttpsUrl(rawUrl: string): URL {
  const parsed = new URL(rawUrl);
  if (parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS endpoints are allowed.');
  }
  const host = parsed.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host === '0.0.0.0' ||
    host === '169.254.169.254' ||
    host.endsWith('.local') ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)
  ) {
    throw new Error('Private or loopback addresses are not allowed.');
  }
  return parsed;
}

interface AuthedRequest extends Request {
  vaultUserId?: string;
}

function requireVaultAuth(req: AuthedRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Missing Bearer session token.' });
    return;
  }
  const token = authHeader.slice('Bearer '.length).trim();
  const uid = verifySessionToken(token);
  if (!uid || !state.users[uid]) {
    res.status(401).json({ error: 'Session expired or invalid.' });
    return;
  }
  req.vaultUserId = uid;
  next();
}

function sanitizeUserResponse(user: UserRecord) {
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    authSalt: user.authSalt,
    encSalt: user.encSalt,
    recoveryHint: user.recoveryHint,
    usedMemoryBytes: user.usedMemoryBytes,
    memoryQuotaBytes: TEN_GB_BYTES,
    usedTeraboxBytes: user.usedTeraboxBytes,
    teraboxQuotaBytes: TERABOX_QUOTA_BYTES,
    teraboxConnected: Boolean(user.teraboxConfig),
    teraboxMode: user.teraboxConfig?.mode || null,
    teraboxEndpoint: user.teraboxConfig?.endpoint || null,
  };
}

async function startServer() {
  await ensureStorageReady();

  const app = express();
  app.set('trust proxy', 1);

  // JSON parser for standard API routes (binary blob routes read raw stream directly)
  app.use('/api', (req, res, next) => {
    if (
      req.path.startsWith('/vault/blobs/') ||
      req.path.startsWith('/terabox/blobs/') ||
      req.path.startsWith('/shares/blobs/')
    ) {
      next();
      return;
    }
    express.json({ limit: '2mb' })(req, res, next);
  });

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok', memoryQuotaBytes: TEN_GB_BYTES, teraboxQuotaBytes: TERABOX_QUOTA_BYTES });
  });

  // 1. Register Username + Rooh Key verifier (zero-knowledge: raw Rooh Key never sent)
  app.post('/api/auth/register', async (req, res) => {
    try {
      const { username, email, authSalt, encSalt, authVerifier, recoveryHint } = req.body || {};
      if (!isValidUsername(username)) {
        res.status(400).json({ error: 'Username must be 3–32 characters (letters, numbers, _, ., -).' });
        return;
      }
      if (typeof email !== 'string' || !email.includes('@') || email.length > 160) {
        res.status(400).json({ error: 'A valid email address is required for recovery.' });
        return;
      }
      if (
        typeof authSalt !== 'string' ||
        typeof encSalt !== 'string' ||
        typeof authVerifier !== 'string' ||
        authVerifier.length < 32
      ) {
        res.status(400).json({ error: 'Invalid cryptographic derivation parameters.' });
        return;
      }

      const key = username.toLowerCase();
      if (state.usernameIndex[key]) {
        res.status(409).json({ error: 'Username is already registered.' });
        return;
      }

      const userId = `u_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
      const verifierSalt = crypto.randomBytes(16).toString('hex');
      const verifierHash = hashVerifier(authVerifier, verifierSalt);

      const user: UserRecord = {
        id: userId,
        username,
        email: email.trim().toLowerCase(),
        authSalt,
        encSalt,
        verifierSalt,
        verifierHash,
        recoveryHint: typeof recoveryHint === 'string' ? recoveryHint.slice(0, 120) : '',
        usedMemoryBytes: 0,
        usedTeraboxBytes: 0,
        createdAt: new Date().toISOString(),
      };

      state.users[userId] = user;
      state.usernameIndex[key] = userId;
      await persistState();

      const token = signSessionToken(userId);
      res.status(201).json({ token, user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Registration failed.' });
    }
  });

  // 2. Get public salts for Username before login
  app.post('/api/auth/challenge', (req, res) => {
    const { username } = req.body || {};
    if (!isValidUsername(username)) {
      res.status(400).json({ error: 'Invalid username format.' });
      return;
    }
    const uid = state.usernameIndex[username.toLowerCase()];
    const user = uid ? state.users[uid] : null;
    if (!user) {
      res.status(404).json({ error: 'No vault found for that username.' });
      return;
    }
    res.json({
      username: user.username,
      authSalt: user.authSalt,
      encSalt: user.encSalt,
      recoveryHint: user.recoveryHint,
    });
  });

  // 3. Login with Username + Rooh Key derived authVerifier
  app.post('/api/auth/login', (req, res) => {
    const { username, authVerifier } = req.body || {};
    if (!isValidUsername(username) || typeof authVerifier !== 'string') {
      res.status(400).json({ error: 'Username and derived verifier are required.' });
      return;
    }
    const uid = state.usernameIndex[username.toLowerCase()];
    const user = uid ? state.users[uid] : null;
    if (!user) {
      res.status(401).json({ error: 'Invalid username or Rooh Key.' });
      return;
    }
    const candidateHash = hashVerifier(authVerifier, user.verifierSalt);
    if (!safeEqualHex(candidateHash, user.verifierHash)) {
      res.status(401).json({ error: 'Invalid username or Rooh Key.' });
      return;
    }

    const token = signSessionToken(user.id);
    res.json({ token, user: sanitizeUserResponse(user) });
  });

  // 4. Google Sign-In session bridge (maps verified Google email/uid into vault session)
  app.post('/api/auth/google-session', async (req, res) => {
    try {
      const { googleUid, email, displayName, authSalt, encSalt, authVerifier } = req.body || {};
      if (typeof googleUid !== 'string' || typeof email !== 'string' || !email.includes('@')) {
        res.status(400).json({ error: 'Invalid Google account payload.' });
        return;
      }

      const normalizedEmail = email.trim().toLowerCase();
      let user = Object.values(state.users).find((u) => u.email === normalizedEmail);

      if (!user) {
        const baseName = (displayName || normalizedEmail.split('@')[0] || 'vaultuser')
          .replace(/[^a-zA-Z0-9_.-]/g, '')
          .slice(0, 20) || 'roohuser';
        let candidate = baseName.length >= 3 ? baseName : `rooh_${baseName}`;
        let suffix = 1;
        while (state.usernameIndex[candidate.toLowerCase()]) {
          candidate = `${baseName.slice(0, 18)}${suffix++}`;
        }

        const userId = `g_${googleUid.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32)}`;
        const finalAuthSalt = typeof authSalt === 'string' && authSalt.length >= 16 ? authSalt : crypto.randomBytes(16).toString('hex');
        const finalEncSalt = typeof encSalt === 'string' && encSalt.length >= 16 ? encSalt : crypto.randomBytes(16).toString('hex');
        const verifierSalt = crypto.randomBytes(16).toString('hex');
        const initialVerifier = typeof authVerifier === 'string' && authVerifier.length >= 32
          ? authVerifier
          : crypto.randomBytes(32).toString('hex');

        user = {
          id: userId,
          username: candidate,
          email: normalizedEmail,
          authSalt: finalAuthSalt,
          encSalt: finalEncSalt,
          verifierSalt,
          verifierHash: hashVerifier(initialVerifier, verifierSalt),
          recoveryHint: 'Google Linked Vault',
          usedMemoryBytes: 0,
          usedTeraboxBytes: 0,
          createdAt: new Date().toISOString(),
        };
        state.users[userId] = user;
        state.usernameIndex[candidate.toLowerCase()] = userId;
        await persistState();
      } else if (typeof authVerifier === 'string' && authVerifier.length >= 32 && typeof authSalt === 'string' && typeof encSalt === 'string') {
        // Optional key binding update if explicitly passed during Google setup
        user.authSalt = authSalt;
        user.encSalt = encSalt;
        user.verifierHash = hashVerifier(authVerifier, user.verifierSalt);
        await persistState();
      }

      const token = signSessionToken(user.id);
      res.json({ token, user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Google session link failed.' });
    }
  });

  // 5. Multi-Step Recovery Step 1: Initiate recovery challenge
  app.post('/api/recovery/initiate', async (req, res) => {
    try {
      const { identifier } = req.body || {};
      if (typeof identifier !== 'string' || !identifier.trim()) {
        res.status(400).json({ error: 'Username or email is required.' });
        return;
      }
      const clean = identifier.trim().toLowerCase();
      let user: UserRecord | undefined;
      if (state.usernameIndex[clean]) {
        user = state.users[state.usernameIndex[clean]];
      } else {
        user = Object.values(state.users).find((u) => u.email === clean);
      }
      if (!user) {
        res.status(404).json({ error: 'No account matched that username or email.' });
        return;
      }

      const challengeId = `rc_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
      const verificationCode = String(crypto.randomInt(100000, 999999));
      const recoveryToken = crypto.randomBytes(24).toString('base64url');

      state.recoveryChallenges[challengeId] = {
        challengeId,
        userId: user.id,
        username: user.username,
        email: user.email,
        codeHash: crypto.createHash('sha256').update(verificationCode).digest('hex'),
        recoveryTokenHash: crypto.createHash('sha256').update(recoveryToken).digest('hex'),
        expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
        used: false,
      };
      await persistState();

      res.json({
        challengeId,
        username: user.username,
        email: user.email,
        hint: user.recoveryHint,
        verificationCode,
        recoveryToken,
        expiresAt: state.recoveryChallenges[challengeId].expiresAt,
      });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Recovery initiation failed.' });
    }
  });

  // Step 2: Verify 6-digit recovery code
  app.post('/api/recovery/verify-code', async (req, res) => {
    const { challengeId, verificationCode } = req.body || {};
    if (!isValidId(challengeId) || typeof verificationCode !== 'string') {
      res.status(400).json({ error: 'Challenge ID and 6-digit code are required.' });
      return;
    }
    const challenge = state.recoveryChallenges[challengeId];
    if (!challenge || challenge.used || Date.now() > Date.parse(challenge.expiresAt)) {
      res.status(400).json({ error: 'Recovery challenge expired or invalid.' });
      return;
    }

    const candidateHash = crypto.createHash('sha256').update(verificationCode.trim()).digest('hex');
    if (!safeEqualHex(candidateHash, challenge.codeHash)) {
      res.status(403).json({ error: 'Verification code does not match.' });
      return;
    }

    const verifiedTicket = crypto.randomBytes(20).toString('hex');
    challenge.verifiedTicket = verifiedTicket;
    await persistState();

    res.json({ verified: true, verifiedTicket, username: challenge.username });
  });

  // Step 3: Complete recovery after pre-login browser cipher decoder unlocks recoveryToken
  app.post('/api/recovery/complete', async (req, res) => {
    try {
      const { challengeId, verifiedTicket, recoveryToken, newAuthSalt, newEncSalt, newAuthVerifier } = req.body || {};
      if (
        !isValidId(challengeId) ||
        typeof verifiedTicket !== 'string' ||
        typeof recoveryToken !== 'string' ||
        typeof newAuthSalt !== 'string' ||
        typeof newEncSalt !== 'string' ||
        typeof newAuthVerifier !== 'string'
      ) {
        res.status(400).json({ error: 'Missing required recovery completion fields.' });
        return;
      }

      const challenge = state.recoveryChallenges[challengeId];
      if (
        !challenge ||
        challenge.used ||
        Date.now() > Date.parse(challenge.expiresAt) ||
        challenge.verifiedTicket !== verifiedTicket
      ) {
        res.status(403).json({ error: 'Recovery verification session invalid or expired.' });
        return;
      }

      const tokenHash = crypto.createHash('sha256').update(recoveryToken.trim()).digest('hex');
      if (!safeEqualHex(tokenHash, challenge.recoveryTokenHash)) {
        res.status(403).json({ error: 'Decoded recovery token mismatch.' });
        return;
      }

      const user = state.users[challenge.userId];
      if (!user) {
        res.status(404).json({ error: 'Account not found.' });
        return;
      }

      user.authSalt = newAuthSalt;
      user.encSalt = newEncSalt;
      user.verifierSalt = crypto.randomBytes(16).toString('hex');
      user.verifierHash = hashVerifier(newAuthVerifier, user.verifierSalt);
      challenge.used = true;
      await persistState();

      const token = signSessionToken(user.id);
      res.json({ token, user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Recovery completion failed.' });
    }
  });

  // 6. Vault File Metadata CRUD
  app.get('/api/vault/files', requireVaultAuth, (req: AuthedRequest, res) => {
    const uid = req.vaultUserId!;
    const user = state.users[uid];
    const files = Object.values(state.files)
      .filter((f) => f.ownerId === uid)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    res.json({ files, user: sanitizeUserResponse(user) });
  });

  app.post('/api/vault/files', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const user = state.users[uid];
      const {
        fileId,
        encryptedName,
        displayName,
        mimeType,
        mediaCategory,
        originalSize,
        encryptedSize,
        provider,
        remoteId,
        ivHex,
        sha256,
      } = req.body || {};

      if (!isValidId(fileId) || !isValidId(remoteId)) {
        res.status(400).json({ error: 'Invalid fileId or remoteId.' });
        return;
      }
      if (
        provider !== 'memory-vault' &&
        provider !== 'google-drive' &&
        provider !== 'terabox'
      ) {
        res.status(400).json({ error: 'Invalid storage provider.' });
        return;
      }

      const record: FileRecord = {
        fileId,
        ownerId: uid,
        encryptedName: String(encryptedName || '').slice(0, 512),
        displayName: typeof displayName === 'string' ? displayName.slice(0, 200) : undefined,
        mimeType: String(mimeType || 'application/octet-stream').slice(0, 128),
        mediaCategory:
          mediaCategory === 'image' ||
          mediaCategory === 'video' ||
          mediaCategory === 'pdf' ||
          mediaCategory === 'zip'
            ? mediaCategory
            : 'other',
        originalSize: Number(originalSize || 0),
        encryptedSize: Number(encryptedSize || 0),
        provider,
        remoteId,
        ivHex: String(ivHex || '').slice(0, 64),
        sha256: String(sha256 || '').slice(0, 64),
        createdAt: new Date().toISOString(),
      };

      state.files[fileId] = record;
      if (provider === 'memory-vault') {
        user.usedMemoryBytes = Object.values(state.files)
          .filter((f) => f.ownerId === uid && f.provider === 'memory-vault')
          .reduce((acc, f) => acc + f.encryptedSize, 0);
      } else if (provider === 'terabox') {
        user.usedTeraboxBytes = Object.values(state.files)
          .filter((f) => f.ownerId === uid && f.provider === 'terabox')
          .reduce((acc, f) => acc + f.encryptedSize, 0);
      }
      await persistState();

      res.status(201).json({ file: record, user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to save file metadata.' });
    }
  });

  app.delete('/api/vault/files/:fileId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const fileId = String(req.params.fileId || '');
      const file = state.files[fileId];
      if (!file || file.ownerId !== uid) {
        res.status(404).json({ error: 'File not found.' });
        return;
      }

      if (file.provider === 'memory-vault') {
        const blobPath = resolveConfinedPath(BLOBS_DIR, file.remoteId);
        await fsp.rm(blobPath, { force: true });
      } else if (file.provider === 'terabox') {
        const user = state.users[uid];
        if (user.teraboxConfig?.mode === 'webdav' && user.teraboxConfig.endpoint && user.teraboxConfig.secretEnc) {
          try {
            const url = isSafeExternalHttpsUrl(`${user.teraboxConfig.endpoint.replace(/\/$/, '')}/${file.remoteId}.rooh`);
            const pass = unsealSecret(user.teraboxConfig.secretEnc);
            const auth = Buffer.from(`${user.teraboxConfig.username || ''}:${pass}`).toString('base64');
            await fetch(url.toString(), {
              method: 'DELETE',
              headers: { Authorization: `Basic ${auth}` },
            });
          } catch {
            // Proceed to clean local stage if remote already removed
          }
        }
        const stagePath = resolveConfinedPath(TERABOX_STAGE_DIR, file.remoteId);
        await fsp.rm(stagePath, { force: true });
      }

      delete state.files[fileId];
      const user = state.users[uid];
      user.usedMemoryBytes = Object.values(state.files)
        .filter((f) => f.ownerId === uid && f.provider === 'memory-vault')
        .reduce((acc, f) => acc + f.encryptedSize, 0);
      user.usedTeraboxBytes = Object.values(state.files)
        .filter((f) => f.ownerId === uid && f.provider === 'terabox')
        .reduce((acc, f) => acc + f.encryptedSize, 0);
      await persistState();

      res.json({ deleted: true, user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Delete failed.' });
    }
  });

  // 7. High-Speed Streaming Encrypted Blob Upload & Download (10 GB Memory Vault)
  app.put('/api/vault/blobs/:blobId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const user = state.users[uid];
      const blobId = String(req.params.blobId || '');
      const contentLength = Number(req.headers['content-length'] || 0);
      if (user.usedMemoryBytes + contentLength > TEN_GB_BYTES) {
        res.status(413).json({ error: '10 GB Memory Vault quota exceeded.' });
        return;
      }

      const targetPath = resolveConfinedPath(BLOBS_DIR, blobId);
      const ws = fs.createWriteStream(targetPath);
      await pipeline(req, ws);
      const stat = await fsp.stat(targetPath);
      if (user.usedMemoryBytes + stat.size > TEN_GB_BYTES) {
        await fsp.rm(targetPath, { force: true });
        res.status(413).json({ error: '10 GB Memory Vault quota exceeded.' });
        return;
      }

      res.status(201).json({ blobId, size: stat.size });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Blob upload failed.' });
    }
  });

  app.get('/api/vault/blobs/:blobId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const blobId = String(req.params.blobId || '');
      const ownsBlob = Object.values(state.files).some(
        (f) => f.ownerId === uid && f.remoteId === blobId
      );
      if (!ownsBlob) {
        res.status(403).json({ error: 'Access denied for this encrypted blob.' });
        return;
      }

      const targetPath = resolveConfinedPath(BLOBS_DIR, blobId);
      const stat = await fsp.stat(targetPath);
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', String(stat.size));
      res.setHeader('Cache-Control', 'no-store');
      fs.createReadStream(targetPath).pipe(res);
    } catch {
      res.status(404).json({ error: 'Encrypted blob not found.' });
    }
  });

  // 8. TeraBox 1024 GB Storage Pool Configuration & High-Speed Streaming
  app.post('/api/terabox/configure', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const user = state.users[uid];
      const { mode, endpoint, username, credential } = req.body || {};

      if (mode === 'webdav') {
        if (typeof endpoint !== 'string' || typeof credential !== 'string' || !credential.trim()) {
          res.status(400).json({ error: 'Valid HTTPS WebDAV endpoint and password/token are required.' });
          return;
        }
        const parsed = isSafeExternalHttpsUrl(endpoint.trim());
        user.teraboxConfig = {
          mode: 'webdav',
          endpoint: parsed.toString().replace(/\/$/, ''),
          username: typeof username === 'string' ? username.trim() : '',
          secretEnc: sealSecret(credential.trim()),
          connectedAt: new Date().toISOString(),
        };
      } else if (mode === 'session') {
        if (typeof credential !== 'string' || credential.trim().length < 8) {
          res.status(400).json({ error: 'TeraBox ndus/BDUSS session token is required.' });
          return;
        }
        user.teraboxConfig = {
          mode: 'session',
          endpoint: 'https://www.terabox.com',
          username: typeof username === 'string' ? username.trim() : user.username,
          secretEnc: sealSecret(credential.trim()),
          connectedAt: new Date().toISOString(),
        };
      } else {
        res.status(400).json({ error: 'Invalid TeraBox connection mode.' });
        return;
      }

      await persistState();
      res.json({ user: sanitizeUserResponse(user) });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'TeraBox configuration failed.' });
    }
  });

  app.put('/api/terabox/blobs/:blobId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const user = state.users[uid];
      const blobId = String(req.params.blobId || '');
      const targetPath = resolveConfinedPath(TERABOX_STAGE_DIR, blobId);
      const ws = fs.createWriteStream(targetPath);
      await pipeline(req, ws);
      const stat = await fsp.stat(targetPath);

      if (user.usedTeraboxBytes + stat.size > TERABOX_QUOTA_BYTES) {
        await fsp.rm(targetPath, { force: true });
        res.status(413).json({ error: '1024 GB TeraBox pool quota exceeded.' });
        return;
      }

      // If user configured a live HTTPS WebDAV bridge for TeraBox, forward encrypted stream
      let syncedRemote = false;
      if (
        user.teraboxConfig?.mode === 'webdav' &&
        user.teraboxConfig.endpoint &&
        user.teraboxConfig.secretEnc
      ) {
        const remoteUrl = isSafeExternalHttpsUrl(
          `${user.teraboxConfig.endpoint.replace(/\/$/, '')}/${blobId}.rooh`
        );
        const pass = unsealSecret(user.teraboxConfig.secretEnc);
        const auth = Buffer.from(`${user.teraboxConfig.username || ''}:${pass}`).toString('base64');
        const buf = await fsp.readFile(targetPath);
        const upstream = await fetch(remoteUrl.toString(), {
          method: 'PUT',
          headers: {
            Authorization: `Basic ${auth}`,
            'Content-Type': 'application/octet-stream',
          },
          body: buf,
        });
        if (!upstream.ok) {
          throw new Error(`TeraBox WebDAV bridge returned HTTP ${upstream.status}.`);
        }
        syncedRemote = true;
      }

      res.status(201).json({ blobId, size: stat.size, syncedRemote });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'TeraBox upload failed.' });
    }
  });

  app.get('/api/terabox/blobs/:blobId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const user = state.users[uid];
      const blobId = String(req.params.blobId || '');
      const ownsBlob = Object.values(state.files).some(
        (f) => f.ownerId === uid && f.remoteId === blobId && f.provider === 'terabox'
      );
      if (!ownsBlob) {
        res.status(403).json({ error: 'Access denied.' });
        return;
      }

      const stagePath = resolveConfinedPath(TERABOX_STAGE_DIR, blobId);
      if (fs.existsSync(stagePath)) {
        const stat = await fsp.stat(stagePath);
        res.setHeader('Content-Type', 'application/octet-stream');
        res.setHeader('Content-Length', String(stat.size));
        fs.createReadStream(stagePath).pipe(res);
        return;
      }

      if (
        user.teraboxConfig?.mode === 'webdav' &&
        user.teraboxConfig.endpoint &&
        user.teraboxConfig.secretEnc
      ) {
        const remoteUrl = isSafeExternalHttpsUrl(
          `${user.teraboxConfig.endpoint.replace(/\/$/, '')}/${blobId}.rooh`
        );
        const pass = unsealSecret(user.teraboxConfig.secretEnc);
        const auth = Buffer.from(`${user.teraboxConfig.username || ''}:${pass}`).toString('base64');
        const upstream = await fetch(remoteUrl.toString(), {
          headers: { Authorization: `Basic ${auth}` },
        });
        if (!upstream.ok) {
          res.status(502).json({ error: `TeraBox upstream failed (${upstream.status}).` });
          return;
        }
        const ab = await upstream.arrayBuffer();
        res.setHeader('Content-Type', 'application/octet-stream');
        res.send(Buffer.from(ab));
        return;
      }

      res.status(404).json({ error: 'Encrypted TeraBox blob not found.' });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'TeraBox download failed.' });
    }
  });

  // 9. Zero-Knowledge Secure Share Links (decryption key stays exclusively in URL #k= fragment!)
  app.put('/api/shares/blobs/:blobId', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const blobId = String(req.params.blobId || '');
      const targetPath = resolveConfinedPath(BLOBS_DIR, blobId);
      const ws = fs.createWriteStream(targetPath);
      await pipeline(req, ws);
      const stat = await fsp.stat(targetPath);
      res.status(201).json({ blobId, size: stat.size });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Share blob upload failed.' });
    }
  });

  app.post('/api/shares', requireVaultAuth, async (req: AuthedRequest, res) => {
    try {
      const uid = req.vaultUserId!;
      const { blobId, fileName, mimeType, originalSize, encryptedSize, sha256, expiryHours, maxDownloads } = req.body || {};
      if (!isValidId(blobId) || typeof fileName !== 'string') {
        res.status(400).json({ error: 'Valid blobId and fileName are required.' });
        return;
      }
      const shareId = `s_${crypto.randomBytes(10).toString('hex')}`;
      const hours = Math.min(720, Math.max(1, Number(expiryHours || 48)));
      const record: ShareRecord = {
        shareId,
        ownerId: uid,
        blobId,
        fileName: fileName.slice(0, 200),
        mimeType: String(mimeType || 'application/octet-stream').slice(0, 128),
        originalSize: Number(originalSize || 0),
        encryptedSize: Number(encryptedSize || 0),
        sha256: String(sha256 || '').slice(0, 64),
        expiresAt: new Date(Date.now() + hours * 3600 * 1000).toISOString(),
        maxDownloads: Math.min(500, Math.max(1, Number(maxDownloads || 25))),
        downloadsCount: 0,
        createdAt: new Date().toISOString(),
      };
      state.shares[shareId] = record;
      await persistState();
      res.status(201).json({ share: record });
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : 'Failed to create share link.' });
    }
  });

  app.get('/api/shares', requireVaultAuth, (req: AuthedRequest, res) => {
    const uid = req.vaultUserId!;
    const shares = Object.values(state.shares)
      .filter((s) => s.ownerId === uid)
      .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt));
    res.json({ shares });
  });

  app.delete('/api/shares/:shareId', requireVaultAuth, async (req: AuthedRequest, res) => {
    const uid = req.vaultUserId!;
    const shareId = String(req.params.shareId || '');
    const share = state.shares[shareId];
    if (!share || share.ownerId !== uid) {
      res.status(404).json({ error: 'Share link not found.' });
      return;
    }
    const blobPath = resolveConfinedPath(BLOBS_DIR, share.blobId);
    await fsp.rm(blobPath, { force: true });
    delete state.shares[shareId];
    await persistState();
    res.json({ revoked: true });
  });

  // Public Share Link metadata & encrypted blob retrieval (ciphertext only, key never sent to server)
  app.get('/api/shares/:shareId', (req, res) => {
    const shareId = String(req.params.shareId || '');
    const share = state.shares[shareId];
    if (!share) {
      res.status(404).json({ error: 'Share link not found or revoked.' });
      return;
    }
    if (Date.now() > Date.parse(share.expiresAt)) {
      res.status(410).json({ error: 'Share link has expired.' });
      return;
    }
    if (share.downloadsCount >= share.maxDownloads) {
      res.status(410).json({ error: 'Maximum download limit reached for this share link.' });
      return;
    }
    res.json({
      share: {
        shareId: share.shareId,
        fileName: share.fileName,
        mimeType: share.mimeType,
        originalSize: share.originalSize,
        encryptedSize: share.encryptedSize,
        sha256: share.sha256,
        expiresAt: share.expiresAt,
        maxDownloads: share.maxDownloads,
        downloadsCount: share.downloadsCount,
      },
    });
  });

  app.get('/api/shares/:shareId/blob', async (req, res) => {
    try {
      const shareId = String(req.params.shareId || '');
      const share = state.shares[shareId];
      if (!share) {
        res.status(404).json({ error: 'Share link not found.' });
        return;
      }
      if (Date.now() > Date.parse(share.expiresAt) || share.downloadsCount >= share.maxDownloads) {
        res.status(410).json({ error: 'Share link expired or exhausted.' });
        return;
      }
      const blobPath = resolveConfinedPath(BLOBS_DIR, share.blobId);
      const stat = await fsp.stat(blobPath);
      share.downloadsCount += 1;
      await persistState();

      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Length', String(stat.size));
      res.setHeader('Cache-Control', 'no-store');
      fs.createReadStream(blobPath).pipe(res);
    } catch {
      res.status(404).json({ error: 'Shared encrypted payload missing.' });
    }
  });

  // Vite dev middleware or static dist serving
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`RoohCloud server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start RoohCloud server:', err);
  process.exit(1);
});
