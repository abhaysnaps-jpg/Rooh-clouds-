import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Cloud,
  Download,
  Eye,
  FileArchive,
  FileText,
  Film,
  HardDrive,
  Image as ImageIcon,
  Link2,
  Lock,
  LogOut,
  Search,
  Server,
  Share2,
  ShieldCheck,
  Trash2,
  Upload,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import { doc, serverTimestamp, setDoc, deleteDoc } from 'firebase/firestore';
import { VaultUserSession } from './AuthGate';
import { MediaPreviewModal } from './MediaPreviewModal';
import { ShareCreateModal } from './ShareCreateModal';
import { TeraBoxConnectModal } from './TeraBoxConnectModal';
import { StorageProvider, UploadEncryptModal } from './UploadEncryptModal';
import { ZipExtractorModal } from './ZipExtractorModal';
import {
  auth,
  db,
  deleteGoogleDriveFile,
  downloadGoogleDriveFileBlob,
  fetchGoogleDriveQuota,
  GoogleDriveFileItem,
  GoogleDriveQuota,
  handleFirestoreError,
  listGoogleDriveFiles,
  OperationType,
  signInWithGoogleWorkspace,
  signOutGoogleWorkspace,
  uploadEncryptedBlobToDrive,
} from '../lib/firebase';
import {
  decryptBlobAfterDownload,
  decryptMetadataText,
  encryptBlobBeforeUpload,
  encryptBlobForShareLink,
  encryptMetadataText,
} from '../lib/roohCrypto';
import { detectMediaCategory } from '../lib/zipTools';

export interface VaultFileItem {
  fileId: string;
  ownerId: string;
  encryptedName: string;
  displayName?: string;
  resolvedName?: string;
  mimeType: string;
  mediaCategory: 'image' | 'video' | 'pdf' | 'zip' | 'other';
  originalSize: number;
  encryptedSize: number;
  provider: StorageProvider;
  remoteId: string;
  ivHex: string;
  sha256: string;
  createdAt: string;
}

interface ShareItem {
  shareId: string;
  fileName: string;
  mimeType: string;
  originalSize: number;
  expiresAt: string;
  maxDownloads: number;
  downloadsCount: number;
}

type NavSection = 'all' | 'memory-vault' | 'google-drive' | 'terabox' | 'shares';
type MediaFilter = 'all' | 'image' | 'video' | 'pdf' | 'zip';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export const VaultDashboard: React.FC<{
  session: VaultUserSession;
  onSessionUpdate: (next: VaultUserSession) => void;
  onLockVault: () => void;
}> = ({ session, onSessionUpdate, onLockVault }) => {
  const [nav, setNav] = useState<NavSection>('all');
  const [mediaFilter, setMediaFilter] = useState<MediaFilter>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [files, setFiles] = useState<VaultFileItem[]>([]);
  const [shares, setShares] = useState<ShareItem[]>([]);
  const [driveFiles, setDriveFiles] = useState<GoogleDriveFileItem[]>([]);
  const [driveQuota, setDriveQuota] = useState<GoogleDriveQuota | null>(null);
  const [loading, setLoading] = useState(true);
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [lastSpeedMBps, setLastSpeedMBps] = useState<number | null>(null);

  // Modals
  const [uploadOpen, setUploadOpen] = useState(false);
  const [zipModalState, setZipModalState] = useState<{
    open: boolean;
    blob: Blob | null;
    name: string;
  }>({ open: false, blob: null, name: '' });
  const [previewState, setPreviewState] = useState<{
    fileName: string;
    mimeType: string;
    mediaCategory: 'image' | 'video' | 'pdf' | 'zip' | 'other';
    decryptedBlob: Blob;
    durationMs: number;
    downloadSpeedMBps: number;
    sha256Hex: string;
    expectedSha256?: string;
  } | null>(null);
  const [shareTarget, setShareTarget] = useState<VaultFileItem | null>(null);
  const [teraboxModalOpen, setTeraboxModalOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<{
    type: 'vault-file' | 'drive-file' | 'share-link';
    id: string;
    label: string;
    provider?: StorageProvider;
    remoteId?: string;
  } | null>(null);

  const resolveEncryptedNames = useCallback(
    async (rawFiles: VaultFileItem[]): Promise<VaultFileItem[]> => {
      return Promise.all(
        rawFiles.map(async (f) => {
          try {
            const decName = await decryptMetadataText(f.encryptedName, session.cryptoKey);
            return { ...f, resolvedName: decName };
          } catch {
            return { ...f, resolvedName: f.displayName || `Encrypted_${f.fileId.slice(0, 8)}` };
          }
        })
      );
    },
    [session.cryptoKey]
  );

  const loadVaultData = useCallback(async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      const [filesRes, sharesRes] = await Promise.all([
        fetch('/api/vault/files', {
          headers: { Authorization: `Bearer ${session.token}` },
        }),
        fetch('/api/shares', {
          headers: { Authorization: `Bearer ${session.token}` },
        }),
      ]);
      const filesData = await filesRes.json();
      const sharesData = await sharesRes.json();
      if (!filesRes.ok) throw new Error(filesData.error || 'Failed to load vault index.');

      const resolved = await resolveEncryptedNames(filesData.files || []);
      setFiles(resolved);
      if (sharesRes.ok) setShares(sharesData.shares || []);
      if (filesData.user) {
        onSessionUpdate({ ...session, user: filesData.user });
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to load files.');
    } finally {
      setLoading(false);
    }
  }, [session.token, resolveEncryptedNames]);

  const loadGoogleDriveData = useCallback(async (accessToken: string) => {
    try {
      const [quota, gFiles] = await Promise.all([
        fetchGoogleDriveQuota(accessToken),
        listGoogleDriveFiles(accessToken, false),
      ]);
      setDriveQuota(quota);
      setDriveFiles(gFiles);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Google Drive sync error.');
    }
  }, []);

  useEffect(() => {
    loadVaultData();
  }, [loadVaultData]);

  useEffect(() => {
    if (session.googleAccessToken) {
      loadGoogleDriveData(session.googleAccessToken);
    }
  }, [session.googleAccessToken, loadGoogleDriveData]);

  // Sync owner profile to Firestore when signed in via Google Auth
  const syncUserToFirestore = useCallback(
    async (userObj: VaultUserSession['user']) => {
      const fbUser = auth.currentUser;
      if (!fbUser || !fbUser.emailVerified) return;
      const userPath = `users/${fbUser.uid}`;
      try {
        await setDoc(
          doc(db, 'users', fbUser.uid),
          {
            uid: fbUser.uid,
            username: userObj.username,
            email: fbUser.email || userObj.email,
            authSalt: userObj.authSalt,
            encSalt: userObj.encSalt,
            storageQuotaBytes: userObj.memoryQuotaBytes,
            usedMemoryBytes: userObj.usedMemoryBytes,
            teraboxConnected: userObj.teraboxConnected,
            createdAt: serverTimestamp(),
            updatedAt: serverTimestamp(),
          },
          { merge: true }
        );
      } catch (err) {
        handleFirestoreError(err, OperationType.WRITE, userPath);
      }
    },
    []
  );

  const syncFileToFirestore = useCallback(async (item: VaultFileItem) => {
    const fbUser = auth.currentUser;
    if (!fbUser || !fbUser.emailVerified) return;
    const filePath = `users/${fbUser.uid}/files/${item.fileId}`;
    try {
      await setDoc(doc(db, 'users', fbUser.uid, 'files', item.fileId), {
        fileId: item.fileId,
        ownerId: fbUser.uid,
        encryptedName: item.encryptedName,
        mimeType: item.mimeType,
        mediaCategory: item.mediaCategory,
        originalSize: item.originalSize,
        encryptedSize: item.encryptedSize,
        provider: item.provider,
        remoteId: item.remoteId,
        ivHex: item.ivHex,
        sha256: item.sha256,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    } catch (err) {
      handleFirestoreError(err, OperationType.CREATE, filePath);
    }
  }, []);

  const handleConnectGoogleDrive = async () => {
    setErrorMsg(null);
    try {
      const { user, accessToken } = await signInWithGoogleWorkspace();
      const updatedSession: VaultUserSession = {
        ...session,
        googleAccessToken: accessToken,
        googleEmail: user.email,
      };
      onSessionUpdate(updatedSession);
      await syncUserToFirestore(session.user);
      await loadGoogleDriveData(accessToken);
      setActionStatus(`Connected Google Drive (${user.email}).`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Google Drive connection failed.');
    }
  };

  // Core Encrypt-Before-Upload Pipeline
  const handleUploadEncryptedFiles = async (
    incomingFiles: File[],
    provider: StorageProvider,
    onProgress: (status: string, pct: number) => void
  ) => {
    let completed = 0;
    for (const file of incomingFiles) {
      const basePct = Math.round((completed / incomingFiles.length) * 100);
      onProgress(`Encrypting ${file.name} locally (AES-256-GCM)...`, basePct + 10);

      const enc = await encryptBlobBeforeUpload(file, session.cryptoKey);
      const encryptedName = await encryptMetadataText(file.name, session.cryptoKey);
      const fileId = `f_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
      let remoteId = `b_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

      const uploadStart = performance.now();
      if (provider === 'memory-vault') {
        onProgress(`Streaming encrypted ${file.name} to 10 GB Memory Vault...`, basePct + 45);
        const upRes = await fetch(`/api/vault/blobs/${remoteId}`, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${session.token}`,
            'Content-Type': 'application/octet-stream',
          },
          body: enc.encryptedBlob,
        });
        if (!upRes.ok) {
          const d = await upRes.json().catch(() => ({}));
          throw new Error(d.error || 'Memory Vault upload failed.');
        }
      } else if (provider === 'terabox') {
        onProgress(`Streaming encrypted ${file.name} to TeraBox 1,024 GB Pool...`, basePct + 45);
        const upRes = await fetch(`/api/terabox/blobs/${remoteId}`, {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${session.token}`,
            'Content-Type': 'application/octet-stream',
          },
          body: enc.encryptedBlob,
        });
        if (!upRes.ok) {
          const d = await upRes.json().catch(() => ({}));
          throw new Error(d.error || 'TeraBox upload failed.');
        }
      } else if (provider === 'google-drive') {
        if (!session.googleAccessToken) {
          throw new Error('Connect Google Drive first.');
        }
        onProgress(`Uploading encrypted ${file.name} to Google Drive...`, basePct + 35);
        const driveItem = await uploadEncryptedBlobToDrive(
          session.googleAccessToken,
          enc.encryptedBlob,
          {
            displayName: file.name,
            originalMimeType: file.type || 'application/octet-stream',
            ivHex: enc.ivHex,
            sha256: enc.sha256Hex,
          },
          (pct) => onProgress(`Uploading to Google Drive (${pct}%)...`, Math.min(95, basePct + Math.round(pct * 0.5)))
        );
        remoteId = driveItem.id;
      }

      const uploadMs = Math.max(1, performance.now() - uploadStart);
      const speedMBps = Number(
        (enc.encryptedSize / (1024 * 1024) / (uploadMs / 1000)).toFixed(2)
      );
      setLastSpeedMBps(speedMBps);

      const category = detectMediaCategory(file.type, file.name);
      const metaRes = await fetch('/api/vault/files', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({
          fileId,
          encryptedName,
          displayName: file.name,
          mimeType: file.type || 'application/octet-stream',
          mediaCategory: category,
          originalSize: enc.originalSize,
          encryptedSize: enc.encryptedSize,
          provider,
          remoteId,
          ivHex: enc.ivHex,
          sha256: enc.sha256Hex,
        }),
      });
      const metaData = await metaRes.json();
      if (!metaRes.ok) throw new Error(metaData.error || 'Failed to index encrypted file.');

      const savedItem: VaultFileItem = {
        ...metaData.file,
        resolvedName: file.name,
      };
      await syncFileToFirestore(savedItem);
      if (metaData.user) {
        onSessionUpdate({ ...session, user: metaData.user });
      }
      completed += 1;
    }

    onProgress('All files encrypted and stored.', 100);
    await loadVaultData();
    if (session.googleAccessToken) {
      await loadGoogleDriveData(session.googleAccessToken);
    }
    setActionStatus(`Encrypted and uploaded ${incomingFiles.length} file(s).`);
  };

  // Download Ciphertext & Decrypt Locally in Browser
  const fetchAndDecryptVaultFile = async (
    item: VaultFileItem
  ): Promise<{ decryptedBlob: Blob; durationMs: number; downloadSpeedMBps: number; sha256Hex: string }> => {
    const t0 = performance.now();
    let encBlob: Blob;

    if (item.provider === 'memory-vault') {
      const res = await fetch(`/api/vault/blobs/${encodeURIComponent(item.remoteId)}`, {
        headers: { Authorization: `Bearer ${session.token}` },
      });
      if (!res.ok) throw new Error('Failed to download from Memory Vault.');
      encBlob = await res.blob();
    } else if (item.provider === 'terabox') {
      const res = await fetch(`/api/terabox/blobs/${encodeURIComponent(item.remoteId)}`, {
        headers: { Authorization: `Bearer ${session.token}` },
      });
      if (!res.ok) throw new Error('Failed to download from TeraBox Pool.');
      encBlob = await res.blob();
    } else {
      if (!session.googleAccessToken) {
        throw new Error('Sign in with Google Drive to decrypt this Drive file.');
      }
      encBlob = await downloadGoogleDriveFileBlob(session.googleAccessToken, item.remoteId);
    }

    const dlMs = Math.max(1, performance.now() - t0);
    const downloadSpeedMBps = Number(
      (encBlob.size / (1024 * 1024) / (dlMs / 1000)).toFixed(2)
    );
    setLastSpeedMBps(downloadSpeedMBps);

    const dec = await decryptBlobAfterDownload(
      encBlob,
      session.cryptoKey,
      item.mimeType,
      item.ivHex
    );

    return {
      decryptedBlob: dec.decryptedBlob,
      durationMs: dec.durationMs,
      downloadSpeedMBps,
      sha256Hex: dec.sha256Hex,
    };
  };

  const handlePreviewOrExtract = async (item: VaultFileItem) => {
    setErrorMsg(null);
    setActionStatus(`Downloading & decrypting ${item.resolvedName || 'file'} locally...`);
    try {
      const res = await fetchAndDecryptVaultFile(item);
      const name = item.resolvedName || item.displayName || 'vault-file';
      if (item.mediaCategory === 'zip') {
        setZipModalState({ open: true, blob: res.decryptedBlob, name });
      } else {
        setPreviewState({
          fileName: name,
          mimeType: item.mimeType,
          mediaCategory: item.mediaCategory,
          decryptedBlob: res.decryptedBlob,
          durationMs: res.durationMs,
          downloadSpeedMBps: res.downloadSpeedMBps,
          sha256Hex: res.sha256Hex,
          expectedSha256: item.sha256,
        });
      }
      setActionStatus(null);
    } catch (err) {
      setActionStatus(null);
      setErrorMsg(err instanceof Error ? err.message : 'Local decryption failed.');
    }
  };

  const handleDownloadDecrypted = async (item: VaultFileItem) => {
    setErrorMsg(null);
    setActionStatus(`Streaming & decrypting ${item.resolvedName || 'file'}...`);
    try {
      const res = await fetchAndDecryptVaultFile(item);
      const url = URL.createObjectURL(res.decryptedBlob);
      const a = document.createElement('a');
      a.href = url;
      a.download = item.resolvedName || item.displayName || 'decrypted-file';
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setActionStatus(
        `Decrypted locally in ${res.durationMs} ms (${res.downloadSpeedMBps} MB/s).`
      );
    } catch (err) {
      setActionStatus(null);
      setErrorMsg(err instanceof Error ? err.message : 'Download failed.');
    }
  };

  const handleGenerateShareLink = async (
    item: VaultFileItem,
    expiryHours: number,
    maxDownloads: number
  ): Promise<string> => {
    const dec = await fetchAndDecryptVaultFile(item);
    const shareEnc = await encryptBlobForShareLink(dec.decryptedBlob);
    const blobId = `sb_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;

    const upRes = await fetch(`/api/shares/blobs/${blobId}`, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${session.token}`,
        'Content-Type': 'application/octet-stream',
      },
      body: shareEnc.encryptedBlob,
    });
    if (!upRes.ok) throw new Error('Failed to upload encrypted share payload.');

    const fileName = item.resolvedName || item.displayName || 'shared-file';
    const metaRes = await fetch('/api/shares', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.token}`,
      },
      body: JSON.stringify({
        blobId,
        fileName,
        mimeType: item.mimeType,
        originalSize: dec.decryptedBlob.size,
        encryptedSize: shareEnc.encryptedBlob.size,
        sha256: shareEnc.sha256Hex,
        expiryHours,
        maxDownloads,
      }),
    });
    const data = await metaRes.json();
    if (!metaRes.ok) throw new Error(data.error || 'Share creation failed.');

    await loadVaultData();
    return `${window.location.origin}/share/${data.share.shareId}#k=${shareEnc.shareKeyBase64Url}`;
  };

  const executeConfirmedDelete = async () => {
    if (!confirmDelete) return;
    setErrorMsg(null);
    try {
      if (confirmDelete.type === 'vault-file') {
        if (confirmDelete.provider === 'google-drive' && session.googleAccessToken && confirmDelete.remoteId) {
          await deleteGoogleDriveFile(session.googleAccessToken, confirmDelete.remoteId);
        }
        const res = await fetch(`/api/vault/files/${encodeURIComponent(confirmDelete.id)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${session.token}` },
        });
        if (!res.ok) throw new Error('Delete failed.');
        if (auth.currentUser?.emailVerified) {
          try {
            await deleteDoc(doc(db, 'users', auth.currentUser.uid, 'files', confirmDelete.id));
          } catch (err) {
            handleFirestoreError(err, OperationType.DELETE, `users/${auth.currentUser.uid}/files/${confirmDelete.id}`);
          }
        }
        await loadVaultData();
        if (session.googleAccessToken) await loadGoogleDriveData(session.googleAccessToken);
      } else if (confirmDelete.type === 'drive-file' && session.googleAccessToken) {
        await deleteGoogleDriveFile(session.googleAccessToken, confirmDelete.id);
        await loadGoogleDriveData(session.googleAccessToken);
      } else if (confirmDelete.type === 'share-link') {
        await fetch(`/api/shares/${encodeURIComponent(confirmDelete.id)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${session.token}` },
        });
        await loadVaultData();
      }
      setActionStatus(`Deleted ${confirmDelete.label}.`);
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Delete operation failed.');
    } finally {
      setConfirmDelete(null);
    }
  };

  const filteredFiles = useMemo(() => {
    return files.filter((f) => {
      if (nav === 'memory-vault' && f.provider !== 'memory-vault') return false;
      if (nav === 'google-drive' && f.provider !== 'google-drive') return false;
      if (nav === 'terabox' && f.provider !== 'terabox') return false;
      if (mediaFilter !== 'all' && f.mediaCategory !== mediaFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const name = (f.resolvedName || f.displayName || '').toLowerCase();
        if (!name.includes(q) && !f.mimeType.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [files, nav, mediaFilter, searchQuery]);

  const memoryPct = Math.min(
    100,
    (session.user.usedMemoryBytes / session.user.memoryQuotaBytes) * 100
  );

  return (
    <div className="min-h-screen bg-[#090B10] text-slate-100 flex">
      {/* Sidebar (260px) */}
      <aside className="w-[260px] shrink-0 border-r border-white/10 bg-[#0D1017] hidden lg:flex flex-col justify-between p-5">
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <span className="text-lg font-bold font-display tracking-tight text-white">
              RoohCloud
            </span>
          </div>

          <div className="flex items-center gap-3 pb-5 border-b border-white/10">
            <img
              src="/src/assets/images/rooh_default_avatar_1795581632216.jpg"
              alt="Vault user avatar"
              referrerPolicy="no-referrer"
              className="w-9 h-9 rounded-lg object-cover border border-white/10 shrink-0"
            />
            <div className="min-w-0">
              <p className="text-sm font-medium text-white truncate">
                @{session.user.username}
              </p>
              <p className="text-[11px] font-mono text-slate-400 truncate tabular-nums">
                Key {session.keyFingerprint}
              </p>
            </div>
          </div>

          <nav className="space-y-1">
            <p className="px-2.5 pb-1 text-xs font-medium text-slate-500">
              Storage Pools
            </p>
            <button
              type="button"
              onClick={() => setNav('all')}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-sm rounded-lg transition-colors ${
                nav === 'all' ? 'bg-[#182030] text-white font-medium' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2.5 whitespace-nowrap">
                <ShieldCheck className="w-4 h-4 text-blue-400" />
                All Vault Files
              </span>
              <span className="text-xs font-mono tabular-nums text-slate-500">
                {files.length}
              </span>
            </button>

            <button
              type="button"
              onClick={() => setNav('memory-vault')}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-sm rounded-lg transition-colors ${
                nav === 'memory-vault' ? 'bg-[#182030] text-white font-medium' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2.5 whitespace-nowrap">
                <HardDrive className="w-4 h-4 text-blue-400" />
                10 GB Memory
              </span>
            </button>

            <button
              type="button"
              onClick={() => setNav('google-drive')}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-sm rounded-lg transition-colors ${
                nav === 'google-drive' ? 'bg-[#182030] text-white font-medium' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2.5 whitespace-nowrap">
                <Cloud className="w-4 h-4 text-emerald-400" />
                Google Drive
              </span>
            </button>

            <button
              type="button"
              onClick={() => setNav('terabox')}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-sm rounded-lg transition-colors ${
                nav === 'terabox' ? 'bg-[#182030] text-white font-medium' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2.5 whitespace-nowrap">
                <Server className="w-4 h-4 text-sky-400" />
                TeraBox 1024 GB
              </span>
            </button>

            <p className="px-2.5 pt-4 pb-1 text-xs font-medium text-slate-500">
              Browser Tools
            </p>
            <button
              type="button"
              onClick={() => setZipModalState({ open: true, blob: null, name: 'Select ZIP' })}
              className="w-full flex items-center gap-2.5 px-2.5 py-2 text-sm text-slate-400 hover:text-white hover:bg-white/5 rounded-lg transition-colors whitespace-nowrap"
            >
              <FileArchive className="w-4 h-4 text-slate-300" />
              ZIP Extractor
            </button>

            <button
              type="button"
              onClick={() => setNav('shares')}
              className={`w-full flex items-center justify-between px-2.5 py-2 text-sm rounded-lg transition-colors ${
                nav === 'shares' ? 'bg-[#182030] text-white font-medium' : 'text-slate-400 hover:text-white hover:bg-white/5'
              }`}
            >
              <span className="flex items-center gap-2.5 whitespace-nowrap">
                <Link2 className="w-4 h-4 text-slate-300" />
                Share Links
              </span>
              <span className="text-xs font-mono tabular-nums text-slate-500">
                {shares.length}
              </span>
            </button>
          </nav>
        </div>

        <div className="pt-4 border-t border-white/10 space-y-3">
          <div className="space-y-1.5">
            <div className="flex justify-between text-xs">
              <span className="text-slate-400">Memory Vault</span>
              <span className="font-mono text-slate-300 tabular-nums">
                {formatBytes(session.user.usedMemoryBytes)} / 10 GB
              </span>
            </div>
            <div className="h-1.5 bg-[#090B10] rounded-full overflow-hidden">
              <div
                className="h-full bg-blue-500 transition-all"
                style={{ width: `${Math.max(2, memoryPct)}%` }}
              />
            </div>
          </div>
          <button
            type="button"
            onClick={async () => {
              await signOutGoogleWorkspace().catch(() => {});
              onLockVault();
            }}
            className="w-full py-2 px-3 text-xs font-medium text-slate-300 hover:text-white bg-[#141925] hover:bg-[#1B2232] border border-white/10 rounded-lg flex items-center justify-center gap-2 transition-colors whitespace-nowrap"
          >
            <LogOut className="w-3.5 h-3.5" />
            Lock Vault
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Clean 3-Zone Top Bar */}
        <header className="border-b border-white/10 px-6 py-3.5 flex items-center justify-between gap-8 bg-[#090B10]">
          <div className="text-sm font-medium text-slate-300 whitespace-nowrap shrink-0">
            RoohCloud /{' '}
            <span className="text-white">
              {nav === 'all'
                ? 'All Vault Files'
                : nav === 'memory-vault'
                ? '10 GB Memory Vault'
                : nav === 'google-drive'
                ? 'Google Drive'
                : nav === 'terabox'
                ? 'TeraBox 1,024 GB'
                : 'Secure Share Links'}
            </span>
          </div>

          <div className="flex-1 max-w-md relative hidden sm:block">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search decrypted filenames or media types..."
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-[#11151E] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex items-center gap-3 shrink-0">
            <button
              type="button"
              onClick={() => setUploadOpen(true)}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-2 transition-colors whitespace-nowrap shrink-0"
            >
              <Upload className="w-3.5 h-3.5" />
              Upload & Encrypt
            </button>
          </div>
        </header>

        <main className="flex-1 p-6 space-y-6 overflow-y-auto">
          {/* Storage Pools Overview Strip */}
          <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-[#11151E] border border-white/10 rounded-xl p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  10 GB Memory Vault
                </span>
                <HardDrive className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <p className="text-xl font-semibold font-mono text-white tabular-nums">
                  {formatBytes(session.user.usedMemoryBytes)}{' '}
                  <span className="text-xs font-normal text-slate-500">/ 10.00 GB</span>
                </p>
                <p className="text-xs text-slate-400 mt-1 tabular-nums">
                  {lastSpeedMBps !== null
                    ? `Last encrypted transfer: ${lastSpeedMBps} MB/s`
                    : 'Direct binary AES-256-GCM streaming'}
                </p>
              </div>
            </div>

            <div className="bg-[#11151E] border border-white/10 rounded-xl p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  Google Drive Direct Auth
                </span>
                <Cloud className="w-4 h-4 text-emerald-400" />
              </div>
              {session.googleAccessToken ? (
                <div>
                  <p className="text-xl font-semibold font-mono text-white tabular-nums">
                    {driveQuota ? formatBytes(driveQuota.usage) : 'Connected'}{' '}
                    {driveQuota && (
                      <span className="text-xs font-normal text-slate-500">
                        / {formatBytes(driveQuota.limit)}
                      </span>
                    )}
                  </p>
                  <p className="text-xs text-slate-400 mt-1 truncate">
                    {session.googleEmail} · Resumable encrypted sync
                  </p>
                </div>
              ) : (
                <div className="flex items-center justify-between gap-3">
                  <span className="text-xs text-slate-400">Not connected</span>
                  <button
                    type="button"
                    onClick={handleConnectGoogleDrive}
                    className="px-3 py-1.5 bg-white hover:bg-slate-100 text-[#1F1F1F] text-xs font-medium rounded-lg whitespace-nowrap shrink-0"
                  >
                    Connect Google Drive
                  </button>
                </div>
              )}
            </div>

            <div className="bg-[#11151E] border border-white/10 rounded-xl p-5 flex flex-col justify-between gap-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-400">
                  TeraBox 1,024 GB Pool
                </span>
                <Server className="w-4 h-4 text-sky-400" />
              </div>
              <div className="flex items-end justify-between gap-3">
                <div>
                  <p className="text-xl font-semibold font-mono text-white tabular-nums">
                    {formatBytes(session.user.usedTeraboxBytes)}{' '}
                    <span className="text-xs font-normal text-slate-500">/ 1,024 GB</span>
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    {session.user.teraboxConnected
                      ? `Bridge active (${session.user.teraboxMode})`
                      : 'High-speed pool ready'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => setTeraboxModalOpen(true)}
                  className="px-3 py-1.5 bg-[#182030] hover:bg-[#212C42] border border-white/10 text-slate-200 text-xs font-medium rounded-lg whitespace-nowrap shrink-0"
                >
                  {session.user.teraboxConnected ? 'Configure' : 'Connect Bridge'}
                </button>
              </div>
            </div>
          </section>

          {actionStatus && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-200 flex items-center justify-between">
              <span>{actionStatus}</span>
              <button
                type="button"
                onClick={() => setActionStatus(null)}
                className="text-emerald-300 hover:text-white"
              >
                Dismiss
              </button>
            </div>
          )}

          {errorMsg && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/30 text-xs text-red-200 flex items-center justify-between">
              <span>{errorMsg}</span>
              <button
                type="button"
                onClick={() => setErrorMsg(null)}
                className="text-red-300 hover:text-white"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Share Links View */}
          {nav === 'shares' ? (
            <section className="bg-[#11151E] border border-white/10 rounded-xl overflow-hidden">
              <div className="px-5 py-4 border-b border-white/10 flex items-center justify-between">
                <h2 className="text-sm font-semibold font-display text-white">
                  Active Encrypted Share Links
                </h2>
                <span className="text-xs text-slate-400">
                  Decryption keys remain only in your copied #k= URLs
                </span>
              </div>
              {shares.length === 0 ? (
                <div className="p-10 text-center text-sm text-slate-400">
                  No active share links yet. Click Share on any file to generate a zero-knowledge link.
                </div>
              ) : (
                <div className="divide-y divide-white/5">
                  {shares.map((s) => (
                    <div
                      key={s.shareId}
                      className="px-5 py-3.5 flex items-center justify-between gap-4 text-xs"
                    >
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-white truncate">{s.fileName}</p>
                        <p className="text-slate-400 mt-0.5 tabular-nums">
                          {formatBytes(s.originalSize)} · Downloads {s.downloadsCount}/{s.maxDownloads} · Expires{' '}
                          {new Date(s.expiresAt).toLocaleString()}
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          setConfirmDelete({
                            type: 'share-link',
                            id: s.shareId,
                            label: s.fileName,
                          })
                        }
                        className="px-3 py-1.5 text-red-300 hover:text-red-200 hover:bg-red-500/10 rounded-lg transition-colors whitespace-nowrap shrink-0"
                      >
                        Revoke Link
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </section>
          ) : (
            /* Encrypted Files Table + Media Filters */
            <section className="bg-[#11151E] border border-white/10 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-white/10 flex flex-wrap items-center justify-between gap-4">
                <div className="flex items-center gap-1 p-1 bg-[#090B10] border border-white/10 rounded-lg overflow-x-auto">
                  {(['all', 'image', 'video', 'pdf', 'zip'] as MediaFilter[]).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setMediaFilter(cat)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                        mediaFilter === cat
                          ? 'bg-[#1B2230] text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {cat === 'all'
                        ? 'All Media'
                        : cat === 'image'
                        ? 'Images'
                        : cat === 'video'
                        ? 'Videos'
                        : cat === 'pdf'
                        ? 'PDFs'
                        : 'ZIP Archives'}
                    </button>
                  ))}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setZipModalState({ open: true, blob: null, name: 'Select ZIP' })}
                    className="px-3 py-1.5 bg-[#182030] hover:bg-[#222C42] border border-white/10 text-xs text-slate-200 rounded-lg inline-flex items-center gap-1.5 whitespace-nowrap shrink-0"
                  >
                    <FileArchive className="w-3.5 h-3.5" />
                    Extract Local ZIP
                  </button>
                  <button
                    type="button"
                    onClick={loadVaultData}
                    title="Refresh vault"
                    className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {loading ? (
                <div className="p-8 space-y-3">
                  {[1, 2, 3].map((n) => (
                    <div key={n} className="h-10 bg-white/5 rounded-lg animate-pulse" />
                  ))}
                </div>
              ) : filteredFiles.length === 0 ? (
                <div className="p-12 text-center space-y-3">
                  <Lock className="w-8 h-8 text-slate-500 mx-auto" />
                  <p className="text-sm font-medium text-white">
                    No encrypted files in this view yet
                  </p>
                  <p className="text-xs text-slate-400 max-w-md mx-auto">
                    Upload images, videos, PDFs, or ZIP archives. Every file is encrypted locally in your browser before leaving your device.
                  </p>
                  <button
                    type="button"
                    onClick={() => setUploadOpen(true)}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-2"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    Encrypt First File
                  </button>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-white/10 text-xs text-slate-400">
                        <th className="py-3 px-5 font-medium">File Name</th>
                        <th className="py-3 px-4 font-medium">Storage Pool</th>
                        <th className="py-3 px-4 font-medium text-right">Size</th>
                        <th className="py-3 px-4 font-medium text-right">Encrypted</th>
                        <th className="py-3 px-5 font-medium text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-white/5 text-sm">
                      {filteredFiles.map((item) => {
                        const name = item.resolvedName || item.displayName || item.fileId;
                        return (
                          <tr
                            key={item.fileId}
                            className="hover:bg-white/[0.02] transition-colors h-12"
                          >
                            <td className="py-2.5 px-5">
                              <div className="flex items-center gap-3 min-w-0">
                                {item.mediaCategory === 'image' ? (
                                  <ImageIcon className="w-4 h-4 text-blue-400 shrink-0" />
                                ) : item.mediaCategory === 'video' ? (
                                  <Film className="w-4 h-4 text-emerald-400 shrink-0" />
                                ) : item.mediaCategory === 'zip' ? (
                                  <FileArchive className="w-4 h-4 text-sky-400 shrink-0" />
                                ) : (
                                  <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                                )}
                                <div className="min-w-0">
                                  <p className="text-sm font-medium text-white truncate max-w-xs sm:max-w-sm">
                                    {name}
                                  </p>
                                  <p className="text-[11px] text-slate-500 truncate">
                                    {item.mimeType} · SHA-256 {item.sha256.slice(0, 10)}
                                  </p>
                                </div>
                              </div>
                            </td>
                            <td className="py-2.5 px-4 text-xs text-slate-300 whitespace-nowrap">
                              {item.provider === 'memory-vault'
                                ? '10 GB Memory Vault'
                                : item.provider === 'google-drive'
                                ? 'Google Drive'
                                : 'TeraBox 1024 GB'}
                            </td>
                            <td className="py-2.5 px-4 text-xs font-mono text-slate-300 text-right tabular-nums whitespace-nowrap">
                              {formatBytes(item.originalSize)}
                            </td>
                            <td className="py-2.5 px-4 text-xs font-mono text-slate-400 text-right tabular-nums whitespace-nowrap">
                              AES-256-GCM
                            </td>
                            <td className="py-2.5 px-5 text-right whitespace-nowrap">
                              <div className="inline-flex items-center gap-1">
                                <button
                                  type="button"
                                  onClick={() => handlePreviewOrExtract(item)}
                                  title={item.mediaCategory === 'zip' ? 'Extract ZIP in browser' : 'Decrypt & preview locally'}
                                  className="p-1.5 text-slate-300 hover:text-white rounded hover:bg-white/10"
                                >
                                  {item.mediaCategory === 'zip' ? (
                                    <FileArchive className="w-4 h-4" />
                                  ) : (
                                    <Eye className="w-4 h-4" />
                                  )}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDownloadDecrypted(item)}
                                  title="Download & decrypt locally"
                                  className="p-1.5 text-slate-300 hover:text-white rounded hover:bg-white/10"
                                >
                                  <Download className="w-4 h-4" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => setShareTarget(item)}
                                  title="Create zero-knowledge share link"
                                  className="p-1.5 text-slate-300 hover:text-white rounded hover:bg-white/10"
                                >
                                  <Share2 className="w-4 h-4" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() =>
                                    setConfirmDelete({
                                      type: 'vault-file',
                                      id: item.fileId,
                                      label: name,
                                      provider: item.provider,
                                      remoteId: item.remoteId,
                                    })
                                  }
                                  title="Delete encrypted file"
                                  className="p-1.5 text-slate-400 hover:text-red-400 rounded hover:bg-red-500/10"
                                >
                                  <Trash2 className="w-4 h-4" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {/* Live Google Drive Explorer when viewing Google Drive pool */}
          {nav === 'google-drive' && session.googleAccessToken && driveFiles.length > 0 && (
            <section className="bg-[#11151E] border border-white/10 rounded-xl overflow-hidden">
              <div className="px-5 py-3.5 border-b border-white/10 flex items-center justify-between">
                <h3 className="text-sm font-semibold font-display text-white">
                  Google Drive Connected Files ({driveFiles.length})
                </h3>
                <span className="text-xs text-slate-400">
                  Direct Google Drive API v3
                </span>
              </div>
              <div className="divide-y divide-white/5">
                {driveFiles.slice(0, 15).map((df) => (
                  <div
                    key={df.id}
                    className="px-5 py-3 flex items-center justify-between gap-4 text-xs"
                  >
                    <div className="min-w-0">
                      <p className="text-sm text-white truncate">{df.name}</p>
                      <p className="text-slate-500">
                        {df.mimeType} {df.size ? `· ${formatBytes(Number(df.size))}` : ''}
                      </p>
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        setConfirmDelete({
                          type: 'drive-file',
                          id: df.id,
                          label: df.name,
                        })
                      }
                      className="px-3 py-1.5 text-red-300 hover:text-red-200 hover:bg-red-500/10 rounded-lg whitespace-nowrap shrink-0"
                    >
                      Delete from Drive
                    </button>
                  </div>
                ))}
              </div>
            </section>
          )}
        </main>
      </div>

      {/* Modals */}
      {uploadOpen && (
        <UploadEncryptModal
          defaultProvider={
            nav === 'google-drive' && session.googleAccessToken
              ? 'google-drive'
              : nav === 'terabox'
              ? 'terabox'
              : 'memory-vault'
          }
          googleConnected={Boolean(session.googleAccessToken)}
          teraboxConnected={session.user.teraboxConnected}
          onClose={() => setUploadOpen(false)}
          onUploadFiles={handleUploadEncryptedFiles}
        />
      )}

      {zipModalState.open && (
        <ZipExtractorModal
          zipBlob={zipModalState.blob}
          archiveName={zipModalState.name}
          onClose={() => setZipModalState({ open: false, blob: null, name: '' })}
          onEncryptAndSaveEntry={async (fileName, mimeType, blob) => {
            const file = new File([blob], fileName, { type: mimeType });
            await handleUploadEncryptedFiles([file], 'memory-vault', () => {});
          }}
        />
      )}

      {previewState && (
        <MediaPreviewModal
          fileName={previewState.fileName}
          mimeType={previewState.mimeType}
          mediaCategory={previewState.mediaCategory}
          decryptedBlob={previewState.decryptedBlob}
          decryptStats={{
            durationMs: previewState.durationMs,
            downloadSpeedMBps: previewState.downloadSpeedMBps,
            sha256Hex: previewState.sha256Hex,
            expectedSha256: previewState.expectedSha256,
          }}
          onClose={() => setPreviewState(null)}
        />
      )}

      {shareTarget && (
        <ShareCreateModal
          fileName={shareTarget.resolvedName || shareTarget.displayName || shareTarget.fileId}
          onClose={() => setShareTarget(null)}
          onGenerateLink={(hours, maxDl) =>
            handleGenerateShareLink(shareTarget, hours, maxDl)
          }
        />
      )}

      {teraboxModalOpen && (
        <TeraBoxConnectModal
          token={session.token}
          currentMode={session.user.teraboxMode}
          currentEndpoint={session.user.teraboxEndpoint}
          onClose={() => setTeraboxModalOpen(false)}
          onUpdated={(updatedUser) =>
            onSessionUpdate({ ...session, user: updatedUser })
          }
        />
      )}

      {/* Mandatory Explicit Confirmation Dialog for Destructive Operations */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#11151E] border border-white/10 rounded-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center gap-3 text-amber-400">
              <AlertTriangle className="w-5 h-5 shrink-0" />
              <h3 className="text-base font-semibold font-display text-white">
                Confirm Permanent Deletion
              </h3>
            </div>
            <p className="text-xs text-slate-300 leading-relaxed">
              Are you sure you want to permanently delete{' '}
              <span className="text-white font-medium">{confirmDelete.label}</span>? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3 pt-2">
              <button
                type="button"
                onClick={() => setConfirmDelete(null)}
                className="px-4 py-2 text-xs text-slate-300 hover:text-white"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={executeConfirmedDelete}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-medium rounded-lg"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
