import React, { useEffect, useState } from 'react';
import {
  Download,
  Lock,
  ShieldCheck,
  AlertCircle,
  FileArchive,
  ArrowLeft,
} from 'lucide-react';
import { decryptShareBlobInBrowser } from '../lib/roohCrypto';
import { detectMediaCategory } from '../lib/zipTools';
import { ZipExtractorModal } from './ZipExtractorModal';

interface ShareMetadata {
  shareId: string;
  fileName: string;
  mimeType: string;
  originalSize: number;
  encryptedSize: number;
  sha256: string;
  expiresAt: string;
  maxDownloads: number;
  downloadsCount: number;
}

export const ShareViewer: React.FC<{ shareId: string }> = ({ shareId }) => {
  const [meta, setMeta] = useState<ShareMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [decrypting, setDecrypting] = useState(false);
  const [decryptedUrl, setDecryptedUrl] = useState<string | null>(null);
  const [decryptedBlob, setDecryptedBlob] = useState<Blob | null>(null);
  const [stats, setStats] = useState<{ speedMBps: number; durationMs: number } | null>(null);
  const [zipOpen, setZipOpen] = useState(false);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch(`/api/shares/${encodeURIComponent(shareId)}`);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Share link unavailable.');
        if (active) setMeta(data.share);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : 'Unable to load share link.');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [shareId]);

  useEffect(() => {
    return () => {
      if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
    };
  }, [decryptedUrl]);

  const handleDownloadAndDecrypt = async () => {
    if (!meta) return;
    setError(null);
    setDecrypting(true);
    try {
      const hash = window.location.hash.replace(/^#/, '');
      const params = new URLSearchParams(hash);
      const key = params.get('k');
      if (!key) {
        throw new Error('Decryption key missing from URL #k= fragment.');
      }

      const t0 = performance.now();
      const res = await fetch(`/api/shares/${encodeURIComponent(shareId)}/blob`);
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || 'Failed to download encrypted payload.');
      }
      const encBlob = await res.blob();
      const downloadMs = Math.max(1, performance.now() - t0);
      const speedMBps = Number(
        (encBlob.size / (1024 * 1024) / (downloadMs / 1000)).toFixed(2)
      );

      const dec = await decryptShareBlobInBrowser(encBlob, key, meta.mimeType);
      if (decryptedUrl) URL.revokeObjectURL(decryptedUrl);
      const url = URL.createObjectURL(dec.decryptedBlob);
      setDecryptedBlob(dec.decryptedBlob);
      setDecryptedUrl(url);
      setStats({ speedMBps, durationMs: dec.durationMs });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Local decryption failed.');
    } finally {
      setDecrypting(false);
    }
  };

  const category = meta ? detectMediaCategory(meta.mimeType, meta.fileName) : 'other';

  return (
    <div className="min-h-screen bg-[#090B10] text-slate-100 flex flex-col">
      <header className="border-b border-white/10 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between gap-6">
          <a href="/" className="text-lg font-bold font-display text-white whitespace-nowrap shrink-0">
            RoohCloud
          </a>
          <a
            href="/"
            className="inline-flex items-center gap-1.5 text-xs text-slate-300 hover:text-white transition-colors whitespace-nowrap shrink-0"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Open Vault
          </a>
        </div>
      </header>

      <main className="flex-1 max-w-4xl w-full mx-auto px-6 py-12">
        <div className="bg-[#11151E] border border-white/10 rounded-xl p-6 sm:p-8 space-y-6">
          {loading && <p className="text-sm text-slate-400">Verifying encrypted share link...</p>}

          {error && (
            <div className="p-4 rounded-lg bg-red-950/50 border border-red-500/30 text-red-200 text-sm flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {meta && !error && (
            <>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-white/10 pb-5">
                <div>
                  <div className="flex items-center gap-2 text-xs text-emerald-400 mb-1.5">
                    <ShieldCheck className="w-4 h-4" />
                    <span>Zero-Knowledge Share Link · Key Never Sent to Server</span>
                  </div>
                  <h1 className="text-xl font-semibold font-display text-white break-all">
                    {meta.fileName}
                  </h1>
                  <p className="text-xs text-slate-400 mt-1 tabular-nums">
                    {(meta.originalSize / (1024 * 1024)).toFixed(2)} MB · {meta.mimeType} · Downloads {meta.downloadsCount}/{meta.maxDownloads}
                  </p>
                </div>

                {!decryptedBlob ? (
                  <button
                    type="button"
                    onClick={handleDownloadAndDecrypt}
                    disabled={decrypting}
                    className="px-4 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors inline-flex items-center gap-2 whitespace-nowrap shrink-0"
                  >
                    <Lock className="w-4 h-4" />
                    {decrypting ? 'Decrypting on Device...' : 'Download & Decrypt Locally'}
                  </button>
                ) : (
                  <div className="flex items-center gap-3">
                    {category === 'zip' && (
                      <button
                        type="button"
                        onClick={() => setZipOpen(true)}
                        className="px-4 py-2 bg-[#1B2230] hover:bg-[#242D40] border border-white/10 text-white text-xs font-medium rounded-lg inline-flex items-center gap-2 whitespace-nowrap shrink-0"
                      >
                        <FileArchive className="w-4 h-4" />
                        Extract ZIP in Browser
                      </button>
                    )}
                    <a
                      href={decryptedUrl || '#'}
                      download={meta.fileName}
                      className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-2 whitespace-nowrap shrink-0"
                    >
                      <Download className="w-4 h-4" />
                      Save File
                    </a>
                  </div>
                )}
              </div>

              {stats && (
                <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3 tabular-nums">
                  <span>Transfer Speed: {stats.speedMBps} MB/s</span>
                  <span aria-hidden="true">·</span>
                  <span>Local AES-256-GCM Decrypt: {stats.durationMs} ms</span>
                </div>
              )}

              {decryptedUrl && category === 'image' && (
                <div className="bg-[#090B10] border border-white/10 rounded-lg p-4 flex justify-center">
                  <img
                    src={decryptedUrl}
                    alt={meta.fileName}
                    className="max-h-[520px] rounded object-contain"
                  />
                </div>
              )}

              {decryptedUrl && category === 'video' && (
                <div className="bg-[#090B10] border border-white/10 rounded-lg p-2">
                  <video
                    src={decryptedUrl}
                    controls
                    className="w-full max-h-[520px] rounded"
                  />
                </div>
              )}

              {decryptedUrl && category === 'pdf' && (
                <div className="bg-[#090B10] border border-white/10 rounded-lg overflow-hidden h-[560px]">
                  <iframe
                    src={decryptedUrl}
                    title={meta.fileName}
                    className="w-full h-full border-0"
                  />
                </div>
              )}
            </>
          )}
        </div>
      </main>

      {zipOpen && decryptedBlob && meta && (
        <ZipExtractorModal
          zipBlob={decryptedBlob}
          archiveName={meta.fileName}
          onClose={() => setZipOpen(false)}
        />
      )}
    </div>
  );
};
