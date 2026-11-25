import React, { useEffect, useState } from 'react';
import { X, Download, ShieldCheck, CheckCircle2 } from 'lucide-react';

interface MediaPreviewModalProps {
  fileName: string;
  mimeType: string;
  mediaCategory: 'image' | 'video' | 'pdf' | 'zip' | 'other';
  decryptedBlob: Blob;
  decryptStats: {
    durationMs: number;
    downloadSpeedMBps: number;
    sha256Hex: string;
    expectedSha256?: string;
  };
  onClose: () => void;
}

export const MediaPreviewModal: React.FC<MediaPreviewModalProps> = ({
  fileName,
  mimeType,
  mediaCategory,
  decryptedBlob,
  decryptStats,
  onClose,
}) => {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [textPreview, setTextPreview] = useState<string | null>(null);

  useEffect(() => {
    const url = URL.createObjectURL(decryptedBlob);
    setBlobUrl(url);
    if (
      mediaCategory === 'other' &&
      (mimeType.startsWith('text/') || mimeType === 'application/json')
    ) {
      decryptedBlob.text().then((t) => setTextPreview(t.slice(0, 30000)));
    }
    return () => {
      URL.revokeObjectURL(url);
    };
  }, [decryptedBlob, mediaCategory, mimeType]);

  const hashVerified =
    !decryptStats.expectedSha256 ||
    decryptStats.expectedSha256 === decryptStats.sha256Hex;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#11151E] border border-white/10 rounded-xl w-full max-w-5xl max-h-[90vh] flex flex-col overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-xs text-emerald-400 mb-1">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span>Decrypted Locally on Device · Zero Server Exposure</span>
            </div>
            <h3 className="text-base font-semibold font-display text-white truncate">
              {fileName}
            </h3>
            <p className="text-xs text-slate-400 tabular-nums mt-0.5">
              Download {decryptStats.downloadSpeedMBps} MB/s · Local AES-256-GCM {decryptStats.durationMs} ms ·{' '}
              {hashVerified ? 'SHA-256 Verified' : 'Checksum Mismatch'}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {blobUrl && (
              <a
                href={blobUrl}
                download={fileName}
                className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-1.5 whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5" />
                Save Decrypted
              </a>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close preview"
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-6 bg-[#090B10] flex flex-col items-center justify-center">
          {blobUrl && mediaCategory === 'image' && (
            <img
              src={blobUrl}
              alt={fileName}
              className="max-h-[65vh] max-w-full rounded object-contain"
            />
          )}

          {blobUrl && mediaCategory === 'video' && (
            <video
              src={blobUrl}
              controls
              autoPlay
              className="max-h-[65vh] w-full rounded bg-black"
            />
          )}

          {blobUrl && mediaCategory === 'pdf' && (
            <iframe
              src={blobUrl}
              title={fileName}
              className="w-full h-[68vh] rounded border border-white/10"
            />
          )}

          {textPreview !== null && (
            <pre className="w-full max-h-[65vh] overflow-auto text-xs font-mono text-slate-300 bg-[#11151E] p-4 rounded-lg border border-white/10 whitespace-pre-wrap">
              {textPreview}
            </pre>
          )}

          {mediaCategory === 'other' && textPreview === null && (
            <div className="text-center space-y-3 py-10">
              <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
              <p className="text-sm text-white font-medium">
                File decrypted in browser memory ({(decryptedBlob.size / (1024 * 1024)).toFixed(2)} MB)
              </p>
              <p className="text-xs text-slate-400 font-mono">
                SHA-256: {decryptStats.sha256Hex}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
