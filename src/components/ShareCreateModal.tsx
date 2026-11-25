import React, { useState } from 'react';
import { X, Share2, Copy, Check, ShieldCheck } from 'lucide-react';

interface ShareCreateModalProps {
  fileName: string;
  onClose: () => void;
  onGenerateLink: (expiryHours: number, maxDownloads: number) => Promise<string>;
}

export const ShareCreateModal: React.FC<ShareCreateModalProps> = ({
  fileName,
  onClose,
  onGenerateLink,
}) => {
  const [expiryHours, setExpiryHours] = useState(48);
  const [maxDownloads, setMaxDownloads] = useState(10);
  const [busy, setBusy] = useState(false);
  const [generatedUrl, setGeneratedUrl] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCreate = async () => {
    setError(null);
    setBusy(true);
    try {
      const url = await onGenerateLink(expiryHours, maxDownloads);
      setGeneratedUrl(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create secure link.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#11151E] border border-white/10 rounded-xl w-full max-w-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Share2 className="w-4 h-4 text-blue-400" />
            <h3 className="text-base font-semibold font-display text-white">
              Create Zero-Knowledge Share Link
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <p className="text-xs text-slate-400 leading-relaxed">
            File <span className="text-white font-medium">{fileName}</span> is re-encrypted locally with an ephemeral 256-bit AES-GCM share key. The key lives strictly in the URL <code className="font-mono text-slate-200">#k=</code> fragment and is never transmitted to the server.
          </p>

          {!generatedUrl ? (
            <>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Expires After (Hours)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={720}
                    value={expiryHours}
                    onChange={(e) => setExpiryHours(Number(e.target.value))}
                    className="w-full px-3.5 py-2 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white font-mono tabular-nums"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Max Downloads
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={500}
                    value={maxDownloads}
                    onChange={(e) => setMaxDownloads(Number(e.target.value))}
                    className="w-full px-3.5 py-2 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white font-mono tabular-nums"
                  />
                </div>
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/30 text-xs text-red-200">
                  {error}
                </div>
              )}

              <div className="flex justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="px-4 py-2 text-xs text-slate-300 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleCreate}
                  disabled={busy}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg"
                >
                  {busy ? 'Encrypting Share Payload...' : 'Generate Secure Link'}
                </button>
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div className="p-3.5 bg-[#090B10] border border-emerald-500/30 rounded-lg space-y-2">
                <div className="flex items-center gap-1.5 text-xs text-emerald-400">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Encrypted Share Link Ready</span>
                </div>
                <p className="text-xs font-mono text-slate-200 break-all select-all">
                  {generatedUrl}
                </p>
              </div>
              <div className="flex justify-end gap-3">
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(generatedUrl);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-1.5"
                >
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied Link' : 'Copy Secure Link'}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
