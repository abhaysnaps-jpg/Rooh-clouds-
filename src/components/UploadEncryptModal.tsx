import React, { useState } from 'react';
import { X, Upload, Lock, HardDrive, Cloud, Server } from 'lucide-react';

export type StorageProvider = 'memory-vault' | 'google-drive' | 'terabox';

interface UploadEncryptModalProps {
  defaultProvider: StorageProvider;
  googleConnected: boolean;
  teraboxConnected: boolean;
  onClose: () => void;
  onUploadFiles: (
    files: File[],
    provider: StorageProvider,
    onProgress: (status: string, pct: number) => void
  ) => Promise<void>;
}

export const UploadEncryptModal: React.FC<UploadEncryptModalProps> = ({
  defaultProvider,
  googleConnected,
  teraboxConnected,
  onClose,
  onUploadFiles,
}) => {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [provider, setProvider] = useState<StorageProvider>(defaultProvider);
  const [uploading, setUploading] = useState(false);
  const [progressText, setProgressText] = useState('');
  const [progressPct, setProgressPct] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const handleStart = async () => {
    if (selectedFiles.length === 0) return;
    setError(null);
    setUploading(true);
    try {
      await onUploadFiles(selectedFiles, provider, (text, pct) => {
        setProgressText(text);
        setProgressPct(pct);
      });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Upload failed.');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#11151E] border border-white/10 rounded-xl w-full max-w-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Lock className="w-4 h-4 text-blue-400" />
            <h3 className="text-base font-semibold font-display text-white">
              Encrypt & Upload Files
            </h3>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={uploading}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-white/5"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 space-y-5">
          <div>
            <p className="text-xs font-medium text-slate-300 mb-2">
              Target Cloud Storage Pool
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setProvider('memory-vault')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  provider === 'memory-vault'
                    ? 'bg-blue-600/15 border-blue-500 text-white'
                    : 'bg-[#090B10] border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                <HardDrive className="w-4 h-4 mb-1.5 text-blue-400" />
                <div className="text-xs font-medium">Memory Vault</div>
                <div className="text-[11px] text-slate-400 tabular-nums">10 GB High-Speed</div>
              </button>

              <button
                type="button"
                disabled={!googleConnected}
                onClick={() => setProvider('google-drive')}
                className={`p-3 rounded-lg border text-left transition-colors disabled:opacity-45 ${
                  provider === 'google-drive'
                    ? 'bg-blue-600/15 border-blue-500 text-white'
                    : 'bg-[#090B10] border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                <Cloud className="w-4 h-4 mb-1.5 text-emerald-400" />
                <div className="text-xs font-medium">Google Drive</div>
                <div className="text-[11px] text-slate-400">
                  {googleConnected ? 'Direct Connected' : 'Connect Google First'}
                </div>
              </button>

              <button
                type="button"
                onClick={() => setProvider('terabox')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  provider === 'terabox'
                    ? 'bg-blue-600/15 border-blue-500 text-white'
                    : 'bg-[#090B10] border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                <Server className="w-4 h-4 mb-1.5 text-sky-400" />
                <div className="text-xs font-medium">TeraBox Pool</div>
                <div className="text-[11px] text-slate-400 tabular-nums">
                  {teraboxConnected ? '1,024 GB Linked' : '1,024 GB Pool'}
                </div>
              </button>
            </div>
          </div>

          <label className="border border-dashed border-white/20 hover:border-blue-500/60 rounded-xl p-8 flex flex-col items-center justify-center gap-2 cursor-pointer bg-[#090B10] transition-colors">
            <Upload className="w-6 h-6 text-blue-400" />
            <span className="text-sm font-medium text-white">
              Select Images, Videos, PDFs, or ZIPs
            </span>
            <span className="text-xs text-slate-400">
              AES-256-GCM encryption runs locally before transmission
            </span>
            <input
              type="file"
              multiple
              onChange={(e) => setSelectedFiles(Array.from(e.target.files || []))}
              className="hidden"
            />
          </label>

          {selectedFiles.length > 0 && (
            <div className="bg-[#090B10] border border-white/10 rounded-lg p-3 max-h-36 overflow-y-auto space-y-1.5">
              {selectedFiles.map((f, idx) => (
                <div key={idx} className="flex items-center justify-between text-xs">
                  <span className="text-slate-200 truncate">{f.name}</span>
                  <span className="text-slate-400 font-mono tabular-nums shrink-0 ml-3">
                    {(f.size / (1024 * 1024)).toFixed(2)} MB
                  </span>
                </div>
              ))}
            </div>
          )}

          {uploading && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-slate-300">
                <span>{progressText}</span>
                <span className="font-mono tabular-nums">{progressPct}%</span>
              </div>
              <div className="h-1.5 bg-[#090B10] rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 transition-all duration-150"
                  style={{ width: `${progressPct}%` }}
                />
              </div>
            </div>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/30 text-xs text-red-200">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={uploading}
              className="px-4 py-2 text-xs font-medium text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleStart}
              disabled={uploading || selectedFiles.length === 0}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors"
            >
              {uploading ? 'Encrypting & Uploading...' : 'Encrypt & Upload'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
