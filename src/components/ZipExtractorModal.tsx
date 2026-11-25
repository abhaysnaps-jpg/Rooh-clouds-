import React, { useEffect, useState } from 'react';
import {
  X,
  FileArchive,
  Folder,
  FileText,
  Image as ImageIcon,
  Film,
  Download,
  Lock,
  Eye,
  CheckCircle2,
  Upload,
} from 'lucide-react';
import {
  detectMediaCategory,
  extractAllZipEntriesInBrowser,
  extractZipEntryInBrowser,
  inspectZipInBrowser,
  ZipEntryInfo,
} from '../lib/zipTools';

interface ZipExtractorModalProps {
  zipBlob?: Blob | null;
  archiveName?: string;
  onClose: () => void;
  onEncryptAndSaveEntry?: (fileName: string, mimeType: string, blob: Blob) => Promise<void>;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export const ZipExtractorModal: React.FC<ZipExtractorModalProps> = ({
  zipBlob: initialBlob = null,
  archiveName: initialName = 'archive.zip',
  onClose,
  onEncryptAndSaveEntry,
}) => {
  const [currentBlob, setCurrentBlob] = useState<Blob | null>(initialBlob);
  const [currentName, setCurrentName] = useState<string>(initialName);
  const [entries, setEntries] = useState<ZipEntryInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [previewItem, setPreviewItem] = useState<{
    name: string;
    mimeType: string;
    text?: string;
  } | null>(null);

  useEffect(() => {
    if (!currentBlob) return;
    let active = true;
    setLoading(true);
    setError(null);
    inspectZipInBrowser(currentBlob)
      .then((list) => {
        if (active) setEntries(list);
      })
      .catch((err) => {
        if (active) setError(err instanceof Error ? err.message : 'Failed to parse ZIP archive.');
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [currentBlob]);

  useEffect(() => {
    return () => {
      if (previewUrl) URL.revokeObjectURL(previewUrl);
    };
  }, [previewUrl]);

  const handleSelectLocalZip = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setCurrentBlob(file);
    setCurrentName(file.name);
    setPreviewItem(null);
    setStatusMsg(null);
  };

  const handleDownloadEntry = async (entryPath: string) => {
    if (!currentBlob) return;
    setError(null);
    try {
      const { fileName, blob } = await extractZipEntryInBrowser(currentBlob, entryPath);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setStatusMsg(`Extracted ${fileName} locally in browser.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Extraction failed.');
    }
  };

  const handlePreviewEntry = async (entryPath: string) => {
    if (!currentBlob) return;
    setError(null);
    try {
      const { fileName, mimeType, blob } = await extractZipEntryInBrowser(currentBlob, entryPath);
      if (previewUrl) URL.revokeObjectURL(previewUrl);
      if (mimeType.startsWith('text/') || mimeType === 'application/json') {
        const text = await blob.text();
        setPreviewUrl(null);
        setPreviewItem({ name: fileName, mimeType, text: text.slice(0, 20000) });
      } else {
        const url = URL.createObjectURL(blob);
        setPreviewUrl(url);
        setPreviewItem({ name: fileName, mimeType });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Preview extraction failed.');
    }
  };

  const handleEncryptSaveEntry = async (entryPath: string) => {
    if (!currentBlob || !onEncryptAndSaveEntry) return;
    setError(null);
    setLoading(true);
    try {
      const { fileName, mimeType, blob } = await extractZipEntryInBrowser(currentBlob, entryPath);
      await onEncryptAndSaveEntry(fileName, mimeType, blob);
      setStatusMsg(`Encrypted & saved ${fileName} to your vault.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to encrypt extracted file.');
    } finally {
      setLoading(false);
    }
  };

  const handleExtractAllToVault = async () => {
    if (!currentBlob || !onEncryptAndSaveEntry) return;
    setError(null);
    setLoading(true);
    try {
      const all = await extractAllZipEntriesInBrowser(currentBlob);
      for (const item of all) {
        await onEncryptAndSaveEntry(item.fileName, item.mimeType, item.blob);
      }
      setStatusMsg(`Extracted, encrypted, and saved ${all.length} files to vault.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Batch ZIP extraction failed.');
    } finally {
      setLoading(false);
    }
  };

  const fileCount = entries.filter((e) => !e.dir).length;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#11151E] border border-white/10 rounded-xl w-full max-w-5xl max-h-[88vh] flex flex-col overflow-hidden">
        <div className="flex items-center justify-between gap-4 px-6 py-4 border-b border-white/10">
          <div className="flex items-center gap-3 min-w-0">
            <FileArchive className="w-5 h-5 text-blue-400 shrink-0" />
            <div className="min-w-0">
              <h3 className="text-base font-semibold font-display text-white truncate">
                Browser ZIP Extractor · {currentBlob ? currentName : 'Load Archive'}
              </h3>
              <p className="text-xs text-slate-400 tabular-nums">
                {currentBlob
                  ? `${fileCount} files unpacked strictly in browser memory`
                  : 'Select a .zip archive to extract and encrypt locally without uploading raw files'}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {currentBlob && onEncryptAndSaveEntry && fileCount > 0 && (
              <button
                type="button"
                onClick={handleExtractAllToVault}
                disabled={loading}
                className="px-3.5 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium rounded-lg inline-flex items-center gap-1.5 whitespace-nowrap"
              >
                <Lock className="w-3.5 h-3.5" />
                Encrypt All to Vault
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              aria-label="Close ZIP extractor"
              className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-white/5"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {!currentBlob && (
            <label className="border border-dashed border-white/20 hover:border-blue-500/60 rounded-xl p-10 flex flex-col items-center justify-center gap-3 cursor-pointer bg-[#090B10] transition-colors">
              <Upload className="w-8 h-8 text-blue-400" />
              <span className="text-sm font-medium text-white">
                Choose a .zip archive to extract in browser
              </span>
              <span className="text-xs text-slate-400">
                Supports nested folders, images, videos, PDFs, and documents
              </span>
              <input
                type="file"
                accept=".zip,application/zip"
                onChange={handleSelectLocalZip}
                className="hidden"
              />
            </label>
          )}

          {error && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/30 text-xs text-red-200">
              {error}
            </div>
          )}

          {statusMsg && (
            <div className="p-3 rounded-lg bg-emerald-950/50 border border-emerald-500/30 text-xs text-emerald-200 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{statusMsg}</span>
            </div>
          )}

          {currentBlob && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
              <div className={`${previewItem ? 'lg:col-span-7' : 'lg:col-span-12'} border border-white/10 rounded-lg overflow-hidden bg-[#090B10]`}>
                <div className="px-4 py-2.5 border-b border-white/10 flex items-center justify-between text-xs text-slate-400">
                  <span>Archive Contents</span>
                  <label className="text-blue-400 hover:text-blue-300 cursor-pointer">
                    Open Another ZIP
                    <input
                      type="file"
                      accept=".zip,application/zip"
                      onChange={handleSelectLocalZip}
                      className="hidden"
                    />
                  </label>
                </div>
                <div className="max-h-[420px] overflow-y-auto divide-y divide-white/5">
                  {loading && entries.length === 0 && (
                    <p className="p-4 text-xs text-slate-400">Reading ZIP directory...</p>
                  )}
                  {entries.map((entry) => {
                    const cat = detectMediaCategory(entry.mimeType, entry.name);
                    return (
                      <div
                        key={entry.path}
                        className="px-4 py-2.5 flex items-center justify-between gap-3 hover:bg-white/[0.03] text-xs"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          {entry.dir ? (
                            <Folder className="w-4 h-4 text-slate-500 shrink-0" />
                          ) : cat === 'image' ? (
                            <ImageIcon className="w-4 h-4 text-blue-400 shrink-0" />
                          ) : cat === 'video' ? (
                            <Film className="w-4 h-4 text-emerald-400 shrink-0" />
                          ) : (
                            <FileText className="w-4 h-4 text-slate-400 shrink-0" />
                          )}
                          <span className="truncate text-slate-200 font-mono text-[11px]">
                            {entry.path}
                          </span>
                        </div>
                        {!entry.dir && (
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="text-slate-500 font-mono tabular-nums">
                              {formatBytes(entry.size)}
                            </span>
                            <button
                              type="button"
                              onClick={() => handlePreviewEntry(entry.path)}
                              title="Preview in browser"
                              className="p-1.5 text-slate-300 hover:text-white rounded hover:bg-white/10"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleDownloadEntry(entry.path)}
                              title="Extract & download"
                              className="p-1.5 text-slate-300 hover:text-white rounded hover:bg-white/10"
                            >
                              <Download className="w-3.5 h-3.5" />
                            </button>
                            {onEncryptAndSaveEntry && (
                              <button
                                type="button"
                                onClick={() => handleEncryptSaveEntry(entry.path)}
                                title="Encrypt with Rooh Key & save to vault"
                                className="px-2 py-1 text-[11px] bg-blue-600/20 hover:bg-blue-600/40 text-blue-300 rounded"
                              >
                                Encrypt & Save
                              </button>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {previewItem && (
                <div className="lg:col-span-5 border border-white/10 rounded-lg bg-[#090B10] p-4 flex flex-col gap-3">
                  <div className="flex items-center justify-between border-b border-white/10 pb-2">
                    <span className="text-xs font-medium text-white truncate">
                      {previewItem.name}
                    </span>
                    <button
                      type="button"
                      onClick={() => setPreviewItem(null)}
                      className="text-xs text-slate-400 hover:text-white"
                    >
                      Close
                    </button>
                  </div>
                  {previewItem.text !== undefined ? (
                    <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-words max-h-[360px] overflow-y-auto">
                      {previewItem.text}
                    </pre>
                  ) : previewUrl && previewItem.mimeType.startsWith('image/') ? (
                    <img
                      src={previewUrl}
                      alt={previewItem.name}
                      className="max-h-[360px] object-contain rounded"
                    />
                  ) : previewUrl && previewItem.mimeType.startsWith('video/') ? (
                    <video src={previewUrl} controls className="max-h-[360px] rounded" />
                  ) : previewUrl && previewItem.mimeType === 'application/pdf' ? (
                    <iframe
                      src={previewUrl}
                      title={previewItem.name}
                      className="h-[360px] w-full rounded border-0"
                    />
                  ) : (
                    <p className="text-xs text-slate-400">
                      Binary file ready for local download or encrypted vault import.
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
