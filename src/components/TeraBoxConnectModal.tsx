import React, { useState } from 'react';
import { X, Server, CheckCircle2 } from 'lucide-react';

interface TeraBoxConnectModalProps {
  token: string;
  currentMode: 'webdav' | 'session' | null;
  currentEndpoint: string | null;
  onClose: () => void;
  onUpdated: (user: any) => void;
}

export const TeraBoxConnectModal: React.FC<TeraBoxConnectModalProps> = ({
  token,
  currentMode,
  currentEndpoint,
  onClose,
  onUpdated,
}) => {
  const [mode, setMode] = useState<'webdav' | 'session'>(currentMode || 'webdav');
  const [endpoint, setEndpoint] = useState(currentEndpoint || '');
  const [username, setUsername] = useState('');
  const [credential, setCredential] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await fetch('/api/terabox/configure', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ mode, endpoint, username, credential }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Configuration failed.');
      onUpdated(data.user);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save TeraBox bridge.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#11151E] border border-white/10 rounded-xl w-full max-w-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Server className="w-4 h-4 text-sky-400" />
            <h3 className="text-base font-semibold font-display text-white">
              TeraBox 1,024 GB Cloud Bridge
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

        <form onSubmit={handleSave} className="p-6 space-y-4">
          <p className="text-xs text-slate-400 leading-relaxed">
            Connect your 1,024 GB TeraBox storage via an HTTPS WebDAV bridge or TeraBox session token (`ndus` / `BDUSS`). Files are always encrypted locally with your Rooh Key before streaming to TeraBox.
          </p>

          <div className="grid grid-cols-2 gap-1 p-1 bg-[#090B10] border border-white/10 rounded-lg">
            <button
              type="button"
              onClick={() => setMode('webdav')}
              className={`py-2 text-xs font-medium rounded-md ${
                mode === 'webdav' ? 'bg-[#1B2230] text-white' : 'text-slate-400'
              }`}
            >
              HTTPS WebDAV Bridge
            </button>
            <button
              type="button"
              onClick={() => setMode('session')}
              className={`py-2 text-xs font-medium rounded-md ${
                mode === 'session' ? 'bg-[#1B2230] text-white' : 'text-slate-400'
              }`}
            >
              TeraBox Session Token
            </button>
          </div>

          {mode === 'webdav' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1.5">
                HTTPS WebDAV Endpoint URL
              </label>
              <input
                type="url"
                required
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
                placeholder="https://dav.your-terabox-bridge.example/roohvault"
                className="w-full px-3.5 py-2.5 text-xs bg-[#090B10] border border-white/10 rounded-lg text-white font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              {mode === 'webdav' ? 'WebDAV Username' : 'TeraBox Account Label'}
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Optional account identifier"
              className="w-full px-3.5 py-2.5 text-xs bg-[#090B10] border border-white/10 rounded-lg text-white focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              {mode === 'webdav' ? 'WebDAV Password / App Token' : 'TeraBox ndus / BDUSS Cookie'}
            </label>
            <input
              type="password"
              required
              value={credential}
              onChange={(e) => setCredential(e.target.value)}
              placeholder="Sealed server-side with AES-256-GCM"
              className="w-full px-3.5 py-2.5 text-xs bg-[#090B10] border border-white/10 rounded-lg text-white font-mono focus:outline-none focus:border-blue-500"
            />
          </div>

          {error && (
            <div className="p-3 rounded-lg bg-red-950/50 border border-red-500/30 text-xs text-red-200">
              {error}
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs text-slate-300 hover:text-white"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg inline-flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              {busy ? 'Saving Bridge...' : 'Connect 1,024 GB Pool'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
