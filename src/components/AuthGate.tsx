import React, { useState } from 'react';
import {
  KeyRound,
  Lock,
  Mail,
  ShieldCheck,
  UserPlus,
  ArrowRight,
  CheckCircle2,
  Copy,
  Check,
  Unlock,
  AlertCircle,
} from 'lucide-react';
import {
  computeKeyFingerprint,
  createRecoveryCipherBlock,
  decodeRecoveryCipherBlockInBrowser,
  deriveRoohAuthVerifier,
  deriveRoohEncryptionKey,
  generateSaltHex,
} from '../lib/roohCrypto';
import {
  sendRecoveryCipherEmail,
  signInWithGoogleWorkspace,
} from '../lib/firebase';

export interface VaultUserSession {
  token: string;
  user: {
    id: string;
    username: string;
    email: string;
    authSalt: string;
    encSalt: string;
    recoveryHint: string;
    usedMemoryBytes: number;
    memoryQuotaBytes: number;
    usedTeraboxBytes: number;
    teraboxQuotaBytes: number;
    teraboxConnected: boolean;
    teraboxMode: 'webdav' | 'session' | null;
    teraboxEndpoint: string | null;
  };
  cryptoKey: CryptoKey;
  keyFingerprint: string;
  googleAccessToken: string | null;
  googleEmail: string | null;
}

interface AuthGateProps {
  onAuthenticated: (session: VaultUserSession) => void;
}

type AuthTab = 'login' | 'register' | 'google' | 'recovery';

export const AuthGate: React.FC<AuthGateProps> = ({ onAuthenticated }) => {
  const [tab, setTab] = useState<AuthTab>('login');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  // Sign In fields
  const [loginUsername, setLoginUsername] = useState('');
  const [loginRoohKey, setLoginRoohKey] = useState('');

  // Register fields
  const [regUsername, setRegUsername] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regRoohKey, setRegRoohKey] = useState('');
  const [regRecoveryPin, setRegRecoveryPin] = useState('');
  const [regHint, setRegHint] = useState('');

  // Google Auth + Rooh Key binding
  const [googlePendingKey, setGooglePendingKey] = useState('');

  // Multi-Step Recovery & Pre-Login Browser Cipher Decoder
  const [recStep, setRecStep] = useState<1 | 2 | 3 | 4>(1);
  const [recIdentifier, setRecIdentifier] = useState('');
  const [recPin, setRecPin] = useState('');
  const [recChallengeId, setRecChallengeId] = useState('');
  const [recTargetEmail, setRecTargetEmail] = useState('');
  const [recGeneratedMailBlock, setRecGeneratedMailBlock] = useState('');
  const [recDemoCodeNotice, setRecDemoCodeNotice] = useState('');
  const [recGmailSent, setRecGmailSent] = useState(false);
  const [recInputCode, setRecInputCode] = useState('');
  const [recVerifiedTicket, setRecVerifiedTicket] = useState('');
  const [recCipherInput, setRecCipherInput] = useState('');
  const [recDecodedResult, setRecDecodedResult] = useState<{
    username: string;
    recoveryToken: string;
    hint: string;
    issuedAt: string;
  } | null>(null);
  const [recNewRoohKey, setRecNewRoohKey] = useState('');
  const [copiedCipher, setCopiedCipher] = useState(false);

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const challengeRes = await fetch('/api/auth/challenge', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: loginUsername.trim() }),
      });
      const challengeData = await challengeRes.json();
      if (!challengeRes.ok) {
        throw new Error(challengeData.error || 'Account lookup failed.');
      }

      const authVerifier = await deriveRoohAuthVerifier(
        loginRoohKey,
        challengeData.authSalt
      );
      const loginRes = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: loginUsername.trim(),
          authVerifier,
        }),
      });
      const loginData = await loginRes.json();
      if (!loginRes.ok) {
        throw new Error(loginData.error || 'Invalid username or Rooh Key.');
      }

      const cryptoKey = await deriveRoohEncryptionKey(
        loginRoohKey,
        loginData.user.encSalt
      );
      const keyFingerprint = await computeKeyFingerprint(
        loginRoohKey,
        loginData.user.encSalt
      );

      onAuthenticated({
        token: loginData.token,
        user: loginData.user,
        cryptoKey,
        keyFingerprint,
        googleAccessToken: null,
        googleEmail: null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign in failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (regRoohKey.length < 6) {
        throw new Error('Choose a Rooh Key of at least 6 characters.');
      }
      if (regRecoveryPin.length < 4) {
        throw new Error('Recovery PIN must be at least 4 characters.');
      }
      const authSalt = generateSaltHex(16);
      const encSalt = generateSaltHex(16);
      const authVerifier = await deriveRoohAuthVerifier(regRoohKey, authSalt);

      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: regUsername.trim(),
          email: regEmail.trim(),
          authSalt,
          encSalt,
          authVerifier,
          recoveryHint: regHint.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Registration failed.');
      }

      const cryptoKey = await deriveRoohEncryptionKey(regRoohKey, data.user.encSalt);
      const keyFingerprint = await computeKeyFingerprint(regRoohKey, data.user.encSalt);

      onAuthenticated({
        token: data.token,
        user: data.user,
        cryptoKey,
        keyFingerprint,
        googleAccessToken: null,
        googleEmail: null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Vault creation failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setError(null);
    if (googlePendingKey.length < 6) {
      setError('Enter your Rooh Key (min 6 characters) to unlock encryption alongside Google Drive.');
      return;
    }
    setBusy(true);
    try {
      const { user, accessToken } = await signInWithGoogleWorkspace();
      const email = user.email || '';
      const authSalt = generateSaltHex(16);
      const encSalt = generateSaltHex(16);
      const authVerifier = await deriveRoohAuthVerifier(googlePendingKey, authSalt);

      const res = await fetch('/api/auth/google-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          googleUid: user.uid,
          email,
          displayName: user.displayName || email.split('@')[0],
          authSalt,
          encSalt,
          authVerifier,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to bind Google session.');
      }

      const cryptoKey = await deriveRoohEncryptionKey(
        googlePendingKey,
        data.user.encSalt
      );
      const keyFingerprint = await computeKeyFingerprint(
        googlePendingKey,
        data.user.encSalt
      );

      onAuthenticated({
        token: data.token,
        user: data.user,
        cryptoKey,
        keyFingerprint,
        googleAccessToken: accessToken,
        googleEmail: email,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Google Drive authentication failed.');
    } finally {
      setBusy(false);
    }
  };

  // Recovery Step 1: Initiate challenge and generate encrypted email cipher block
  const handleInitiateRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfo(null);
    setBusy(true);
    try {
      if (recPin.trim().length < 4) {
        throw new Error('Enter a Recovery PIN (at least 4 characters) to seal the email cipher.');
      }
      const res = await fetch('/api/recovery/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: recIdentifier.trim() }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Could not initiate recovery.');
      }

      const cipherBlock = await createRecoveryCipherBlock(
        {
          username: data.username,
          recoveryToken: data.recoveryToken,
          hint: data.hint || 'No hint saved',
          issuedAt: new Date().toISOString(),
        },
        data.verificationCode,
        recPin.trim()
      );

      setRecChallengeId(data.challengeId);
      setRecTargetEmail(data.email);
      setRecGeneratedMailBlock(cipherBlock);
      setRecDemoCodeNotice(data.verificationCode);
      setRecGmailSent(false);
      setRecStep(2);
      setInfo(`Recovery challenge created for @${data.username}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Recovery initiation failed.');
    } finally {
      setBusy(false);
    }
  };

  const handleDispatchViaGmail = async () => {
    setError(null);
    setBusy(true);
    try {
      const { accessToken } = await signInWithGoogleWorkspace();
      await sendRecoveryCipherEmail(
        accessToken,
        recTargetEmail,
        recIdentifier.trim(),
        recGeneratedMailBlock
      );
      setRecGmailSent(true);
      setInfo(`Encrypted recovery cipher sent via Gmail to ${recTargetEmail}.`);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Could not dispatch via Gmail. You can copy the encrypted mail block directly below.'
      );
    } finally {
      setBusy(false);
    }
  };

  // Recovery Step 2: Verify 6-digit code
  const handleVerifyRecoveryCode = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const res = await fetch('/api/recovery/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: recChallengeId,
          verificationCode: recInputCode.trim(),
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Code verification failed.');
      }
      setRecVerifiedTicket(data.verifiedTicket);
      setRecStep(3);
      setInfo('Step 2 verified. Now decode the encrypted mail block locally in your browser.');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Code verification failed.');
    } finally {
      setBusy(false);
    }
  };

  // Recovery Step 3: Browser-Only Cipher Decoder (Pre-Login!)
  const handleDecodeMailInBrowser = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const decoded = await decodeRecoveryCipherBlockInBrowser(
        recCipherInput,
        recInputCode.trim(),
        recPin.trim()
      );
      setRecDecodedResult(decoded);
      setRecStep(4);
      setInfo('Encrypted recovery mail decoded locally in your browser.');
    } catch {
      setError('Decryption failed. Confirm the mail cipher block, 6-digit code, and recovery PIN match.');
    } finally {
      setBusy(false);
    }
  };

  // Recovery Step 4: Set new Rooh Key
  const handleResetRoohKey = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      if (!recDecodedResult) throw new Error('Decode the recovery mail first.');
      if (recNewRoohKey.length < 6) {
        throw new Error('New Rooh Key must be at least 6 characters.');
      }
      const newAuthSalt = generateSaltHex(16);
      const newEncSalt = generateSaltHex(16);
      const newAuthVerifier = await deriveRoohAuthVerifier(recNewRoohKey, newAuthSalt);

      const res = await fetch('/api/recovery/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: recChallengeId,
          verifiedTicket: recVerifiedTicket,
          recoveryToken: recDecodedResult.recoveryToken,
          newAuthSalt,
          newEncSalt,
          newAuthVerifier,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to update Rooh Key.');
      }

      const cryptoKey = await deriveRoohEncryptionKey(
        recNewRoohKey,
        data.user.encSalt
      );
      const keyFingerprint = await computeKeyFingerprint(
        recNewRoohKey,
        data.user.encSalt
      );

      onAuthenticated({
        token: data.token,
        user: data.user,
        cryptoKey,
        keyFingerprint,
        googleAccessToken: null,
        googleEmail: null,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Key reset failed.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#090B10] text-slate-100 flex flex-col">
      {/* Clean 3-zone header */}
      <header className="border-b border-white/10 px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between gap-8">
          <span className="text-lg font-bold tracking-tight font-display text-white whitespace-nowrap shrink-0">
            RoohCloud
          </span>
          <nav className="hidden md:flex items-center gap-6 text-sm text-slate-400">
            <button
              type="button"
              onClick={() => { setTab('login'); setError(null); }}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${tab === 'login' ? 'text-white font-medium' : ''}`}
            >
              Vault Login
            </button>
            <button
              type="button"
              onClick={() => { setTab('register'); setError(null); }}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${tab === 'register' ? 'text-white font-medium' : ''}`}
            >
              Create Account
            </button>
            <button
              type="button"
              onClick={() => { setTab('google'); setError(null); }}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${tab === 'google' ? 'text-white font-medium' : ''}`}
            >
              Google Drive Auth
            </button>
            <button
              type="button"
              onClick={() => { setTab('recovery'); setError(null); }}
              className={`hover:text-white transition-colors whitespace-nowrap shrink-0 ${tab === 'recovery' ? 'text-white font-medium' : ''}`}
            >
              Pre-Login Decoder
            </button>
          </nav>
          <button
            type="button"
            onClick={() => { setTab('recovery'); setError(null); }}
            className="px-4 py-2 text-xs font-medium bg-[#161B26] hover:bg-[#1E2534] border border-white/10 text-slate-200 rounded-lg transition-colors whitespace-nowrap shrink-0"
          >
            Recover Rooh Key
          </button>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-10 grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
        {/* Left: Auth & Pre-Login Recovery Decoder */}
        <section className="lg:col-span-6 bg-[#11151E] border border-white/10 rounded-xl p-6 sm:p-8 flex flex-col justify-between">
          <div>
            <div className="mb-6">
              <p className="text-xs font-medium text-blue-400 mb-2">
                Zero-Knowledge Encrypted Cloud Storage
              </p>
              <h1 className="text-2xl sm:text-3xl font-semibold font-display tracking-tight text-white [text-wrap:balance]">
                Unlock your vault locally with your Rooh Key
              </h1>
              <p className="mt-2 text-sm text-slate-400 leading-relaxed">
                All images, videos, PDFs, and ZIP archives are encrypted with AES-256-GCM in your browser before upload and decrypted strictly on your device.
              </p>
            </div>

            {/* Interactive Segmented Control */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-1 p-1 bg-[#090B10] border border-white/10 rounded-lg mb-6">
              <button
                type="button"
                onClick={() => { setTab('login'); setError(null); setInfo(null); }}
                className={`px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  tab === 'login' ? 'bg-[#1B2230] text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => { setTab('register'); setError(null); setInfo(null); }}
                className={`px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  tab === 'register' ? 'bg-[#1B2230] text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Create Vault
              </button>
              <button
                type="button"
                onClick={() => { setTab('google'); setError(null); setInfo(null); }}
                className={`px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  tab === 'google' ? 'bg-[#1B2230] text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Google Drive
              </button>
              <button
                type="button"
                onClick={() => { setTab('recovery'); setError(null); setInfo(null); }}
                className={`px-3 py-2 text-xs font-medium rounded-md transition-colors whitespace-nowrap ${
                  tab === 'recovery' ? 'bg-[#1B2230] text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                Recovery
              </button>
            </div>

            {error && (
              <div className="mb-5 p-3.5 rounded-lg bg-red-950/50 border border-red-500/30 text-red-200 text-xs flex items-start gap-2.5">
                <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            {info && (
              <div className="mb-5 p-3.5 rounded-lg bg-emerald-950/50 border border-emerald-500/30 text-emerald-200 text-xs flex items-start gap-2.5">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>{info}</span>
              </div>
            )}

            {/* TAB 1: USERNAME + ROOH KEY SIGN IN */}
            {tab === 'login' && (
              <form onSubmit={handleSignIn} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Username
                  </label>
                  <input
                    type="text"
                    required
                    value={loginUsername}
                    onChange={(e) => setLoginUsername(e.target.value)}
                    placeholder="e.g. abhay_vault"
                    className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label className="block text-xs font-medium text-slate-300">
                      Rooh Key (Never leaves browser)
                    </label>
                    <button
                      type="button"
                      onClick={() => {
                        setTab('recovery');
                        setRecStep(1);
                        setError(null);
                      }}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      Forgot Rooh Key?
                    </button>
                  </div>
                  <input
                    type="password"
                    required
                    value={loginRoohKey}
                    onChange={(e) => setLoginRoohKey(e.target.value)}
                    placeholder="Enter your secret Rooh Key"
                    className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <Unlock className="w-4 h-4" />
                  {busy ? 'Deriving Key & Unlocking...' : 'Unlock Vault'}
                </button>
              </form>
            )}

            {/* TAB 2: CREATE NEW VAULT */}
            {tab === 'register' && (
              <form onSubmit={handleRegister} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Username
                    </label>
                    <input
                      type="text"
                      required
                      value={regUsername}
                      onChange={(e) => setRegUsername(e.target.value)}
                      placeholder="abhay_vault"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Recovery Email
                    </label>
                    <input
                      type="email"
                      required
                      value={regEmail}
                      onChange={(e) => setRegEmail(e.target.value)}
                      placeholder="you@gmail.com"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Create Rooh Key (Min 6 characters)
                  </label>
                  <input
                    type="password"
                    required
                    minLength={6}
                    value={regRoohKey}
                    onChange={(e) => setRegRoohKey(e.target.value)}
                    placeholder="Strong passphrase for AES-256-GCM encryption"
                    className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Recovery PIN (For mail cipher)
                    </label>
                    <input
                      type="password"
                      required
                      minLength={4}
                      value={regRecoveryPin}
                      onChange={(e) => setRegRecoveryPin(e.target.value)}
                      placeholder="4+ chars"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1.5">
                      Optional Key Hint
                    </label>
                    <input
                      type="text"
                      value={regHint}
                      onChange={(e) => setRegHint(e.target.value)}
                      placeholder="Optional memory cue"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                    />
                  </div>
                </div>
                <button
                  type="submit"
                  disabled={busy}
                  className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                >
                  <UserPlus className="w-4 h-4" />
                  {busy ? 'Generating Cryptographic Salts...' : 'Create 10 GB Encrypted Vault'}
                </button>
              </form>
            )}

            {/* TAB 3: GOOGLE LOGIN AUTH + DIRECT GOOGLE DRIVE */}
            {tab === 'google' && (
              <div className="space-y-4">
                <p className="text-xs text-slate-400 leading-relaxed">
                  Connect your Google account to sync encrypted files directly with Google Drive and enable Gmail encrypted recovery delivery. Your Rooh Key remains strictly inside your browser.
                </p>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5">
                    Rooh Key for Browser Encryption
                  </label>
                  <input
                    type="password"
                    value={googlePendingKey}
                    onChange={(e) => setGooglePendingKey(e.target.value)}
                    placeholder="Enter your Rooh Key (min 6 chars)"
                    className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                  />
                </div>
                {/* Official Google Sign-In Button Styling */}
                <button
                  type="button"
                  onClick={handleGoogleSignIn}
                  disabled={busy}
                  className="w-full flex items-center justify-center gap-3 px-4 py-2.5 bg-white hover:bg-slate-100 disabled:opacity-60 text-[#1F1F1F] font-medium text-sm rounded-lg border border-slate-300 transition-colors cursor-pointer"
                >
                  <svg className="w-5 h-5 shrink-0" viewBox="0 0 48 48" aria-hidden="true">
                    <path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z" />
                    <path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z" />
                    <path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z" />
                    <path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z" />
                  </svg>
                  <span>{busy ? 'Connecting Google Drive...' : 'Sign in with Google'}</span>
                </button>
              </div>
            )}

            {/* TAB 4: MULTI-STEP RECOVERY & PRE-LOGIN BROWSER CIPHER DECODER */}
            {tab === 'recovery' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between text-xs text-slate-400 border-b border-white/10 pb-3">
                  <span>Multi-Step Recovery · Step {recStep} of 4</span>
                  <button
                    type="button"
                    onClick={() => {
                      setRecStep(1);
                      setRecDecodedResult(null);
                      setError(null);
                    }}
                    className="text-blue-400 hover:text-blue-300"
                  >
                    Restart Flow
                  </button>
                </div>

                {recStep === 1 && (
                  <form onSubmit={handleInitiateRecovery} className="space-y-3">
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Step 1: Enter your username or recovery email and your recovery PIN. We generate an encrypted recovery mail block that only your browser can decode before login.
                    </p>
                    <input
                      type="text"
                      required
                      value={recIdentifier}
                      onChange={(e) => setRecIdentifier(e.target.value)}
                      placeholder="Username or email"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500"
                    />
                    <input
                      type="password"
                      required
                      value={recPin}
                      onChange={(e) => setRecPin(e.target.value)}
                      placeholder="Recovery PIN"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 font-mono"
                    />
                    <button
                      type="submit"
                      disabled={busy}
                      className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      <Mail className="w-4 h-4" />
                      {busy ? 'Generating Recovery Mail...' : 'Generate Encrypted Recovery Mail'}
                    </button>
                  </form>
                )}

                {recStep === 2 && (
                  <form onSubmit={handleVerifyRecoveryCode} className="space-y-3">
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Step 2: Send or copy your encrypted recovery mail block, then enter the 6-digit verification code (<span className="font-mono text-white">{recDemoCodeNotice}</span>).
                    </p>
                    <div className="p-3 bg-[#090B10] border border-white/10 rounded-lg space-y-2">
                      <div className="flex items-center justify-between text-xs text-slate-400">
                        <span>Encrypted Recovery Mail Block</span>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => {
                              navigator.clipboard.writeText(recGeneratedMailBlock);
                              setCopiedCipher(true);
                              setTimeout(() => setCopiedCipher(false), 2000);
                            }}
                            className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
                          >
                            {copiedCipher ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                            {copiedCipher ? 'Copied' : 'Copy Block'}
                          </button>
                          <button
                            type="button"
                            onClick={handleDispatchViaGmail}
                            disabled={busy}
                            className="text-emerald-400 hover:text-emerald-300"
                          >
                            {recGmailSent ? 'Sent via Gmail' : 'Send via Gmail'}
                          </button>
                        </div>
                      </div>
                      <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all max-h-28 overflow-y-auto">
                        {recGeneratedMailBlock}
                      </pre>
                    </div>
                    <input
                      type="text"
                      required
                      value={recInputCode}
                      onChange={(e) => setRecInputCode(e.target.value)}
                      placeholder="Enter 6-digit verification code"
                      className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white font-mono focus:outline-none focus:border-blue-500"
                    />
                    <button
                      type="submit"
                      disabled={busy}
                      className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      Verify Code & Open Browser Decoder
                      <ArrowRight className="w-4 h-4" />
                    </button>
                  </form>
                )}

                {recStep === 3 && (
                  <form onSubmit={handleDecodeMailInBrowser} className="space-y-3">
                    <p className="text-xs text-slate-300 leading-relaxed">
                      Step 3 — Pre-Login Browser Cipher Decoder: Paste the encrypted message from your mail below. Only your browser decodes it locally using Web Crypto.
                    </p>
                    <textarea
                      rows={4}
                      required
                      value={recCipherInput}
                      onChange={(e) => setRecCipherInput(e.target.value)}
                      placeholder="-----BEGIN ROOHCLOUD RECOVERY CIPHER----- ..."
                      className="w-full px-3.5 py-2.5 text-xs bg-[#090B10] border border-white/10 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-blue-500"
                    />
                    <button
                      type="submit"
                      disabled={busy}
                      className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      <Lock className="w-4 h-4" />
                      Decode Mail Cipher Locally in Browser
                    </button>
                  </form>
                )}

                {recStep === 4 && recDecodedResult && (
                  <form onSubmit={handleResetRoohKey} className="space-y-3">
                    <div className="p-3 bg-[#090B10] border border-emerald-500/30 rounded-lg text-xs space-y-1">
                      <p className="text-emerald-400 font-medium">
                        Decoded Locally for @{recDecodedResult.username}
                      </p>
                      <p className="text-slate-400">
                        Saved Hint: <span className="text-slate-200">{recDecodedResult.hint}</span>
                      </p>
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-300 mb-1.5">
                        Set New Rooh Key (Min 6 characters)
                      </label>
                      <input
                        type="password"
                        required
                        minLength={6}
                        value={recNewRoohKey}
                        onChange={(e) => setRecNewRoohKey(e.target.value)}
                        placeholder="Enter new Rooh Key"
                        className="w-full px-3.5 py-2.5 text-sm bg-[#090B10] border border-white/10 rounded-lg text-white font-mono focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={busy}
                      className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors flex items-center justify-center gap-2"
                    >
                      <KeyRound className="w-4 h-4" />
                      Update Rooh Key & Enter Vault
                    </button>
                  </form>
                )}
              </div>
            )}
          </div>

          <div className="mt-8 pt-4 border-t border-white/10 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-500">
            <span>AES-256-GCM Web Crypto</span>
            <span aria-hidden="true">·</span>
            <span>PBKDF2 310k Rounds</span>
            <span aria-hidden="true">·</span>
            <span>Browser ZIP Extraction</span>
          </div>
        </section>

        {/* Right: Visual Showcase & Architecture Specs */}
        <aside className="lg:col-span-6 relative rounded-xl overflow-hidden border border-white/10 bg-[#11151E] min-h-[380px] flex flex-col justify-end">
          <img
            src="/src/assets/images/rooh_vault_obsidian_1795581632090.jpg"
            alt="Precision dark anodized aluminum and sapphire glass security vault mechanism"
            referrerPolicy="no-referrer"
            className="absolute inset-0 w-full h-full object-cover"
          />
          <div className="absolute inset-0 bg-gradient-to-t from-[#090B10] via-[#090B10]/70 to-transparent" />
          <div className="relative p-6 sm:p-8 space-y-4">
            <div className="flex items-center gap-2 text-xs font-medium text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
              <span>Local-First Zero-Knowledge Guarantees</span>
            </div>
            <h2 className="text-xl font-semibold font-display text-white">
              Multi-Cloud Storage with Device-Only Decryption
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-2 border-t border-white/15">
              <div>
                <p className="text-xs text-slate-400">Memory Vault</p>
                <p className="text-base font-mono font-semibold text-white tabular-nums mt-0.5">
                  10.00 GB
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400">TeraBox Cloud Pool</p>
                <p className="text-base font-mono font-semibold text-white tabular-nums mt-0.5">
                  1,024 GB
                </p>
              </div>
              <div>
                <p className="text-xs text-slate-400">Google Drive</p>
                <p className="text-base font-mono font-semibold text-white mt-0.5">
                  Direct Auth
                </p>
              </div>
            </div>
          </div>
        </aside>
      </main>
    </div>
  );
};
