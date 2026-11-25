/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useEffect, useState } from 'react';
import { AuthGate, VaultUserSession } from './components/AuthGate';
import { ErrorBoundary } from './components/ErrorBoundary';
import { ShareViewer } from './components/ShareViewer';
import { VaultDashboard } from './components/VaultDashboard';
import { initGoogleAuthListener, testFirestoreConnection } from './lib/firebase';

export default function App() {
  const [session, setSession] = useState<VaultUserSession | null>(null);

  useEffect(() => {
    testFirestoreConnection();
    const unsub = initGoogleAuthListener(
      () => {
        // Google Auth state tracked; access token kept strictly in memory
      },
      () => {
        // Cleared on Google sign-out
      }
    );
    return () => unsub();
  }, []);

  // Route /share/:shareId to the zero-knowledge browser decryptor
  const pathname = window.location.pathname;
  const shareMatch = pathname.match(/^\/share\/([a-zA-Z0-9_-]+)$/);
  if (shareMatch) {
    return (
      <ErrorBoundary>
        <ShareViewer shareId={shareMatch[1]} />
      </ErrorBoundary>
    );
  }

  return (
    <ErrorBoundary>
      {!session ? (
        <AuthGate onAuthenticated={(newSession) => setSession(newSession)} />
      ) : (
        <VaultDashboard
          session={session}
          onSessionUpdate={setSession}
          onLockVault={() => setSession(null)}
        />
      )}
    </ErrorBoundary>
  );
}
