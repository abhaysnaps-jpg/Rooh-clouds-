import React from 'react';
import { ShieldAlert, RotateCcw } from 'lucide-react';

interface State {
  hasError: boolean;
  message: string;
}

export class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  State
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }

  static getDerivedStateFromError(error: Error): State {
    return {
      hasError: true,
      message: error?.message || 'An unexpected error occurred.',
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('RoohCloud ErrorBoundary:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#090B10] text-slate-100 flex items-center justify-center p-6">
          <div className="max-w-lg w-full bg-[#11151E] border border-white/10 rounded-xl p-8 space-y-5">
            <div className="flex items-center gap-3 text-red-400">
              <ShieldAlert className="w-6 h-6 shrink-0" />
              <h2 className="text-lg font-semibold font-display">
                Vault Session Interrupted
              </h2>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed break-words">
              {this.state.message}
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors whitespace-nowrap shrink-0"
            >
              <RotateCcw className="w-4 h-4" />
              Reload Vault
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
