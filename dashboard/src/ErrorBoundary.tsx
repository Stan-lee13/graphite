// Round 29 (audit 2026-10-20, D5): there was no error boundary, so any
// exception thrown while rendering — a payload shape an older or newer Core
// sends, a browser quirk — unmounted the whole React tree and left the
// operator a blank page with no word about why. A boundary around each view
// keeps the shell (navigation, connection status) alive and says what broke;
// the outer one in main.tsx catches anything that escapes the shell itself.

import { Component, type ErrorInfo, type ReactNode } from "react";
import { ServerCrash } from "lucide-react";

interface Props {
  children: ReactNode;
  /** What the operator was looking at, for the message. */
  where?: string;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // The console has no telemetry by design; the browser console is where
    // an operator (or a bug report) finds the stack.
    console.error("Graphite console render failure", error, info.componentStack);
  }

  render(): ReactNode {
    const { error } = this.state;
    if (!error) return this.props.children;
    return (
      <div className="note fault" role="alert">
        <ServerCrash className="note-icon" aria-hidden="true" />
        <strong>{this.props.where ? `The ${this.props.where} view failed to draw` : "The console failed to draw"}</strong>
        <p>
          {error.message || String(error)}. Nothing was sent anywhere; the browser console has the details. Other
          views may still work.
        </p>
        <button type="button" className="btn primary" onClick={() => this.setState({ error: null })}>
          Try again
        </button>
      </div>
    );
  }
}
