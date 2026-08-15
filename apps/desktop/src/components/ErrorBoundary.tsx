import { Component, type ReactNode } from "react";
import { errorMessage, lockVault } from "../api";

interface ErrorBoundaryProps {
  children: ReactNode;
}

/**
 * Whether the vault got locked once an error was caught.
 *
 * `null` while the lock call is still in flight — the fallback is on screen
 * before that promise settles, and it must not claim a state it has not
 * reached yet.
 */
type LockOutcome = "locked" | "lock-failed" | null;

interface ErrorBoundaryState {
  error: Error | null;
  lockOutcome: LockOutcome;
}

/**
 * Catches whatever escapes render, locks the vault, and says so.
 *
 * `useAutoLock` is a hook. An error thrown during render with nothing above
 * it to catch it unmounts the whole tree in React 19, which takes the idle
 * timer down with whatever was using it — the vault key is left in memory
 * with nothing counting against it and no interface left standing to notice.
 * `lib.rs` already carries the same reasoning for a reload, on
 * `on_page_load`: a reload must not leave the vault unlocked behind a screen
 * that says it is locked. A crash is the same hazard through a different
 * door, and now it is met the same way.
 *
 * A class component, which nothing else in this codebase is.
 * `getDerivedStateFromError` and `componentDidCatch` have no hook form, so
 * this is the one place a class is the correct tool rather than a stylistic
 * throwback.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null, lockOutcome: null };

  static getDerivedStateFromError(thrown: unknown): Partial<ErrorBoundaryState> {
    // Must stay pure — React is free to call this more than once for the same
    // error under Strict Mode. The lock itself, which is not pure, happens in
    // componentDidCatch below instead.
    return { error: thrown instanceof Error ? thrown : new Error(errorMessage(thrown)) };
  }

  componentDidCatch(): void {
    // React already logs the caught error to the console on its own. This
    // only needs to react to it, not report it a second time.
    void this.lockAfterCrash();
  }

  private async lockAfterCrash(): Promise<void> {
    try {
      await lockVault();
      this.setState({ lockOutcome: "locked" });
    } catch {
      // Already in the failure path. Throwing from here would replace the
      // message the user was about to be shown with a second, less useful
      // one, so the rejection becomes state instead of a rethrow.
      this.setState({ lockOutcome: "lock-failed" });
    }
  }

  render(): ReactNode {
    const { error, lockOutcome } = this.state;
    if (!error) {
      return this.props.children;
    }

    return (
      <main className="unlock-layer" data-mode="crash">
        <section className="crash" role="alert">
          <h1 className="crash__title">Yara hit an error and stopped</h1>
          <p className="crash__body">{lockStatusMessage(lockOutcome)}</p>
          <p className="crash__detail">{error.message}</p>
          <button
            type="button"
            className="button button--primary"
            // Safe to reload into: `on_page_load` locks on every reload,
            // which is exactly the state this screen is already reporting.
            onClick={() => window.location.reload()}
          >
            Reload
          </button>
        </section>
      </main>
    );
  }
}

function lockStatusMessage(outcome: LockOutcome): string {
  switch (outcome) {
    case "locked":
      return "The vault has been locked.";
    case "lock-failed":
      return "The vault could not be locked. Close the app now, rather than continue with it open.";
    case null:
      return "Locking the vault…";
  }
}
