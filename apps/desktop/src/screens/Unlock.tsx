import { useEffect, useRef, useState, type JSX } from "react";
import { createVault, errorMessage, unlockVault } from "../api";
import { Icon } from "../components/Icon";
import { StrengthMeter, useStrength } from "../components/StrengthMeter";
import { yaraLogoUrl } from "../components/YaraLogo";

const LOGO_PIECES = [1, 2, 3, 4, 5, 6] as const;

interface UnlockProps {
  mode: "setup" | "unlock";
  onAuthenticated: () => void;
}

export function Unlock({
  mode,
  onAuthenticated,
}: UnlockProps): JSX.Element {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  const isSetup = mode === "setup";
  // Nothing to measure when unlocking: the password is either the vault's or it
  // is not, and rating one that already exists would be commentary.
  const strength = useStrength(isSetup ? password : "");

  useEffect(() => {
    const delay = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? 0
      : 1660;
    const timer = window.setTimeout(
      () => passwordRef.current?.focus({ preventScroll: true }),
      delay,
    );
    return () => window.clearTimeout(timer);
  }, [mode]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setError(null);

    if (isSetup) {
      if (strength === "weak") {
        setError("Choose a longer master password.");
        return;
      }
      if (password !== confirmation) {
        setError("The passwords do not match.");
        return;
      }
    }

    setBusy(true);
    try {
      await (isSetup ? createVault(password) : unlockVault(password));
      onAuthenticated();
    } catch (caught) {
      setError(isSetup ? errorMessage(caught) : "That password did not open the vault.");
      setBusy(false);
    }
  }

  const canSubmit =
    password.length > 0 && (!isSetup || confirmation.length > 0) && !busy;

  return (
    <main
      className="unlock-layer"
      data-mode={mode}
      role="dialog"
      aria-modal="true"
      aria-labelledby="unlock-title"
      aria-busy={busy || undefined}
    >
      <div className="unlock-stage">
        <div className="unlock-brand" aria-hidden="true">
          <span className="unlock-mark">
            {LOGO_PIECES.map((piece) => (
              <span
                className={`unlock-piece unlock-piece--${piece}`}
                key={piece}
              >
                <img src={yaraLogoUrl} alt="" />
              </span>
            ))}
          </span>
          <span className="unlock-wordmark">yara</span>
        </div>

        <form
          className="unlock-form"
          data-has-value={password.length > 0 || undefined}
          onSubmit={(event) => void submit(event)}
        >
          <h1 className="sr-only" id="unlock-title">
            {isSetup ? "Create your Yara vault" : "Unlock Yara"}
          </h1>

          <label className="unlock-field">
            <Icon name="lock" size={15} />
            <input
              ref={passwordRef}
              type="password"
              value={password}
              placeholder="Master password"
              aria-label="Master password"
              autoComplete={isSetup ? "new-password" : "current-password"}
              readOnly={busy}
              onChange={(event) => setPassword(event.target.value)}
            />
            {!isSetup && (
              <button
                className="unlock-submit"
                type="submit"
                aria-label="Unlock vault"
                disabled={!canSubmit}
              >
                <Icon name="arrowRight" size={15} />
              </button>
            )}
          </label>

          {isSetup && (
            <>
              <StrengthMeter strength={strength} />

              <label className="unlock-field">
                <Icon name="lock" size={15} />
                <input
                  type="password"
                  value={confirmation}
                  placeholder="Confirm master password"
                  aria-label="Confirm master password"
                  autoComplete="new-password"
                  readOnly={busy}
                  onChange={(event) => setConfirmation(event.target.value)}
                />
                <button
                  className="unlock-submit"
                  type="submit"
                  aria-label="Create vault"
                  disabled={!canSubmit}
                >
                  <Icon name="arrowRight" size={15} />
                </button>
              </label>
            </>
          )}

          {error && (
            <p className="unlock-error" role="alert">
              {error}
            </p>
          )}
        </form>
      </div>
    </main>
  );
}
