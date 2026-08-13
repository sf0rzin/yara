import { useEffect, useRef, useState, type JSX } from "react";
import {
  createVault,
  errorMessage,
  estimateStrength,
  unlockVault,
  type Strength,
} from "../api";
import { Icon } from "../components/Icon";
import { yaraLogoUrl } from "../components/YaraLogo";

const STRENGTH_STEPS: Record<Strength, number> = { weak: 1, fair: 2, strong: 3 };
const STRENGTH_WORDS: Record<Strength, string> = {
  weak: "Too easy to guess",
  fair: "Reasonable",
  strong: "Strong",
};

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
  const [strength, setStrength] = useState<Strength | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  const isSetup = mode === "setup";

  useEffect(() => {
    if (!isSetup || password.length === 0) {
      setStrength(null);
      return;
    }

    let active = true;
    estimateStrength(password)
      .then((next) => active && setStrength(next))
      .catch(() => active && setStrength(null));
    return () => {
      active = false;
    };
  }, [isSetup, password]);

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
              <div className="unlock-strength" aria-live="polite">
                <span className="unlock-strength__track" aria-hidden="true">
                  {[1, 2, 3].map((step) => (
                    <span
                      key={step}
                      data-filled={
                        strength && STRENGTH_STEPS[strength] >= step
                          ? true
                          : undefined
                      }
                    />
                  ))}
                </span>
                <span>{strength ? STRENGTH_WORDS[strength] : "12 characters minimum"}</span>
              </div>

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
