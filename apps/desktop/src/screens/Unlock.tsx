import { useEffect, useRef, useState, type JSX } from "react";
import { createVault, errorMessage, unlockVault } from "../api";
import { Icon } from "../components/Icon";
import { StrengthMeter, useStrength } from "../components/StrengthMeter";
import { yaraLogoUrl } from "../components/YaraLogo";

const LOGO_PIECES = [1, 2, 3, 4, 5, 6] as const;

interface UnlockProps {
  mode: "setup" | "unlock";
  vaultName?: string;
  hasOtherVaults?: boolean;
  onAuthenticated: () => void;
  onUseAnother?: () => void;
}

export function Unlock({
  mode,
  vaultName,
  hasOtherVaults = false,
  onAuthenticated,
  onUseAnother,
}: UnlockProps): JSX.Element {
  const isSetup = mode === "setup";
  const [name, setName] = useState(
    isSetup && !hasOtherVaults ? "Personal" : "",
  );
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  // Nothing to measure when unlocking: the password is either the vault's or it
  // is not, and rating one that already exists would be commentary.
  const strength = useStrength(isSetup ? password : "");

  useEffect(() => {
    const delay = window.matchMedia("(prefers-reduced-motion: reduce)").matches
      ? 0
      : 1660;
    const timer = window.setTimeout(
      () => (isSetup ? nameRef : passwordRef).current?.focus({ preventScroll: true }),
      delay,
    );
    return () => window.clearTimeout(timer);
  }, [isSetup, mode]);

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
      await (isSetup
        ? createVault(name.trim(), password, remember)
        : unlockVault(password, remember));
      onAuthenticated();
    } catch (caught) {
      setError(
        isSetup ? errorMessage(caught) : "That password did not open the vault.",
      );
      setBusy(false);
    }
  }

  const canSubmit =
    password.length > 0 &&
    (!isSetup || (name.trim().length > 0 && confirmation.length > 0)) &&
    !busy;

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

          <p className="unlock-context">
            {isSetup
              ? hasOtherVaults
                ? "Create another Vault"
                : "Create your Vault"
              : vaultName ?? "Personal"}
          </p>

          {isSetup && (
            <label className="unlock-field">
              <Icon name="folder" size={15} />
              <input
                ref={nameRef}
                type="text"
                value={name}
                placeholder="Vault name"
                aria-label="Vault name"
                autoComplete="off"
                maxLength={64}
                readOnly={busy}
                onChange={(event) => setName(event.target.value)}
              />
            </label>
          )}

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

          <div className="unlock-options">
            <label className="unlock-remember">
              <input
                type="checkbox"
                checked={remember}
                disabled={busy}
                onChange={(event) => setRemember(event.target.checked)}
              />
              <span className="unlock-remember__box" aria-hidden="true">
                {remember && <Icon name="check" size={11} />}
              </span>
              <span>Remember for 2 weeks</span>
            </label>

            {onUseAnother && (
              <button
                type="button"
                className="unlock-switch"
                disabled={busy}
                onClick={onUseAnother}
              >
                Use another Vault
              </button>
            )}
          </div>

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
