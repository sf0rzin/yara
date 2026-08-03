import { useEffect, useState, type JSX } from "react";
import {
  createVault,
  errorMessage,
  estimateStrength,
  unlockVault,
  type Strength,
} from "../api";
import { Icon } from "../components/Icon";

const STRENGTH_STEPS: Record<Strength, number> = { weak: 1, fair: 2, strong: 3 };
const STRENGTH_WORDS: Record<Strength, string> = {
  weak: "Too easy to guess",
  fair: "Reasonable",
  strong: "Strong",
};

interface UnlockProps {
  mode: "setup" | "unlock";
  onOpen: () => void;
}

export function Unlock({ mode, onOpen }: UnlockProps): JSX.Element {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [strength, setStrength] = useState<Strength | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

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

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (isSetup) {
      if (strength === "weak") {
        setError("That password is too easy to guess. Make it longer.");
        return;
      }
      if (password !== confirmation) {
        setError("The two passwords do not match.");
        return;
      }
    }

    setBusy(true);
    try {
      await (isSetup ? createVault(password) : unlockVault(password));
      setPassword("");
      setConfirmation("");
      onOpen();
    } catch (caught) {
      setError(
        isSetup
          ? errorMessage(caught)
          : "That password did not open the vault.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="gate">
      <form className="gate__card" onSubmit={(event) => void submit(event)}>
        <span className="gate__mark" aria-hidden="true">
          <Icon name="lock" size={18} />
        </span>

        <div className="gate__intro">
          <h1 className="gate__title">
            {isSetup ? "Create your vault" : "yara"}
          </h1>
          <p className="gate__sub">
            {isSetup
              ? "Your master password encrypts everything. It is never stored and cannot be reset — if you lose it, the vault is gone."
              : "Enter your master password to continue."}
          </p>
        </div>

        <input
          className="input"
          type="password"
          value={password}
          autoFocus
          placeholder="Master password"
          aria-label="Master password"
          onChange={(event) => setPassword(event.target.value)}
        />

        {isSetup && (
          <>
            <div className="meter" aria-live="polite">
              <div className="meter__track">
                {[1, 2, 3].map((step) => (
                  <span
                    key={step}
                    className="meter__step"
                    data-filled={
                      strength && STRENGTH_STEPS[strength] >= step
                        ? true
                        : undefined
                    }
                  />
                ))}
              </div>
              <span className="meter__word">
                {strength ? STRENGTH_WORDS[strength] : "At least 12 characters"}
              </span>
            </div>

            <input
              className="input"
              type="password"
              value={confirmation}
              placeholder="Confirm master password"
              aria-label="Confirm master password"
              onChange={(event) => setConfirmation(event.target.value)}
            />
          </>
        )}

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <button
          type="submit"
          className="button button--primary button--block"
          disabled={busy || password.length === 0}
        >
          {busy ? "Working…" : isSetup ? "Create vault" : "Unlock"}
        </button>
      </form>
    </main>
  );
}
