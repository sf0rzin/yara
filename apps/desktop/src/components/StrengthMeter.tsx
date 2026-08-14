import { useEffect, useState, type JSX } from "react";
import { estimateStrength, type Strength } from "../api";

const STRENGTH_STEPS: Record<Strength, number> = { weak: 1, fair: 2, strong: 3 };
const STRENGTH_WORDS: Record<Strength, string> = {
  weak: "Too easy to guess",
  fair: "Reasonable",
  strong: "Strong",
};

/**
 * How good a master password is, according to the vault.
 *
 * Asked of the backend rather than judged here, so the meter shown while
 * choosing a password and the audit that later calls it weak cannot disagree.
 * Null while there is nothing to judge, or when the estimate did not come back
 * — an unanswered call must not read as "weak".
 */
export function useStrength(password: string): Strength | null {
  const [strength, setStrength] = useState<Strength | null>(null);

  useEffect(() => {
    if (password.length === 0) {
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
  }, [password]);

  return strength;
}

/**
 * The meter itself.
 *
 * Lifted out of the unlock screen when Settings grew a way to change the master
 * password. Two copies of this would have been two opinions about what "fair"
 * looks like and what to say when nothing has been typed yet, on the two
 * screens where the same decision is being made.
 */
export function StrengthMeter({ strength }: { strength: Strength | null }): JSX.Element {
  return (
    <div className="unlock-strength" aria-live="polite">
      <span className="unlock-strength__track" aria-hidden="true">
        {[1, 2, 3].map((step) => (
          <span
            key={step}
            data-filled={strength && STRENGTH_STEPS[strength] >= step ? true : undefined}
          />
        ))}
      </span>
      <span>{strength ? STRENGTH_WORDS[strength] : "12 characters minimum"}</span>
    </div>
  );
}
