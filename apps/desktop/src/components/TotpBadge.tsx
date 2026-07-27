import { useEffect, useState, type JSX } from "react";
import { totpCode, type TotpCode } from "../api";

const RADIUS = 7;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface TotpBadgeProps {
  itemId: string;
  /** Larger presentation for the detail panel. */
  prominent?: boolean;
}

/**
 * A live TOTP code with a countdown ring.
 *
 * Polls the backend every second rather than deriving the code in the frontend,
 * which keeps the TOTP secret on the Rust side of the IPC boundary. A six-digit
 * code is short-lived and single-use, so it is far less sensitive than the
 * seed that generates it.
 */
export function TotpBadge({ itemId, prominent }: TotpBadgeProps): JSX.Element | null {
  const [code, setCode] = useState<TotpCode | null>(null);

  useEffect(() => {
    let active = true;

    const tick = () => {
      totpCode(itemId)
        .then((next) => active && setCode(next))
        .catch(() => active && setCode(null));
    };

    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [itemId]);

  if (!code) return null;

  const fraction = code.secondsRemaining / code.period;
  // Under five seconds the code is about to roll; dim it so nobody starts
  // typing one that will be stale by the time they finish.
  const expiring = code.secondsRemaining <= 5;

  return (
    <div
      className="totp"
      data-prominent={prominent || undefined}
      data-expiring={expiring || undefined}
      title={`Expires in ${code.secondsRemaining}s`}
    >
      <span className="totp__code">
        {code.code.slice(0, 3)}
        <span className="totp__gap" />
        {code.code.slice(3)}
      </span>

      <svg className="totp__ring" width="18" height="18" viewBox="0 0 18 18">
        <circle cx="9" cy="9" r={RADIUS} className="totp__track" />
        <circle
          cx="9"
          cy="9"
          r={RADIUS}
          className="totp__progress"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={CIRCUMFERENCE * (1 - fraction)}
        />
      </svg>

      <span className="sr-only">
        One-time code {code.code.split("").join(" ")}, expires in{" "}
        {code.secondsRemaining} seconds
      </span>
    </div>
  );
}
