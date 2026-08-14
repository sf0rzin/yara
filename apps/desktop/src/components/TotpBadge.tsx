import { useEffect, useState, type JSX } from "react";
import { totpCode, type TotpCode } from "../api";

const RADIUS = 7;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface BadgeShape {
  itemId: string;
  /** Larger presentation for the detail panel. */
  prominent?: boolean;
  /** Generic lists only need to say that 2FA exists, without polling a secret. */
  showCode?: boolean;
}

/*
 * A copyable badge has to be told where its outcome goes.
 *
 * Expressed as a union rather than an optional callback on purpose: a copy can
 * fail to be kept out of Clipboard History, or fail to be wiped afterwards,
 * and this control is too small to say either. Making `onCopy` mandatory the
 * moment `copyable` is set means the next person to place one cannot repeat
 * the version of this component that copied a live credential and threw the
 * answer away.
 */
type TotpBadgeProps = BadgeShape &
  (
    | { copyable: true; onCopy: (code: string) => void | Promise<void> }
    | { copyable?: false; onCopy?: never }
  );

/**
 * A live TOTP code with a countdown ring.
 *
 * Polls the backend every second rather than deriving the code in the frontend,
 * which keeps the TOTP secret on the Rust side of the IPC boundary. A six-digit
 * code is short-lived and single-use, so it is far less sensitive than the
 * seed that generates it.
 */
// Taken whole rather than destructured: narrowing on `props.copyable` is what
// tells the compiler `props.onCopy` is there, and pulling the two apart loses
// the link between them.
export function TotpBadge(props: TotpBadgeProps): JSX.Element | null {
  const { itemId, prominent, showCode = true } = props;
  const [code, setCode] = useState<TotpCode | null>(null);

  useEffect(() => {
    if (!showCode) {
      setCode(null);
      return;
    }

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
  }, [itemId, showCode]);

  if (!showCode) {
    return (
      <div className="totp totp--presence" aria-label="Two-factor authentication enabled">
        <span className="totp__presence-label" aria-hidden="true">2FA</span>
        <svg aria-hidden="true" className="totp__ring" width="16" height="16" viewBox="0 0 18 18">
          <circle cx="9" cy="9" r={RADIUS} className="totp__track" />
          <circle cx="9" cy="9" r={RADIUS} className="totp__progress" />
        </svg>
      </div>
    );
  }

  if (!code) return null;

  const fraction = code.secondsRemaining / code.period;
  // Under five seconds the code is about to roll; dim it so nobody starts
  // typing one that will be stale by the time they finish.
  const expiring = code.secondsRemaining <= 5;

  const content = (
    <>
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
    </>
  );

  if (props.copyable) {
    return (
      <button
        type="button"
        className="totp totp--copyable"
        data-prominent={prominent || undefined}
        data-expiring={expiring || undefined}
        aria-label={`Copy one-time code, ${code.secondsRemaining} seconds remaining`}
        // Through the backend, like every other copy of a secret: a one-time
        // code pasted from Win+V an hour later is useless, but it is still a
        // credential and it has no business being in the history at all.
        //
        // The badge is too small to hold a sentence, so whoever placed it says
        // what happened. It used to discard the outcome instead, which hid the
        // one that matters: a wipe that failed leaves the code on the clipboard
        // long after the thirty seconds it is good for.
        onClick={() => void props.onCopy(code.code)}
      >
        {content}
      </button>
    );
  }

  return (
    <div
      className="totp"
      data-prominent={prominent || undefined}
      data-expiring={expiring || undefined}
      title={`Expires in ${code.secondsRemaining}s`}
    >
      {content}
    </div>
  );
}
