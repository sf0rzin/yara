import { useEffect, useRef, useState } from "react";

/**
 * Locks the vault after a stretch of inactivity.
 *
 * The lock is real, not cosmetic: the callback drops the vault in the Rust
 * process, which zeroizes the key. Returns the milliseconds left so the UI can
 * show the countdown the design calls for.
 */
export function useAutoLock(timeoutMs: number, onLock: () => void): number {
  const [remaining, setRemaining] = useState(timeoutMs);

  // Held in a ref so a caller passing an inline arrow does not restart the
  // timer on every render.
  const onLockRef = useRef(onLock);
  onLockRef.current = onLock;

  const lastActivity = useRef(Date.now());
  const fired = useRef(false);

  useEffect(() => {
    const bump = () => {
      lastActivity.current = Date.now();
      fired.current = false;
    };

    const events = ["pointerdown", "keydown", "wheel", "pointermove"] as const;
    for (const event of events) {
      window.addEventListener(event, bump, { passive: true });
    }

    const timer = setInterval(() => {
      const left = timeoutMs - (Date.now() - lastActivity.current);
      setRemaining(Math.max(0, left));

      if (left <= 0 && !fired.current) {
        fired.current = true;
        onLockRef.current();
      }
    }, 1000);

    return () => {
      for (const event of events) {
        window.removeEventListener(event, bump);
      }
      clearInterval(timer);
    };
  }, [timeoutMs]);

  return remaining;
}

/** "8 min" / "45s", for the sidebar countdown. */
export function formatCountdown(ms: number): string {
  const seconds = Math.ceil(ms / 1000);
  if (seconds >= 60) {
    return `${Math.ceil(seconds / 60)} min`;
  }
  return `${seconds}s`;
}
