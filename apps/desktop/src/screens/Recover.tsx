import { useState, type JSX } from "react";
import { errorMessage, recoverVault } from "../api";

interface RecoverProps {
  /** The vault is back at its usual place; ask for the password as normal. */
  onRecovered: () => void;
}

/**
 * The third startup state, which the app used to mistake for the first.
 *
 * Saving a vault writes a new file, copies the old one aside, and renames the
 * new one into place. A machine that dies between the last two steps comes back
 * with nothing at the vault's path and a complete copy beside it. That looked
 * exactly like a fresh install, so the app offered first-run setup — and the
 * empty vault created there deleted the copy on its own first save. The whole
 * screen exists so that never happens again, which is why the only thing it
 * offers is putting the copy back.
 *
 * It does not ask for the master password. Recovery moves a file; it does not
 * open one, and asking for the password here would suggest that a wrong one
 * could cost you the recovery.
 */
export function Recover({ onRecovered }: RecoverProps): JSX.Element {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function putBack() {
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      await recoverVault();
      onRecovered();
    } catch (caught) {
      setError(errorMessage(caught));
      setBusy(false);
    }
  }

  return (
    <main
      className="unlock-layer"
      data-mode="recover"
      role="dialog"
      aria-modal="true"
      aria-labelledby="recover-title"
      aria-busy={busy || undefined}
    >
      <section className="recover">
        <h1 className="recover__title" id="recover-title">
          Your vault file is missing, and a copy of it is here
        </h1>

        <p className="recover__body">
          Yara saves by writing a new vault beside the old one and swapping them
          over. This machine stopped between those two steps: there is nothing
          at the place the vault normally lives, and a complete copy is sitting
          next to it.
        </p>

        <p className="recover__body">
          Putting it back copies that file to where the vault belongs and leaves
          the copy where it is, so this can be tried again if it goes wrong.
          Then you unlock with the same master password as before. Whatever was
          being saved at the moment it stopped may not be in it.
        </p>

        <p className="recover__body">
          You are not being offered a new vault here, and will not be. Creating
          one at this path would write over the only copy of your passwords that
          is left.
        </p>

        {error && (
          <p className="recover__error" role="alert">
            {error}
          </p>
        )}

        <button
          type="button"
          className="button button--primary"
          disabled={busy}
          onClick={() => void putBack()}
        >
          {busy ? "Putting it back…" : "Put the vault back"}
        </button>
      </section>
    </main>
  );
}
