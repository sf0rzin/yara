import { useEffect, useState, type JSX } from "react";
import { errorMessage, resolveApproval, type ApprovalPrompt } from "../api";
import { Icon } from "./Icon";

const WINDOW_MINUTES = 15;

interface ApprovalDialogProps {
  prompt: ApprovalPrompt;
  onSettled: () => void;
}

/**
 * The prompt that decides whether an agent gets a credential.
 *
 * Two deliberate choices here.
 *
 * Deny is the inverted button, not Allow. In an interface with no accent
 * colour, the inverted element is the one the eye lands on and the hand
 * reaches for — so it goes to the safe answer. Approving takes an extra
 * moment of attention, which is the point of asking at all.
 *
 * The reason is written by the requesting program, and is labelled as a
 * claim rather than presented as fact. It is rendered as text, never markup:
 * a request that could style itself could dress up as part of this dialog.
 */
export function ApprovalDialog({ prompt, onSettled }: ApprovalDialogProps): JSX.Element {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isReveal = prompt.mode === "reveal";

  async function answer(choice: "deny" | "once" | "window") {
    setBusy(true);
    setError(null);
    try {
      await resolveApproval(prompt.id, choice, choice === "window" ? WINDOW_MINUTES : undefined);
      onSettled();
    } catch (caught) {
      setError(errorMessage(caught));
      setBusy(false);
    }
  }

  // Escape denies. Dismissing a security prompt should never mean yes, and
  // there is no click-outside-to-close for the same reason.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") void answer("deny");
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prompt.id]);

  return (
    <div className="overlay overlay--front" role="presentation">
      <div className="dialog approval" role="alertdialog" aria-label="Credential request">
        <header className="approval__head">
          <span className="approval__mark" aria-hidden="true">
            <Icon name="sparkle" size={16} />
          </span>
          <div>
            <h2 className="dialog__title">
              {prompt.program} wants {isReveal ? "to see" : "to use"} a credential
            </h2>
            <p className="approval__pid">
              Process {prompt.pid}
              {prompt.programPath && ` · ${prompt.programPath}`}
            </p>
          </div>
        </header>

        <dl className="approval__facts">
          <div>
            <dt>Item</dt>
            <dd>{prompt.item}</dd>
          </div>
          <div>
            <dt>Field</dt>
            <dd>{prompt.field}</dd>
          </div>
          {prompt.command && (
            <div>
              <dt>Command</dt>
              <dd className="approval__command selectable">{prompt.command}</dd>
            </div>
          )}
          {prompt.envVar && (
            <div>
              <dt>Passed as</dt>
              <dd className="approval__command">${prompt.envVar}</dd>
            </div>
          )}
        </dl>

        <div className="approval__reason">
          <p className="approval__reason-label">It says this is for:</p>
          <p className="approval__reason-text selectable">{prompt.reason}</p>
        </div>

        <p className="approval__consequence">
          <Icon name={isReveal ? "alert" : "check"} size={14} />
          {isReveal
            ? "The value will be given to that program in full. Once it is out, yara cannot take it back."
            : "yara runs the command itself. The value goes into the command's environment, and the program only sees its output."}
        </p>

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <div className="approval__actions">
          <button
            type="button"
            className="button button--primary"
            disabled={busy}
            onClick={() => void answer("deny")}
            autoFocus
          >
            Deny
          </button>

          <button
            type="button"
            className="button button--quiet"
            disabled={busy}
            onClick={() => void answer("once")}
          >
            Allow once
          </button>

          {/* Revealing plaintext never earns a standing grant — the backend
              enforces this, so the option is simply not offered. */}
          {!isReveal && (
            <button
              type="button"
              className="button button--quiet"
              disabled={busy}
              onClick={() => void answer("window")}
            >
              Allow for {WINDOW_MINUTES} min
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
