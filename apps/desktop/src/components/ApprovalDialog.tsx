import { useCallback, useEffect, useState, type JSX } from "react";
import {
  errorMessage,
  resolveApproval,
  type ApprovalChoice,
  type ApprovalPrompt,
} from "../api";
import { isTopmostDialog, useModalDialog } from "../lib/useModalDialog";
import { Icon } from "./Icon";

const WINDOW_MINUTES = 15;

interface ApprovalDialogProps {
  prompt: ApprovalPrompt;
  queueLength?: number;
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
export function ApprovalDialog({
  prompt,
  queueLength = 1,
  onSettled,
}: ApprovalDialogProps): JSX.Element {
  const [busyChoice, setBusyChoice] = useState<ApprovalChoice | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [moreOpen, setMoreOpen] = useState(false);
  // This dialog is pinned above every other overlay by `overlay--front`'s
  // z-index, so it needs to win the Tab-trap even if something else — the
  // command palette, `NewItemDialog` — mounts after it while it's still up.
  const dialogRef = useModalDialog<HTMLDivElement>({ front: true });

  const isReveal = prompt.mode === "reveal";

  // True for a reveal, and also for a `run` whose command would print the
  // value — a shell, or an interpreter handed a program. The two differ in
  // wording and not in consequence, so the dialog treats them the same.
  const discloses = prompt.discloses;
  const modeLabel = isReveal
    ? "REVEAL"
    : discloses
      ? "RUN · DISCLOSES SECRET"
      : "RUN";
  const consequence = isReveal
    ? `${prompt.program} receives the ${prompt.field} in full. It can save or forward it, and yara cannot revoke it afterward.`
    : discloses
      ? `This command can print the ${prompt.field}. Approving it discloses the credential as fully as Reveal would.`
      : `The launched process receives the ${prompt.field}${prompt.envVar ? ` in $${prompt.envVar}` : ""}. The requesting agent receives only the command output.`;

  const answer = useCallback(
    async (choice: ApprovalChoice) => {
      setBusyChoice(choice);
      setError(null);
      try {
        await resolveApproval(prompt.id, choice, choice === "window" ? WINDOW_MINUTES : undefined);
        onSettled();
      } catch (caught) {
        setError(errorMessage(caught));
        setBusyChoice(null);
      }
    },
    [onSettled, prompt.id],
  );

  // Escape denies. Dismissing a security prompt should never mean yes, and
  // there is no click-outside-to-close for the same reason.
  //
  // The dependency list used to name `prompt.id` and carry a suppression for
  // the rule that says so, which nothing enforced. It happened to be harmless
  // because this dialog is keyed on the prompt id and so remounts per request
  // — but a listener that denies on Escape closing over a stale `answer` is
  // exactly the class of bug the rule exists to catch, and it was one edit away
  // the whole time.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      // `front: true` already keeps this dialog topmost whenever it is
      // mounted, so this rarely changes anything today — it is here so this
      // stays true if that ever stops being the only dialog with the flag.
      if (event.key === "Escape" && isTopmostDialog(dialogRef.current)) {
        void answer("deny");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // `dialogRef` is a ref, so it never changes identity and never makes this
    // effect re-run — it is only in this list because eslint cannot see
    // through `useModalDialog` to know that the way `useRef` can.
  }, [answer, dialogRef]);

  return (
    <div className="overlay overlay--front" role="presentation">
      <div
        className="dialog approval"
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-label="Credential request"
      >
        <header className="approval__head">
          <span className="approval__mark" aria-hidden="true">
            <Icon name="sparkle" size={16} />
          </span>
          <div className="approval__heading">
            <div className="approval__eyebrow">
              <span>{modeLabel}</span>
              {queueLength > 1 && <span>Request 1 of {queueLength}</span>}
            </div>
            <h2 className="dialog__title">
              {prompt.program} wants {discloses ? "to see" : "to use"} {prompt.item}
            </h2>
            <p className="approval__identity selectable">
              {prompt.programPath ?? "Executable path unavailable"} · process {prompt.pid}
            </p>
          </div>
        </header>

        <dl className="approval__facts">
          <div>
            <dt>Credential</dt>
            <dd>{prompt.item} · {prompt.field}</dd>
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
          <p className="approval__reason-label">Reason claimed by {prompt.program}</p>
          <p className="approval__reason-text selectable">“{prompt.reason}”</p>
        </div>

        <p className="approval__consequence">
          <Icon name={discloses ? "alert" : "security"} size={14} />
          <span>{consequence}</span>
        </p>

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        {!discloses && moreOpen && (
          <div className="approval__more">
            <div>
              <p className="approval__more-title">Allow this exact request for {WINDOW_MINUTES} minutes</p>
              <p className="approval__more-copy">
                Reuses are limited to this program, credential and command. Locking the vault cancels the grant.
              </p>
            </div>
            <button
              type="button"
              className="button button--outline"
              disabled={busyChoice !== null}
              onClick={() => void answer("window")}
            >
              {busyChoice === "window" ? "Allowing…" : `Allow for ${WINDOW_MINUTES} min`}
            </button>
          </div>
        )}

        <div className="approval__actions">
          <button
            type="button"
            className="button button--primary"
            disabled={busyChoice !== null}
            onClick={() => void answer("deny")}
            autoFocus
          >
            {busyChoice === "deny" ? "Denying…" : "Deny"}
          </button>

          <button
            type="button"
            className="button button--outline"
            disabled={busyChoice !== null}
            onClick={() => void answer("once")}
          >
            {busyChoice === "once" ? "Allowing…" : "Allow once"}
          </button>

          {!discloses && (
            <button
              type="button"
              className="button button--quiet"
              disabled={busyChoice !== null}
              aria-expanded={moreOpen}
              onClick={() => setMoreOpen((open) => !open)}
            >
              More options…
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
