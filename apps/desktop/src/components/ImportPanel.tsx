import { useEffect, useState, type JSX } from "react";
import {
  errorMessage,
  previewImport,
  runImport,
  type ImportPreview,
} from "../api";
import { useModalDialog } from "../lib/useModalDialog";
import { Icon } from "./Icon";

/**
 * Bringing two-factor codes in from another authenticator.
 *
 * Two steps, never one. The file is plaintext seeds, and the user is entitled
 * to see what is about to enter the vault — and what will be skipped, and why
 * — before it happens rather than after.
 *
 * The warning about the file afterwards is not decoration. An export like this
 * is as sensitive as every account in it, it is sitting in Downloads, and
 * unlike a password a leaked seed cannot be rotated without re-enrolling the
 * account it belongs to.
 *
 * A dialog, because importing is something you do once and reading codes is
 * something you do daily. This used to sit permanently above the list on the
 * Authenticator screen, so every visit to read a six-digit number began with a
 * paragraph about a file the user imported months ago.
 */
export function ImportDialog({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: () => void;
}): JSX.Element {
  const dialogRef = useModalDialog<HTMLDivElement>();

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="overlay" onMouseDown={onClose}>
      <div
        className="dialog"
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Import codes"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="dialog__head">
          <h2 className="dialog__title">Import codes</h2>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
            <Icon name="close" size={14} />
          </button>
        </header>

        <ImportPanel onImported={onImported} />
      </div>
    </div>
  );
}

function ImportPanel({ onImported }: { onImported: () => void }): JSX.Element {
  const [path, setPath] = useState<string | null>(null);
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [added, setAdded] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const choose = async () => {
    setError(null);
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const chosen = await open({
        multiple: false,
        filters: [{ name: "Authenticator export", extensions: ["txt", "json"] }],
      });
      if (typeof chosen !== "string") return;

      setBusy(true);
      setPath(chosen);
      setAdded(null);
      setPreview(await previewImport(chosen));
    } catch (caught) {
      setError(errorMessage(caught));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!path) return;
    setBusy(true);
    setError(null);
    try {
      setAdded(await runImport(path));
      setPreview(null);
      onImported();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="import">
      {error && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {error}
        </p>
      )}

      {added !== null ? (
        <>
          <p className="notice notice--loud">
            <Icon name="check" size={13} />
            {added === 0
              ? "Nothing new to add — every code was already here."
              : `Imported ${added} ${added === 1 ? "code" : "codes"}.`}
          </p>
          <p className="input-hint">
            The export you just read is plaintext seeds, one per account. Delete
            it. A leaked seed cannot be changed the way a password can — the
            account has to be enrolled again from scratch.
          </p>
          <button type="button" className="button button--quiet" onClick={() => setAdded(null)}>
            Import another
          </button>
        </>
      ) : preview ? (
        <Confirm preview={preview} busy={busy} onConfirm={() => void confirm()} onCancel={() => setPreview(null)} />
      ) : (
        <>
          <p className="sync__lead">
            Import two-factor codes from a Proton Authenticator plaintext
            backup. Nothing is written until you have seen what it contains.
          </p>
          <button type="button" className="button button--outline" disabled={busy} onClick={() => void choose()}>
            <Icon name="download" size={14} />
            {busy ? "Reading…" : "Choose an export file"}
          </button>
        </>
      )}
    </section>
  );
}

function Confirm({
  preview,
  busy,
  onConfirm,
  onCancel,
}: {
  preview: ImportPreview;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  const nothingToDo = preview.ready.length === 0;

  return (
    <>
      <p className="sync__lead">
        {preview.ready.length} to add
        {preview.duplicates.length > 0 && `, ${preview.duplicates.length} already here`}
        {preview.skipped.length > 0 && `, ${preview.skipped.length} that cannot be read`}.
      </p>

      {preview.ready.length > 0 && (
        <Group label="Will be added" names={preview.ready} />
      )}

      {/* Matched by seed, not by name: the same code saved under two different
          labels is still the same code, and two items generating identical
          digits turns the authenticator screen into a guessing game. */}
      {preview.duplicates.length > 0 && (
        <Group label="Already in your vault" names={preview.duplicates} />
      )}

      {preview.skipped.length > 0 && (
        <section>
          <p className="section-label">Cannot be read</p>
          <ul className="import__list">
            {preview.skipped.map((problem) => (
              <li key={problem.name}>
                <span className="import__name">{problem.name}</span>
                <span className="import__reason">{problem.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <div className="sync__actions">
        <button
          type="button"
          className="button button--outline"
          disabled={busy || nothingToDo}
          onClick={onConfirm}
        >
          {busy
            ? "Importing…"
            : nothingToDo
              ? "Nothing to import"
              : `Import ${preview.ready.length}`}
        </button>
        <button type="button" className="button button--quiet" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </>
  );
}

function Group({ label, names }: { label: string; names: string[] }): JSX.Element {
  return (
    <section>
      <p className="section-label">{label}</p>
      <ul className="import__list">
        {names.map((name, index) => (
          <li key={`${name}-${index}`}>
            <span className="import__name">{name}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
