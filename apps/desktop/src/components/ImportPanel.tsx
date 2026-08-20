import { useEffect, useState, type JSX } from "react";
import {
  errorMessage,
  previewImport,
  runImport,
  type ImportCandidate,
  type ImportPreview,
} from "../api";
import { isTopmostDialog, useModalDialog } from "../lib/useModalDialog";
import { Icon } from "./Icon";

/**
 * Bringing credentials or two-factor codes in from another application.
 *
 * Two steps, never one. The export contains plaintext secrets, and the user is
 * entitled to see what is about to enter the vault — and what will be skipped,
 * and why — before it happens rather than after.
 *
 * The warning about the file afterwards is not decoration. An export like this
 * is as sensitive as every account in it, it is sitting in Downloads, and it
 * remains plaintext after the encrypted copies have entered the vault.
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
      // An approval prompt can be open on top of this one — see isTopmostDialog.
      if (event.key === "Escape" && isTopmostDialog(dialogRef.current)) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // `dialogRef` is a ref, so it never changes identity and never makes this
    // effect re-run — it is only in this list because eslint cannot see
    // through `useModalDialog` to know that the way `useRef` can.
  }, [onClose, dialogRef]);

  return (
    <div className="overlay" onMouseDown={onClose}>
      <div
        className="dialog dialog--import"
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Import items"
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="dialog__head">
          <h2 className="dialog__title">Import from another app</h2>
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
  const [completedSource, setCompletedSource] = useState<ImportPreview["source"] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const choose = async () => {
    setError(null);
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const chosen = await open({
        multiple: false,
        filters: [
          {
            name: "Password manager or authenticator export",
            extensions: ["csv", "txt", "json"],
          },
        ],
      });
      if (typeof chosen !== "string") return;

      setBusy(true);
      setPath(chosen);
      setAdded(null);
      setCompletedSource(null);
      setPreview(await previewImport(chosen));
    } catch (caught) {
      setError(errorMessage(caught));
      setPreview(null);
    } finally {
      setBusy(false);
    }
  };

  const updateCandidate = (
    index: number,
    change: Partial<Pick<ImportCandidate, "name" | "folder">>,
  ) => {
    setPreview((current) => current && {
      ...current,
      ready: current.ready.map((candidate) =>
        candidate.index === index ? { ...candidate, ...change } : candidate,
      ),
    });
  };

  const confirm = async () => {
    if (!path || !preview) return;
    setBusy(true);
    setError(null);
    try {
      setCompletedSource(preview.source);
      setAdded(await runImport(path, preview.fileToken, preview.ready));
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
              ? "Nothing new to add — every item was already here."
              : `Imported ${added} ${added === 1 ? "item" : "items"}.`}
          </p>
          <p className="input-hint">
            {completedSource === "protonAuthenticator"
              ? "That export still contains plaintext two-factor seeds. Delete it after checking the imported codes; a leaked seed requires enrolling the account again."
              : "That export still contains plaintext passwords, card details and notes. Delete it after checking the imported items; importing it does not protect the original file."}
          </p>
          <button type="button" className="button button--quiet" onClick={() => setAdded(null)}>
            Import another
          </button>
        </>
      ) : preview ? (
        <Confirm
          preview={preview}
          busy={busy}
          onCandidateChange={updateCandidate}
          onConfirm={() => void confirm()}
          onCancel={() => setPreview(null)}
        />
      ) : (
        <>
          <p className="sync__lead">
            Import passwords from a Proton Pass CSV or two-factor codes from a
            Proton Authenticator backup. Nothing is written until you review
            and, if needed, edit the names and folders.
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
  onCandidateChange,
  onConfirm,
  onCancel,
}: {
  preview: ImportPreview;
  busy: boolean;
  onCandidateChange: (
    index: number,
    change: Partial<Pick<ImportCandidate, "name" | "folder">>,
  ) => void;
  onConfirm: () => void;
  onCancel: () => void;
}): JSX.Element {
  const nothingToDo = preview.ready.length === 0;
  const sourceName = preview.source === "protonPass" ? "Proton Pass" : "Proton Authenticator";
  const singularNoun = preview.source === "protonPass" ? "item" : "code";
  const noun = preview.ready.length === 1 ? singularNoun : `${singularNoun}s`;
  const hasBlankName = preview.ready.some((candidate) => candidate.name.trim() === "");

  return (
    <>
      <p className="sync__lead">
        <strong>{sourceName}</strong> · {preview.ready.length} {noun} to add
        {preview.duplicates.length > 0 && `, ${preview.duplicates.length} already here`}
        {preview.skipped.length > 0 && `, ${preview.skipped.length} to skip`}
        {preview.warnings.length > 0 &&
          `, ${preview.warnings.length} ${preview.warnings.length === 1 ? "warning" : "warnings"}`}.
      </p>

      <p className="input-hint">
        Passwords, notes, card details and two-factor seeds stay in the backend;
        only names and folders can be edited here.
      </p>

      {preview.ready.length > 0 && (
        <EditableGroup
          candidates={preview.ready}
          disabled={busy}
          onChange={onCandidateChange}
        />
      )}

      {hasBlankName && <p className="input-hint">Every imported item needs a name.</p>}

      {/* Authenticator codes are matched by seed. Proton Pass entries are
          matched by their imported credential fields, never by name alone. */}
      {preview.duplicates.length > 0 && (
        <NameGroup label="Already in your vault" names={preview.duplicates} />
      )}

      {preview.skipped.length > 0 && (
        <section>
          <p className="section-label">Will be skipped</p>
          <ul className="import__list">
            {preview.skipped.map((problem, index) => (
              <li key={`${problem.name}-${index}`}>
                <span className="import__name">{problem.name}</span>
                <span className="import__reason">{problem.reason}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {preview.warnings.length > 0 && (
        <section>
          <p className="section-label">Needs attention</p>
          <ul className="import__list">
            {preview.warnings.map((problem, index) => (
              <li key={`${problem.name}-${index}`}>
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
          disabled={busy || nothingToDo || hasBlankName}
          onClick={onConfirm}
        >
          {busy
            ? "Importing…"
            : nothingToDo
              ? "Nothing to import"
              : `Import ${preview.ready.length} ${noun}`}
        </button>
        <button type="button" className="button button--quiet" disabled={busy} onClick={onCancel}>
          Cancel
        </button>
      </div>
    </>
  );
}

function EditableGroup({
  candidates,
  disabled,
  onChange,
}: {
  candidates: ImportCandidate[];
  disabled: boolean;
  onChange: (
    index: number,
    change: Partial<Pick<ImportCandidate, "name" | "folder">>,
  ) => void;
}): JSX.Element {
  return (
    <section>
      <p className="section-label">Review and edit</p>
      <ul className="import__list import__list--editable">
        {candidates.map((candidate) => (
          <li className="import__edit-row" key={candidate.index}>
            <label className="import__edit-field">
              <span className="import__edit-label">Name</span>
              <input
                className="input import__edit-input"
                value={candidate.name}
                disabled={disabled}
                aria-invalid={candidate.name.trim() === ""}
                onChange={(event) => onChange(candidate.index, { name: event.target.value })}
              />
            </label>
            <label className="import__edit-field">
              <span className="import__edit-label">Folder</span>
              <input
                className="input import__edit-input"
                value={candidate.folder ?? ""}
                placeholder="No folder"
                disabled={disabled}
                onChange={(event) => onChange(candidate.index, { folder: event.target.value || null })}
              />
            </label>
          </li>
        ))}
      </ul>
    </section>
  );
}

function NameGroup({ label, names }: { label: string; names: string[] }): JSX.Element {
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
