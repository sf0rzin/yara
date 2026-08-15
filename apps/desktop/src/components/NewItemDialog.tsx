import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import {
  addItem,
  clearScannedTotp,
  errorMessage,
  generatePassword,
  itemExtras,
  revealField,
  revealNotes,
  updateItem,
  type ItemKind,
  type ItemSummary,
  type NewField,
  type TotpPreview,
} from "../api";
import { Icon } from "./Icon";
import { QrCapture } from "./QrCapture";

const KINDS: { value: ItemKind; label: string }[] = [
  { value: "login", label: "Login" },
  { value: "card", label: "Card" },
  { value: "note", label: "Note" },
];

interface NewItemDialogProps {
  onClose: () => void;
  onCreated: (id: string) => void;
  /** When present the dialog edits this item instead of creating one. */
  editing?: ItemSummary;
}

/**
 * Creating and editing, in one dialog.
 *
 * The same form either way, because the fields are the same and two components
 * would drift. What differs is the password: an edit never receives the stored
 * one — it is a secret, and the whole architecture is built on not shipping
 * those to the frontend without being asked. So the box starts empty and means
 * "leave it alone" until it is touched, which is a thing the interface has to
 * say out loud rather than imply.
 */
export function NewItemDialog({
  onClose,
  onCreated,
  editing,
}: NewItemDialogProps): JSX.Element {
  const [kind, setKind] = useState<ItemKind>(editing?.kind ?? "login");
  const [name, setName] = useState(editing?.name ?? "");
  const [username, setUsername] = useState(editing?.username ?? "");
  const [password, setPassword] = useState("");
  const [passwordTouched, setPasswordTouched] = useState(false);
  const [generatedPasswordVisible, setGeneratedPasswordVisible] = useState(false);
  const [url, setUrl] = useState(editing?.url ?? "");
  const [notes, setNotes] = useState("");
  const [fields, setFields] = useState<NewField[]>([]);
  const [totpUri, setTotpUri] = useState("");
  const [scanned, setScanned] = useState<TotpPreview | null>(null);
  const [manualEntry, setManualEntry] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const firstField = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstField.current?.focus();
  }, []);

  // An edit has to load what a listing leaves out. Secret field values are
  // fetched one by one rather than in a batch, because there is no command
  // that hands over several at once and adding one would be a way to get all
  // of an item's secrets in a single call.
  useEffect(() => {
    if (!editing) return;
    let cancelled = false;

    void (async () => {
      try {
        const extras = await itemExtras(editing.id);
        const loaded = await Promise.all(
          extras.fields.map(async (field) => ({
            label: field.label,
            secret: field.secret,
            value: field.secret
              ? await revealField(editing.id, field.label)
              : (field.value ?? ""),
          })),
        );
        const text = extras.hasNotes ? await revealNotes(editing.id) : "";
        if (!cancelled) {
          setFields(loaded);
          setNotes(text);
        }
      } catch (caught) {
        if (!cancelled) setError(errorMessage(caught));
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [editing]);

  // Abandoning the dialog must not leave a scanned secret parked in the backend.
  const dismiss = useCallback(() => {
    void clearScannedTotp();
    onClose();
  }, [onClose]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") dismiss();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [dismiss]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);

    const kept = fields.filter((field) => field.label.trim() !== "");

    try {
      if (editing) {
        await updateItem(editing.id, {
          name: name.trim(),
          kind,
          username: username.trim() || null,
          // Untouched means untouched. Sending "" here would erase a password
          // simply because the form could not show it back.
          password: passwordTouched ? password : null,
          url: url.trim() || null,
          notes: notes.trim() || null,
          fields: kept,
        });
        onCreated(editing.id);
        return;
      }

      const id = await addItem({
        name: name.trim(),
        kind,
        username: username.trim() || null,
        password: password || null,
        url: url.trim() || null,
        notes: notes.trim() || null,
        fields: kept,
        totp_uri: scanned ? null : totpUri.trim() || null,
        use_scanned_totp: Boolean(scanned),
      });
      onCreated(id);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  async function fillGeneratedPassword() {
    setError(null);
    try {
      const generated = await generatePassword({
        length: 20,
        lowercase: true,
        uppercase: true,
        digits: true,
        symbols: true,
      });
      setPassword(generated);
      setPasswordTouched(true);
      setGeneratedPasswordVisible(true);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  const setField = (index: number, patch: Partial<NewField>) =>
    setFields((current) =>
      current.map((field, at) => (at === index ? { ...field, ...patch } : field)),
    );

  return (
    <div className="overlay" onMouseDown={dismiss}>
      <form
        className="dialog"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => void submit(event)}
        aria-label={editing ? "Edit item" : "New item"}
      >
        <header className="dialog__head">
          <h2 className="dialog__title">{editing ? "Edit item" : "New item"}</h2>
          <button
            type="button"
            className="icon-button"
            onClick={dismiss}
            aria-label="Close"
          >
            <Icon name="close" size={14} />
          </button>
        </header>

        <div className="segmented" role="radiogroup" aria-label="Item type">
          {KINDS.map((option) => (
            <button
              key={option.value}
              type="button"
              role="radio"
              aria-checked={kind === option.value}
              className="segmented__option"
              data-active={kind === option.value || undefined}
              onClick={() => setKind(option.value)}
            >
              {option.label}
            </button>
          ))}
        </div>

        <label className="input-label">
          Name
          <input
            ref={firstField}
            className="input"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="GitHub"
          />
        </label>

        {kind === "login" && (
          <>
            <label className="input-label">
              Username
              <input
                className="input"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="you@example.com"
              />
            </label>

            <label className="input-label">
              Password
              <div className="fields__row">
                <input
                  className="input fields__value"
                  type={generatedPasswordVisible ? "text" : "password"}
                  value={password}
                  placeholder={editing ? "Unchanged" : undefined}
                  onChange={(event) => {
                    setPassword(event.target.value);
                    setPasswordTouched(true);
                    setGeneratedPasswordVisible(false);
                  }}
                />
                <button
                  type="button"
                  className="icon-button icon-button--bordered"
                  aria-label="Generate password"
                  title="Generate password"
                  onClick={() => void fillGeneratedPassword()}
                >
                  <Icon name="sparkle" size={14} />
                </button>
              </div>
              {/* Said outright, because an empty box that means "keep what is
                  there" is otherwise indistinguishable from one that means
                  "remove it", and the two are opposite instructions. */}
              {editing && !passwordTouched && (
                <span className="input-hint">
                  Left empty, the stored password stays as it is. Type to
                  replace it; clear it after typing to remove it.
                </span>
              )}
            </label>

            <label className="input-label">
              Website
              <input
                className="input"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://github.com"
              />
            </label>

            <div className="input-label">
              Authenticator
              <QrCapture preview={scanned} onScanned={setScanned} />

              {!scanned &&
                (manualEntry ? (
                  <>
                    <input
                      className="input"
                      value={totpUri}
                      onChange={(event) => setTotpUri(event.target.value)}
                      placeholder="otpauth://totp/…"
                    />
                    <span className="input-hint">
                      Typed keys pass through the interface, unlike a scanned
                      code. Prefer the QR when you have one.
                    </span>
                  </>
                ) : (
                  <button
                    type="button"
                    className="linkish"
                    onClick={() => setManualEntry(true)}
                  >
                    Enter a setup key by hand instead
                  </button>
                ))}
            </div>
          </>
        )}

        {/*
          Custom fields. Available on every kind, not just logins — a card has
          a PIN and a note has whatever the person filing it decided, and the
          reason this exists at all is that one fixed password box was never
          going to cover what people keep.
        */}
        <div className="input-label">
          Fields
          {fields.length > 0 && (
            <ul className="fields">
              {fields.map((field, index) => (
                <li className="fields__row" key={index}>
                  <input
                    className="input fields__label"
                    value={field.label}
                    aria-label={`Field ${index + 1} name`}
                    placeholder="API key"
                    onChange={(event) => setField(index, { label: event.target.value })}
                  />
                  <input
                    className="input fields__value"
                    type={field.secret ? "password" : "text"}
                    value={field.value}
                    aria-label={`Field ${index + 1} value`}
                    placeholder="Value"
                    onChange={(event) => setField(index, { value: event.target.value })}
                  />
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={field.secret ? "Stop hiding this field" : "Hide this field"}
                    title={field.secret ? "Hidden — shown only on request" : "Shown in plain text"}
                    aria-pressed={field.secret}
                    onClick={() => setField(index, { secret: !field.secret })}
                  >
                    <Icon name={field.secret ? "eyeOff" : "eye"} size={14} />
                  </button>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={`Remove ${field.label || "this field"}`}
                    onClick={() => setFields((c) => c.filter((_, at) => at !== index))}
                  >
                    <Icon name="close" size={13} />
                  </button>
                </li>
              ))}
            </ul>
          )}

          <button
            type="button"
            className="button button--outline"
            onClick={() =>
              setFields((current) => [...current, { label: "", value: "", secret: true }])
            }
          >
            <Icon name="plus" size={13} />
            Add a field
          </button>
        </div>

        <label className="input-label">
          Notes
          <textarea
            className="input input--area"
            value={notes}
            rows={3}
            onChange={(event) => setNotes(event.target.value)}
            placeholder="Anything else worth keeping with this item"
          />
        </label>

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <div className="dialog__foot">
          <button type="button" className="button button--quiet" onClick={dismiss}>
            Cancel
          </button>
          <button
            type="submit"
            className="button button--primary"
            disabled={busy || !name.trim()}
          >
            {busy ? "Saving…" : editing ? "Save changes" : "Save item"}
          </button>
        </div>
      </form>
    </div>
  );
}
