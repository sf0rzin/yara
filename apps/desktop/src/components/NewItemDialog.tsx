import { useEffect, useRef, useState, type JSX } from "react";
import { addItem, errorMessage, type ItemKind } from "../api";
import { Icon } from "./Icon";

const KINDS: { value: ItemKind; label: string }[] = [
  { value: "login", label: "Login" },
  { value: "card", label: "Card" },
  { value: "note", label: "Note" },
];

interface NewItemDialogProps {
  onClose: () => void;
  onCreated: (id: string) => void;
}

export function NewItemDialog({ onClose, onCreated }: NewItemDialogProps): JSX.Element {
  const [kind, setKind] = useState<ItemKind>("login");
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const firstField = useRef<HTMLInputElement>(null);

  useEffect(() => {
    firstField.current?.focus();
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      const id = await addItem({
        name: name.trim(),
        kind,
        username: username.trim() || null,
        password: password || null,
        url: url.trim() || null,
        totp_uri: totpUri.trim() || null,
      });
      onCreated(id);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="overlay" onMouseDown={onClose}>
      <form
        className="dialog"
        onMouseDown={(event) => event.stopPropagation()}
        onSubmit={(event) => void submit(event)}
        aria-label="New item"
      >
        <header className="dialog__head">
          <h2 className="dialog__title">New item</h2>
          <button
            type="button"
            className="icon-button"
            onClick={onClose}
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
              <input
                className="input"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
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

            <label className="input-label">
              Authenticator
              <input
                className="input"
                value={totpUri}
                onChange={(event) => setTotpUri(event.target.value)}
                placeholder="otpauth://totp/…"
              />
              <span className="input-hint">
                Paste the setup link behind the QR code to generate codes here.
              </span>
            </label>
          </>
        )}

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <div className="dialog__foot">
          <button type="button" className="button button--quiet" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="button button--primary"
            disabled={busy || !name.trim()}
          >
            {busy ? "Saving…" : "Save item"}
          </button>
        </div>
      </form>
    </div>
  );
}
