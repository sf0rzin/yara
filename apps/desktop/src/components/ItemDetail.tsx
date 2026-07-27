import { useEffect, useState, type JSX } from "react";
import { deleteItem, errorMessage, revealPassword, type ItemSummary } from "../api";
import { clipboardClearSeconds, copySecret } from "../lib/clipboard";
import { Icon } from "./Icon";
import { TotpBadge } from "./TotpBadge";

interface ItemDetailProps {
  item: ItemSummary;
  onClose: () => void;
  onChanged: () => void;
}

export function ItemDetail({ item, onClose, onChanged }: ItemDetailProps): JSX.Element {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Re-selecting a different item must never carry the previous plaintext over.
  useEffect(() => {
    setRevealed(null);
    setConfirmingDelete(false);
    setNotice(null);
    setError(null);
  }, [item.id]);

  // A password left on screen is a shoulder-surfing risk; hide it again.
  useEffect(() => {
    if (!revealed) return;
    const timer = setTimeout(() => setRevealed(null), 30_000);
    return () => clearTimeout(timer);
  }, [revealed]);

  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), 2_500);
    return () => clearTimeout(timer);
  }, [notice]);

  // Escape closes the panel, and does not merely hide the revealed password.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  async function toggleReveal() {
    if (revealed) {
      setRevealed(null);
      return;
    }
    try {
      setRevealed(await revealPassword(item.id));
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function copyPassword() {
    try {
      const password = await revealPassword(item.id);
      await copySecret(password);
      setNotice(`Copied. Clipboard clears in ${clipboardClearSeconds}s.`);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function copyPlain(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    setNotice(`${label} copied.`);
  }

  async function remove() {
    if (!confirmingDelete) {
      setConfirmingDelete(true);
      return;
    }
    try {
      await deleteItem(item.id);
      onChanged();
      onClose();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  return (
    <aside className="detail" aria-label={`Details for ${item.name}`}>
      <header className="detail__head">
        <div>
          <h2 className="detail__title">{item.name}</h2>
          <p className="detail__kind">{item.kind}</p>
        </div>
        <button
          type="button"
          className="icon-button"
          onClick={onClose}
          aria-label="Close details"
        >
          <Icon name="close" size={14} />
        </button>
      </header>

      <div className="detail__fields">
        {item.username && (
          <Field label="Username" value={item.username}>
            <button
              type="button"
              className="icon-button"
              onClick={() => void copyPlain("Username", item.username!)}
              aria-label="Copy username"
            >
              <Icon name="copy" size={14} />
            </button>
          </Field>
        )}

        {item.hasPassword && (
          <Field
            label="Password"
            value={revealed ?? "••••••••••••"}
            monospace
            selectable={Boolean(revealed)}
          >
            <button
              type="button"
              className="icon-button"
              onClick={() => void toggleReveal()}
              aria-label={revealed ? "Hide password" : "Reveal password"}
            >
              <Icon name={revealed ? "eyeOff" : "eye"} size={14} />
            </button>
            <button
              type="button"
              className="icon-button"
              onClick={() => void copyPassword()}
              aria-label="Copy password"
            >
              <Icon name="copy" size={14} />
            </button>
          </Field>
        )}

        {item.url && (
          <Field label="Website" value={item.url}>
            <button
              type="button"
              className="icon-button"
              onClick={() => void copyPlain("Address", item.url!)}
              aria-label="Copy address"
            >
              <Icon name="copy" size={14} />
            </button>
          </Field>
        )}

        {item.hasTotp && (
          <div className="field">
            <p className="field__label">One-time code</p>
            <div className="field__row">
              <TotpBadge itemId={item.id} prominent />
            </div>
          </div>
        )}

        {item.tags.length > 0 && (
          <div className="field">
            <p className="field__label">Tags</p>
            <div className="tags">
              {item.tags.map((tag) => (
                <span key={tag} className="tag">
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="detail__foot">
        {notice && <p className="notice">{notice}</p>}
        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <button type="button" className="button button--quiet" onClick={() => void remove()}>
          <Icon name="trash" size={14} />
          {confirmingDelete ? "Click again to delete" : "Delete item"}
        </button>
      </div>
    </aside>
  );
}

interface FieldProps {
  label: string;
  value: string;
  monospace?: boolean;
  selectable?: boolean;
  children?: React.ReactNode;
}

function Field({ label, value, monospace, selectable, children }: FieldProps): JSX.Element {
  return (
    <div className="field">
      <p className="field__label">{label}</p>
      <div className="field__row">
        <span
          className={`field__value${monospace ? " field__value--mono" : ""}${
            selectable ? " selectable" : ""
          }`}
        >
          {value}
        </span>
        <span className="field__actions">{children}</span>
      </div>
    </div>
  );
}
