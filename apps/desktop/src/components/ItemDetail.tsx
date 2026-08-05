import { useEffect, useState, type JSX } from "react";
import {
  deleteItem,
  errorMessage,
  formatCharge,
  formatMoney,
  itemSubscription,
  revealPassword,
  type ItemSummary,
  type SubscriptionView,
  type VaultHealth,
} from "../api";
import { copySecret } from "../lib/clipboard";
import { itemHealth } from "../lib/health";
import { Icon } from "./Icon";
import { Tile } from "./Tile";
import { TotpBadge } from "./TotpBadge";

interface ItemDetailProps {
  item: ItemSummary;
  health: VaultHealth | null;
  onChanged: () => void;
}

/**
 * The right-hand pane.
 *
 * A pane rather than the overlay this used to be. An overlay says "you are
 * doing one thing now"; a vault is read by moving between items, and covering
 * the list to show one of them fought that every time.
 *
 * Sections are inset grouped lists: a label outside, rows inside a rounded
 * well. What that buys is a place to put the label that is not a table header,
 * so "Credentials" and "Details" can be quiet without becoming ambiguous.
 */
export function ItemDetail({ item, health, onChanged }: ItemDetailProps): JSX.Element {
  const [revealed, setRevealed] = useState<string | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [billing, setBilling] = useState<SubscriptionView | null>(null);

  // Switching items must not carry the previous one's revealed password, its
  // half-pressed delete, or a notice about something you are no longer looking
  // at. Keyed on the id so it fires on selection rather than on every render.
  useEffect(() => {
    setRevealed(null);
    setConfirmingDelete(false);
    setNotice(null);
    setError(null);
    setBilling(null);
    // Fetched per item rather than carried on the summary: most items have no
    // subscription, and a field that is null for nine rows in ten does not
    // belong in the list payload.
    void itemSubscription(item.id)
      .then(setBilling)
      .catch(() => setBilling(null));
  }, [item.id]);

  // A revealed password does not stay revealed. Leaving one on screen is how a
  // shoulder becomes a leak, and the person who revealed it has already read it.
  useEffect(() => {
    if (revealed === null) return;
    const timer = setTimeout(() => setRevealed(null), 30_000);
    return () => clearTimeout(timer);
  }, [revealed]);

  useEffect(() => {
    if (notice === null) return;
    const timer = setTimeout(() => setNotice(null), 2_500);
    return () => clearTimeout(timer);
  }, [notice]);

  async function toggleReveal() {
    if (revealed !== null) {
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
      // Fetched fresh rather than reused from `revealed`, so copying works
      // whether or not it is currently on screen.
      await copySecret(await revealPassword(item.id));
      setNotice("Password copied. Clipboard clears shortly.");
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function copyPlain(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    setNotice(`${label} copied.`);
  }

  async function remove() {
    try {
      await deleteItem(item.id);
      onChanged();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  const host = hostOf(item.url);
  const health_ = itemHealth(item, health);

  return (
    <section className="detail" aria-label={item.name}>
      <header className="detail__toolbar">
        <span className="detail__toolbar-spacer" />
        <button type="button" className="icon-button" aria-label="Edit item" disabled>
          <Icon name="pencil" size={14} />
        </button>
        <button type="button" className="icon-button" aria-label="More actions" disabled>
          <Icon name="ellipsis" size={14} />
        </button>
      </header>

      <div className="detail__scroll">
        <div className="detail__header">
          <Tile name={item.name} kind={item.kind} url={item.url} large />
          <div className="detail__heading">
            <h2 className="detail__name">{item.name}</h2>
            {host && <p className="detail__host">{host}</p>}
          </div>
        </div>

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}
        {notice && (
          <p className="notice">
            <Icon name="check" size={13} />
            {notice}
          </p>
        )}

        {(item.username || item.hasPassword) && (
          <Section label="Credentials">
            {item.username && (
              <Row label="Username" value={item.username}>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Copy username"
                  onClick={() => void copyPlain("Username", item.username as string)}
                >
                  <Icon name="copy" size={14} />
                </button>
              </Row>
            )}

            {item.hasPassword && (
              <Row
                label="Password"
                value={revealed ?? "••••••••••••••••"}
                mono
                title={revealed ? undefined : "Hidden until you ask"}
              >
                <button
                  type="button"
                  className="icon-button"
                  aria-label={revealed ? "Hide password" : "Reveal password"}
                  onClick={() => void toggleReveal()}
                >
                  <Icon name={revealed ? "eyeOff" : "eye"} size={14} />
                </button>
                <button
                  type="button"
                  className="icon-button"
                  aria-label="Copy password"
                  onClick={() => void copyPassword()}
                >
                  <Icon name="copy" size={14} />
                </button>
              </Row>
            )}
          </Section>
        )}

        {item.hasTotp && (
          <Section label="One-time code">
            <div className="detail__row detail__row--tall">
              <span className="detail__label">Code</span>
              <span className="detail__value">
                <TotpBadge itemId={item.id} prominent />
              </span>
            </div>
          </Section>
        )}

        {billing && (
          <Section label="Billing">
            {billing.plan && <Row label="Plan" value={billing.plan} />}
            <Row
              label="Amount"
              value={`${formatMoney(billing.amountMinor, billing.currency)} ${billing.cadence}`}
            />
            <Row label="Next charge" value={formatCharge(billing.nextCharge)} />
            {/*
              The row this feature exists for. A card that has since been
              deleted says so rather than showing a blank — blank reads as "no
              card" when the truth is "a card that is gone", and those lead to
              opposite actions.
            */}
            <Row
              label="Paid with"
              value={
                billing.paidWith === null
                  ? "Not recorded"
                  : (billing.paidWithName ?? "A card no longer in this vault")
              }
            >
              {billing.paidWithName && <Icon name="chevronRight" size={13} />}
            </Row>
          </Section>
        )}

        <Section label="Details">
          {host && (
            <Row label="Website" value={host}>
              <Icon name="chevronRight" size={13} />
            </Row>
          )}
          <Row label="Added" value={formatDate(item.createdAt)} />
          <Row label="Updated" value={formatRelative(item.updatedAt)} />
          {health_ && <Row label="Health" value={health_} />}
        </Section>

        {/*
          Two presses, not a confirm dialog. There is no red to make this look
          dangerous, so the safeguard is that the first press only changes the
          words — and the words then say exactly what is about to happen.
        */}
        <div className="group group--destructive">
          <button
            type="button"
            className="detail__row detail__row--action"
            onClick={() => (confirmingDelete ? void remove() : setConfirmingDelete(true))}
            onBlur={() => setConfirmingDelete(false)}
          >
            <span className="detail__action-text">
              {confirmingDelete ? `Delete ${item.name} for good` : "Delete item…"}
            </span>
          </button>
        </div>

        <p className="detail__provenance">
          Encrypted under your vault key. Never leaves this machine unless Sync
          is on.
        </p>
      </div>
    </section>
  );
}

function Section({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <section className="detail__section">
      <p className="section-label">{label}</p>
      <div className="group">{children}</div>
    </section>
  );
}

function Row({
  label,
  value,
  mono,
  title,
  children,
}: {
  label: string;
  value: string;
  mono?: boolean;
  title?: string;
  children?: React.ReactNode;
}): JSX.Element {
  return (
    <div className="detail__row">
      <span className="detail__label">{label}</span>
      <span
        className="detail__value"
        data-mono={mono || undefined}
        title={title}
      >
        {value}
      </span>
      {children}
    </div>
  );
}

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url).host.replace(/^www\./, "");
  } catch {
    return url;
  }
}

function formatDate(seconds: number): string {
  if (!seconds) return "Unknown";
  return new Date(seconds * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
    year: "numeric",
  });
}

function formatRelative(seconds: number): string {
  if (!seconds) return "Unknown";
  const elapsed = Math.max(0, Math.floor(Date.now() / 1000) - seconds);
  if (elapsed < 60) return "Just now";
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)} minutes ago`;
  if (elapsed < 86_400) return `${Math.floor(elapsed / 3600)} hours ago`;
  const days = Math.floor(elapsed / 86_400);
  if (days === 1) return "Yesterday";
  if (days < 30) return `${days} days ago`;
  return formatDate(seconds);
}
