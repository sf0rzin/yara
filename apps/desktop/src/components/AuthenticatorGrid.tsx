import type { JSX } from "react";
import type { ItemSummary } from "../api";
import { Icon } from "./Icon";
import { Tile } from "./Tile";
import { TotpBadge } from "./TotpBadge";

interface AuthenticatorGridProps {
  items: ItemSummary[];
  query: string;
  loading: boolean;
  error: string | null;
  onQueryChange: (query: string) => void;
  onNew: () => void;
  onImport: () => void;
  onContextMenu: (item: ItemSummary, x: number, y: number) => void;
}

export function AuthenticatorGrid({
  items,
  query,
  loading,
  error,
  onQueryChange,
  onNew,
  onImport,
  onContextMenu,
}: AuthenticatorGridProps): JSX.Element {
  return (
    <section className="auth-view" aria-label="Authenticator codes">
      <header className="auth-view__toolbar">
        <div className="auth-view__heading">
          <h1>Authenticator</h1>
          <span>{items.length} {items.length === 1 ? "code" : "codes"}</span>
        </div>
      </header>

      <div className="auth-view__tools">
        <label className="auth-view__search">
          <Icon name="search" size={14} />
          <input
            type="search"
            value={query}
            placeholder="Filter codes"
            aria-label="Filter authenticator codes"
            onChange={(event) => onQueryChange(event.target.value)}
          />
        </label>
        <div className="auth-view__actions">
          <button
            type="button"
            className="icon-button icon-button--bordered"
            aria-label="Import codes"
            title="Import codes"
            onClick={onImport}
          >
            <Icon name="download" size={14} />
          </button>
          <button type="button" className="button button--primary" onClick={onNew}>
            <Icon name="plus" size={14} />
            <span>New code</span>
          </button>
        </div>
      </div>

      {error && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {error}
        </p>
      )}

      {loading ? (
        <div className="auth-grid auth-grid--loading" aria-label="Loading codes">
          {Array.from({ length: 6 }, (_, index) => (
            <span className="auth-card auth-card--skeleton" key={index} />
          ))}
        </div>
      ) : items.length === 0 ? (
        <p className="empty auth-empty">
          {query ? "No codes match this search." : "No authenticator codes yet."}
        </p>
      ) : (
        <div className="auth-grid">
          {items.map((item) => (
            <article
              className="auth-card"
              key={item.id}
              onContextMenu={(event) => {
                event.preventDefault();
                onContextMenu(item, event.clientX, event.clientY);
              }}
            >
              <header className="auth-card__header">
                <span className="auth-card__identity">
                  <Tile name={item.name} kind={item.kind} url={item.url} />
                  <span>
                    <strong>{item.name}</strong>
                    <small>{item.username ?? hostOf(item.url) ?? "Account"}</small>
                  </span>
                </span>
                <button
                  type="button"
                  className="auth-card__more"
                  aria-label={`${item.name} code options`}
                  onClick={(event) => {
                    const rect = event.currentTarget.getBoundingClientRect();
                    onContextMenu(item, rect.right, rect.bottom);
                  }}
                >
                  <Icon name="ellipsis" size={14} />
                </button>
              </header>

              <TotpBadge itemId={item.id} prominent copyable />
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}
