import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import {
  errorMessage,
  listItems,
  lockVault,
  recentItems,
  vaultCounts,
  vaultHealth,
  type ItemSummary,
  type VaultCounts,
  type VaultHealth,
} from "../api";
import { Icon } from "../components/Icon";
import { ItemDetail } from "../components/ItemDetail";
import { ItemRow } from "../components/ItemRow";
import { NewItemDialog } from "../components/NewItemDialog";
import { SecurityView } from "../components/SecurityView";
import { Sidebar } from "../components/Sidebar";
import { affectedItemCount, isClean } from "../lib/health";
import { useAutoLock } from "../lib/useAutoLock";
import { viewSubtitle, viewTitle, type View } from "../views";

/** Matches the countdown the design shows in the sidebar. */
const AUTO_LOCK_MS = 8 * 60 * 1000;

interface VaultProps {
  onLock: () => void;
}

export function Vault({ onLock }: VaultProps): JSX.Element {
  const [view, setView] = useState<View>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [recent, setRecent] = useState<ItemSummary[]>([]);
  const [counts, setCounts] = useState<VaultCounts | null>(null);
  const [health, setHealth] = useState<VaultHealth | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);

  const lock = useCallback(() => {
    void lockVault();
    onLock();
  }, [onLock]);

  const lockRemaining = useAutoLock(AUTO_LOCK_MS, lock);

  const refresh = useCallback(async () => {
    try {
      const [nextItems, nextRecent, nextCounts, nextHealth] = await Promise.all([
        listItems({
          query,
          kind: view.kind === "type" ? view.itemKind : undefined,
          withTotp: view.kind === "authenticator" ? true : undefined,
        }),
        recentItems(5),
        vaultCounts(),
        vaultHealth(),
      ]);

      setItems(nextItems);
      setRecent(nextRecent);
      setCounts(nextCounts);
      setHealth(nextHealth);
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, [query, view]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Ctrl/Cmd+K jumps to search, as advertised in the sidebar.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? recent.find((item) => item.id === selectedId) ?? null,
    [items, recent, selectedId],
  );

  const searching = query.trim().length > 0;
  const showOverview = view.kind === "all" && !searching;

  return (
    <div className="app">
      <Sidebar
        view={view}
        counts={counts}
        lockRemainingMs={lockRemaining}
        onSelect={(next) => {
          setView(next);
          setQuery("");
          setSelectedId(null);
        }}
        onFocusSearch={() => searchRef.current?.focus()}
        onLock={lock}
      />

      <main className="main">
        <header className="main__head">
          <div>
            <h1 className="main__title">
              {searching ? "Search" : viewTitle(view)}
            </h1>
            <p className="main__sub">
              {searching
                ? `${items.length} ${items.length === 1 ? "match" : "matches"} for “${query.trim()}”`
                : viewSubtitle(view, counts)}
            </p>
          </div>

          <button
            type="button"
            className="button button--primary"
            onClick={() => setCreating(true)}
          >
            <Icon name="plus" size={14} />
            New item
          </button>
        </header>

        <div className="searchbar">
          <Icon name="search" size={15} />
          <input
            ref={searchRef}
            className="searchbar__input"
            value={query}
            placeholder="Search your vault"
            onChange={(event) => setQuery(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                setQuery("");
                event.currentTarget.blur();
              }
            }}
          />
          {searching && (
            <button
              type="button"
              className="icon-button"
              onClick={() => setQuery("")}
              aria-label="Clear search"
            >
              <Icon name="close" size={13} />
            </button>
          )}
        </div>

        {error && (
          <p className="notice notice--loud">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}

        <div className="main__body">
          {view.kind === "security" ? (
            health && (
              <SecurityView
                health={health}
                items={items}
                onSelect={setSelectedId}
              />
            )
          ) : showOverview ? (
            <Overview
              recent={recent}
              health={health}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onOpenSecurity={() => setView({ kind: "security" })}
            />
          ) : (
            <ItemList
              items={items}
              selectedId={selectedId}
              onSelect={setSelectedId}
              emptyMessage={
                searching ? "Nothing matches that." : "Nothing here yet."
              }
            />
          )}
        </div>
      </main>

      {selected && (
        <ItemDetail
          item={selected}
          onClose={() => setSelectedId(null)}
          onChanged={() => void refresh()}
        />
      )}

      {creating && (
        <NewItemDialog
          onClose={() => setCreating(false)}
          onCreated={(id) => {
            setCreating(false);
            setSelectedId(id);
            void refresh();
          }}
        />
      )}
    </div>
  );
}

function Overview({
  recent,
  health,
  selectedId,
  onSelect,
  onOpenSecurity,
}: {
  recent: ItemSummary[];
  health: VaultHealth | null;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onOpenSecurity: () => void;
}): JSX.Element {
  const clean = health !== null && isClean(health);
  const affected = health ? affectedItemCount(health) : 0;

  return (
    <>
      {recent.length > 0 && (
        <section>
          <p className="section-label">Recently used</p>
          <ItemList
            items={recent}
            selectedId={selectedId}
            onSelect={onSelect}
            emptyMessage="Nothing here yet."
          />
        </section>
      )}

      <section className="suggestions">
        <p className="section-label">Suggested</p>
        <div className="suggestions__grid">
          <button type="button" className="card" onClick={onOpenSecurity}>
            <span className="card__head">
              <Icon name={clean ? "check" : "alert"} size={15} />
              Vault health
            </span>
            <span className="card__body">
              {health === null
                ? "Checking your passwords…"
                : clean
                  ? "No weak or reused passwords found."
                  : `${affected} ${affected === 1 ? "password needs" : "passwords need"} attention.`}
            </span>
            <span className="card__action">Review security</span>
          </button>

          <div className="card card--static">
            <span className="card__head">
              <Icon name="sparkle" size={15} />
              AI access
            </span>
            <span className="card__body">
              Not yet available. Agents will request credentials here, and
              nothing is released without your approval.
            </span>
            <span className="card__action card__action--muted">In development</span>
          </div>
        </div>
      </section>
    </>
  );
}

function ItemList({
  items,
  selectedId,
  onSelect,
  emptyMessage,
}: {
  items: ItemSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  emptyMessage: string;
}): JSX.Element {
  if (items.length === 0) {
    return <p className="empty">{emptyMessage}</p>;
  }

  return (
    <ul className="rows">
      {items.map((item) => (
        <ItemRow
          key={item.id}
          item={item}
          selected={item.id === selectedId}
          onSelect={onSelect}
        />
      ))}
    </ul>
  );
}
