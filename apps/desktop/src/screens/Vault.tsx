import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import {
  autoLockSeconds as readAutoLock,
  errorMessage,
  listItems,
  lockVault,
  recentItems,
  setAutoLockSeconds,
  vaultCounts,
  vaultHealth,
  type ItemSummary,
  type VaultCounts,
  type VaultHealth,
} from "../api";
import type { ApprovalPrompt } from "../api";
import { AgentAccess } from "../components/AgentAccess";
import { ApprovalDialog } from "../components/ApprovalDialog";
import { Icon } from "../components/Icon";
import { ImportPanel } from "../components/ImportPanel";
import { ItemDetail } from "../components/ItemDetail";
import { ItemRow } from "../components/ItemRow";
import { NewItemDialog } from "../components/NewItemDialog";
import { Sidebar } from "../components/Sidebar";
import { SubscriptionsView } from "../components/SubscriptionsView";
import { SyncView } from "../components/SyncView";
import { UpdateNotice } from "../components/UpdateNotice";
import { useAutoLock } from "../lib/useAutoLock";
import { isItemList, viewSubtitle, viewTitle, type View } from "../views";

/** Until the vault says otherwise. Matches the core default. */
const FALLBACK_AUTO_LOCK = 15 * 60;

interface VaultProps {
  onLock: () => void;
}

/**
 * Three columns: navigate, choose, read.
 *
 * The detail used to cover the list. Moving it into a column of its own is
 * what lets you walk down a vault comparing items, which is most of what
 * anyone actually does here.
 *
 * Screens that are not lists of items — Agent access, Sync — take the list and
 * detail area together rather than pretending to be a selection.
 */
export function Vault({ onLock }: VaultProps): JSX.Element {
  const [view, setView] = useState<View>({ kind: "all" });
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [counts, setCounts] = useState<VaultCounts | null>(null);
  const [health, setHealth] = useState<VaultHealth | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ApprovalPrompt[]>([]);
  const [autoLock, setAutoLock] = useState<number | null>(FALLBACK_AUTO_LOCK);

  const searchRef = useRef<HTMLInputElement>(null);

  const lock = useCallback(() => {
    void lockVault();
    onLock();
  }, [onLock]);

  // Never means never: an interval of Infinity leaves the countdown pinned
  // and the callback unreachable, which is exactly the intent.
  const lockRemaining = useAutoLock(
    autoLock === null ? Number.POSITIVE_INFINITY : autoLock * 1000,
    lock,
  );

  useEffect(() => {
    void readAutoLock()
      .then(setAutoLock)
      .catch(() => setAutoLock(FALLBACK_AUTO_LOCK));
  }, []);

  const showsItems = isItemList(view);

  const refresh = useCallback(async () => {
    if (!isItemList(view)) return;

    try {
      const [nextItems, nextCounts, nextHealth] = await Promise.all([
        view.kind === "recent"
          ? recentItems(30)
          : listItems({
              query,
              kind: view.kind === "type" ? view.itemKind : undefined,
              withTotp: view.kind === "authenticator" ? true : undefined,
            }),
        vaultCounts(),
        vaultHealth(),
      ]);

      setItems(nextItems);
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

  // Agent requests arrive from the broker at any moment. They queue rather than
  // replace one another, so a second request cannot displace a prompt the user
  // is halfway through reading.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    void (async () => {
      try {
        const { listen } = await import("@tauri-apps/api/event");
        const stop = await listen<ApprovalPrompt>("broker://approval", (event) => {
          setApprovals((queue) => [...queue, event.payload]);
        });
        if (cancelled) stop();
        else unlisten = stop;
      } catch {
        // Outside Tauri there is no broker to listen to.
      }
    })();

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey)) return;
      const key = event.key.toLowerCase();
      if (key === "k") {
        event.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
      if (key === "l") {
        event.preventDefault();
        lock();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [lock]);

  const selected = useMemo(
    () => items.find((item) => item.id === selectedId) ?? null,
    [items, selectedId],
  );

  const searching = query.trim().length > 0;

  return (
    <div className="app" data-wide={!showsItems || undefined}>
      <Sidebar
        view={view}
        counts={counts}
        lockRemainingMs={lockRemaining}
        autoLockSeconds={autoLock}
        onChangeAutoLock={(seconds) => {
          setAutoLock(seconds);
          void setAutoLockSeconds(seconds);
        }}
        onSelect={(next) => {
          setView(next);
          setQuery("");
          setSelectedId(null);
        }}
        onLock={lock}
      />

      {showsItems ? (
        <>
          <div className="list-column">
            <header className="column__toolbar">
              <h1 className="column__title">
                {searching ? "Search" : viewTitle(view)}
              </h1>
              <button
                type="button"
                className="icon-button icon-button--bordered"
                aria-label="New item"
                onClick={() => setCreating(true)}
              >
                <Icon name="plus" size={14} />
              </button>
            </header>

            <div className="list-column__search">
              <div className="field">
                <Icon name="search" size={13} />
                <input
                  ref={searchRef}
                  className="field__input"
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
                {searching ? (
                  <button
                    type="button"
                    className="icon-button icon-button--tiny"
                    onClick={() => setQuery("")}
                    aria-label="Clear search"
                  >
                    <Icon name="close" size={11} />
                  </button>
                ) : (
                  <kbd className="kbd">Ctrl K</kbd>
                )}
              </div>
            </div>

            <div className="list-column__items">
              {error && (
                <p className="notice notice--loud">
                  <Icon name="alert" size={13} />
                  {error}
                </p>
              )}

              <UpdateNotice />

              {view.kind === "authenticator" && !searching && (
                <ImportPanel onImported={() => void refresh()} />
              )}

              {view.kind === "subscriptions" ? (
                <SubscriptionsView onSelect={setSelectedId} />
              ) : items.length === 0 ? (
                <p className="empty">
                  {searching ? "Nothing matches that." : "Nothing here yet."}
                </p>
              ) : (
                <ul className="rows">
                  {items.map((item) => (
                    <ItemRow
                      key={item.id}
                      item={item}
                      selected={item.id === selectedId}
                      onSelect={setSelectedId}
                    />
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="detail-column">
            {selected ? (
              <ItemDetail
                item={selected}
                health={health}
                onChanged={() => {
                  setSelectedId(null);
                  void refresh();
                }}
              />
            ) : (
              <p className="empty empty--centred">
                {viewSubtitle(view, counts) || "Select an item"}
              </p>
            )}
          </div>
        </>
      ) : (
        <div className="wide-column">
          <header className="column__toolbar">
            <div>
              <h1 className="column__title">{viewTitle(view)}</h1>
              <p className="column__sub">{viewSubtitle(view, counts)}</p>
            </div>
          </header>
          <div className="wide-column__body">
            {view.kind === "agents" ? <AgentAccess /> : <SyncView />}
          </div>
        </div>
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

      {/* Drawn last so it sits above everything: an agent is blocked waiting
          on this answer, and it must not end up behind another dialog. */}
      {approvals.length > 0 && (
        <ApprovalDialog
          key={approvals[0].id}
          prompt={approvals[0]}
          onSettled={() => setApprovals((queue) => queue.slice(1))}
        />
      )}
    </div>
  );
}
