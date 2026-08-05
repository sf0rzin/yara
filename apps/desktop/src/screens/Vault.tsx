import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import {
  autoLockSeconds as readAutoLock,
  deleteItem,
  errorMessage,
  listItems,
  lockVault,
  recentItems,
  setAutoLockSeconds,
  vaultCounts,
  type ItemSummary,
  type VaultCounts,
} from "../api";
import type { ApprovalPrompt } from "../api";
import { AgentAccess } from "../components/AgentAccess";
import { ApprovalDialog } from "../components/ApprovalDialog";
import { Icon, type IconName } from "../components/Icon";
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

interface ContextMenuState {
  item: ItemSummary;
  x: number;
  y: number;
  confirming: boolean;
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
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ApprovalPrompt[]>([]);
  const [autoLock, setAutoLock] = useState<number | null>(FALLBACK_AUTO_LOCK);
  const [loading, setLoading] = useState(true);
  const [showLoading, setShowLoading] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);

  const searchRef = useRef<HTMLInputElement>(null);
  const requestRef = useRef(0);
  const menuOpenerRef = useRef<HTMLElement | null>(null);
  const menuItemRef = useRef<HTMLButtonElement>(null);

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

    const request = ++requestRef.current;
    setLoading(true);

    try {
      const [nextItems, nextCounts] = await Promise.all([
        view.kind === "recent"
          ? recentItems(30)
          : listItems({
              query,
              kind: view.kind === "type" ? view.itemKind : undefined,
              withTotp: view.kind === "authenticator" ? true : undefined,
            }),
        vaultCounts(),
      ]);

      if (request === requestRef.current) {
        setItems(nextItems);
        setCounts(nextCounts);
        setError(null);
      }
    } catch (caught) {
      if (request === requestRef.current) setError(errorMessage(caught));
    } finally {
      if (request === requestRef.current) setLoading(false);
    }
  }, [query, view]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!loading) {
      setShowLoading(false);
      return;
    }
    const timer = setTimeout(() => setShowLoading(true), 120);
    return () => clearTimeout(timer);
  }, [loading]);

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

  useEffect(() => {
    const onArrow = (event: KeyboardEvent) => {
      if (!showsItems || view.kind === "subscriptions" || items.length === 0) return;
      const target = event.target as HTMLElement | null;
      if (
        target?.matches("input, textarea, select") ||
        target?.isContentEditable
      ) {
        return;
      }
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;

      event.preventDefault();
      const current = items.findIndex((item) => item.id === selectedId);
      const next = event.key === "ArrowDown"
        ? Math.min(current + 1, items.length - 1)
        : Math.max(current < 0 ? 0 : current - 1, 0);
      setSelectedId(items[next].id);
    };
    window.addEventListener("keydown", onArrow);
    return () => window.removeEventListener("keydown", onArrow);
  }, [items, selectedId, showsItems, view.kind]);

  const selected = useMemo(
    () =>
      items.find((item) => item.id === selectedId) ??
      (!loading && view.kind !== "subscriptions" ? items[0] ?? null : null),
    [items, loading, selectedId, view.kind],
  );

  // Keep the three-column geometry stable: a populated collection always has
  // a detail to show. Searches preserve the current item when it still
  // matches; otherwise the first result becomes the new comparison anchor.
  useEffect(() => {
    if (loading || view.kind === "subscriptions") return;

    if (items.length === 0) {
      if (selectedId !== null) setSelectedId(null);
      return;
    }

    if (!items.some((item) => item.id === selectedId)) {
      setSelectedId(items[0].id);
    }
  }, [items, loading, selectedId, view.kind]);

  // Dismissing without choosing hands focus back to the row. The menu takes
  // focus when it opens, so closing it any other way drops a keyboard user at
  // the top of the document, having lost their place in the list.
  const closeContextMenu = useCallback(() => {
    setContextMenu(null);
    menuOpenerRef.current?.focus();
    menuOpenerRef.current = null;
  }, []);

  useEffect(() => {
    if (contextMenu === null) return;

    // Focused here rather than with `autoFocus`, which React does not apply to
    // an element mounted after the first render — verified in the browser, the
    // menu was opening with focus left behind on the row. A menu raised from
    // the keyboard that cannot then be operated from the keyboard is worse
    // than no menu at all.
    menuItemRef.current?.focus();

    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeContextMenu();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeContextMenu, contextMenu]);

  function openContextMenu(item: ItemSummary, x: number, y: number) {
    menuOpenerRef.current = document.activeElement as HTMLElement | null;
    setSelectedId(item.id);
    setContextMenu({
      item,
      x: Math.max(8, Math.min(x, window.innerWidth - 228)),
      y: Math.max(8, Math.min(y, window.innerHeight - 52)),
      confirming: false,
    });
  }

  async function removeContextItem() {
    if (contextMenu === null) return;
    if (!contextMenu.confirming) {
      setContextMenu({ ...contextMenu, confirming: true });
      return;
    }

    try {
      await deleteItem(contextMenu.item.id);
      // Not closeContextMenu: the row that opened this no longer exists, so
      // there is nothing to hand focus back to.
      setContextMenu(null);
      menuOpenerRef.current = null;
      setSelectedId(null);
      await refresh();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  const searching = query.trim().length > 0;
  const listMeta = loading
    ? "Updating…"
    : searching
      ? `${items.length} ${items.length === 1 ? "result" : "results"}`
      : viewSubtitle(view, counts);

  return (
    <div className="app" data-wide={!showsItems || undefined}>
      <Sidebar
        view={view}
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
              <div className="column__heading">
                <h1 className="column__title">
                  {searching ? "Search" : viewTitle(view)}
                </h1>
                <p className="column__sub" aria-live="polite">{listMeta}</p>
              </div>
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

            <div className="list-column__items" aria-busy={loading}>
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
              ) : loading ? (
                showLoading ? <ListSkeleton /> : <div className="list-wait" aria-hidden="true" />
              ) : items.length === 0 ? (
                <EmptyState
                  icon={searching ? "search" : "key"}
                  title={searching ? `No items match “${query.trim()}”` : emptyTitle(view)}
                  body={searching
                    ? "Try another name, account or website."
                    : "Add the first item to make this view useful."}
                  action={searching ? "Clear search" : "New item"}
                  onAction={() => searching ? setQuery("") : setCreating(true)}
                />
              ) : (
                <ul className="rows">
                  {items.map((item) => (
                    <ItemRow
                      key={item.id}
                      item={item}
                      selected={item.id === selectedId}
                      showTotpCode={view.kind === "authenticator"}
                      onSelect={setSelectedId}
                      onContextMenu={openContextMenu}
                    />
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="detail-column">
            {selected ? (
              <ItemDetail item={selected} />
            ) : (
              <EmptyState
                centred
                icon="allItems"
                title="Select an item"
                body="View its credentials here. Use ↑ and ↓ to compare without leaving the keyboard."
              />
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

      {contextMenu && (
        <div
          className="context-menu-layer"
          role="presentation"
          onPointerDown={closeContextMenu}
          onContextMenu={(event) => event.preventDefault()}
        >
          <div
            className="context-menu"
            role="menu"
            style={{ left: contextMenu.x, top: contextMenu.y }}
            onPointerDown={(event) => event.stopPropagation()}
          >
            <button
              type="button"
              ref={menuItemRef}
              className="popover__item"
              role="menuitem"
              onClick={() => void removeContextItem()}
            >
              <Icon name="trash" size={13} />
              <span>
                {contextMenu.confirming
                  ? `Delete ${contextMenu.item.name} for good`
                  : "Delete item…"}
              </span>
            </button>
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
          queueLength={approvals.length}
          onSettled={() => setApprovals((queue) => queue.slice(1))}
        />
      )}
    </div>
  );
}

function ListSkeleton(): JSX.Element {
  return (
    <div className="skeleton-list" aria-hidden="true">
      {[0, 1, 2, 3, 4].map((row) => (
        <div className="skeleton-row" key={row}>
          <span className="skeleton-row__tile" />
          <span className="skeleton-row__copy">
            <span className="skeleton-row__name" />
            <span className="skeleton-row__sub" />
          </span>
        </div>
      ))}
    </div>
  );
}

function EmptyState({
  icon,
  title,
  body,
  action,
  centred,
  onAction,
}: {
  icon: IconName;
  title: string;
  body: string;
  action?: string;
  centred?: boolean;
  onAction?: () => void;
}): JSX.Element {
  return (
    <div className="empty-state" data-centred={centred || undefined}>
      <span className="empty-state__mark" aria-hidden="true">
        <Icon name={icon} size={17} />
      </span>
      <h2 className="empty-state__title">{title}</h2>
      <p className="empty-state__body">{body}</p>
      {action && onAction && (
        <button type="button" className="button button--outline" onClick={onAction}>
          {action}
        </button>
      )}
    </div>
  );
}

function emptyTitle(view: View): string {
  if (view.kind === "all") return "Your vault is empty";
  if (view.kind === "authenticator") return "No authenticator codes yet";
  if (view.kind === "recent") return "No recent items yet";
  if (view.kind === "type") return `No ${viewTitle(view).toLowerCase()} yet`;
  return "Nothing here yet";
}
