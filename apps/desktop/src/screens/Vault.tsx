import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import {
  autoLockSeconds as readAutoLock,
  createFolder,
  deleteFolder,
  deleteItem,
  errorMessage,
  folders as listFolders,
  listItems,
  lockVault,
  recentItems,
  renameFolder,
  reorderFolders,
  reorderItems,
  setAutoLockSeconds,
  setItemFolder,
  vaultCounts,
  type ItemSummary,
  type VaultCounts,
} from "../api";
import type { ApprovalPrompt } from "../api";
import { AgentAccess } from "../components/AgentAccess";
import { ApprovalDialog } from "../components/ApprovalDialog";
import { AuthenticatorGrid } from "../components/AuthenticatorGrid";
import { CommandPalette } from "../components/CommandPalette";
import { Icon } from "../components/Icon";
import { ImportDialog } from "../components/ImportPanel";
import { ItemDetail } from "../components/ItemDetail";
import { ItemRow } from "../components/ItemRow";
import { NewItemDialog } from "../components/NewItemDialog";
import { Sidebar } from "../components/Sidebar";
import { SubscriptionsView } from "../components/SubscriptionsView";
import { SyncView } from "../components/SyncView";
import { UpdateNotice } from "../components/UpdateNotice";
import { useAutoLock } from "../lib/useAutoLock";
import { useItemDrag, type RowTarget } from "../lib/useItemDrag";
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
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [palette, setPalette] = useState(false);
  /*
   * Scoped to the Authenticator grid, which is the one screen that still
   * filters in place. Codes are read at a glance and copied in seconds, so
   * narrowing the grid you are looking at beats opening a layer over it — and
   * unlike the item list, that grid has nowhere else to send you.
   */
  const [authQuery, setAuthQuery] = useState("");
  const [counts, setCounts] = useState<VaultCounts | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [editingItem, setEditingItem] = useState<ItemSummary | null>(null);
  const [importing, setImporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [approvals, setApprovals] = useState<ApprovalPrompt[]>([]);
  const [autoLock, setAutoLock] = useState<number | null>(FALLBACK_AUTO_LOCK);
  const [loading, setLoading] = useState(true);
  const [showLoading, setShowLoading] = useState(false);
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [folderNames, setFolderNames] = useState<string[]>([]);
  const [compactDetailOpen, setCompactDetailOpen] = useState(false);


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
              query: view.kind === "authenticator" ? authQuery : undefined,
              kind: view.kind === "type" ? view.itemKind : undefined,
              withTotp: view.kind === "authenticator" ? true : undefined,
              folder: view.kind === "folder" ? view.name : undefined,
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
  }, [authQuery, view]);

  const refreshFolders = useCallback(async () => {
    try {
      setFolderNames(await listFolders());
    } catch {
      // A vault that cannot list folders still lists items; the sidebar just
      // shows none rather than the whole screen failing.
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    void refreshFolders();
  }, [refreshFolders]);

  /*
   * Deliberately not memoised. The hook stores these in a ref it rewrites
   * every render, so a fresh closure each time costs nothing — and memoising
   * on an empty dependency list would pin `refresh` to the first render,
   * which would reload the wrong view after filing something from a folder.
   */
  const drag = useItemDrag({
    onReorder: dropOnRow,
    onFile: (itemId, folder) => {
      void setItemFolder(itemId, folder)
        .then(refresh)
        .catch((caught) => setError(errorMessage(caught)));
    },
    onMoveFolder: (name, before) => {
      const without = folderNames.filter((f) => f !== name);
      const at = without.indexOf(before);
      const next = [...without.slice(0, at), name, ...without.slice(at)];
      // Applied locally first: a folder that snaps back while the write lands
      // reads as the drag having failed.
      setFolderNames(next);
      void reorderFolders(next).catch((caught) => {
        setError(errorMessage(caught));
        void refreshFolders();
      });
    },
  });

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
      const key = event.key.toLowerCase();
      const target = event.target;
      const isTyping =
        target instanceof HTMLElement &&
        (target.matches("input, textarea, select") || target.isContentEditable);

      if (key === "/" && !isTyping && !event.ctrlKey && !event.metaKey) {
        event.preventDefault();
        setPalette(true);
        return;
      }

      if (!(event.ctrlKey || event.metaKey)) return;
      if (key === "k") {
        // Ctrl+K works while typing, unlike "/", which would otherwise be
        // impossible to put in a password field.
        event.preventDefault();
        setPalette(true);
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
      if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;

      // Narrowed with `instanceof` rather than cast and optional-chained: a
      // keydown target is an element by convention, not by type, and `matches`
      // does not exist on anything that is not one. The cast said otherwise and
      // `?.` only guards null, so a listener bound to the window threw on any
      // event dispatched at the window itself.
      const target = event.target;
      if (
        target instanceof HTMLElement &&
        (target.matches("input, textarea, select") || target.isContentEditable)
      ) {
        return;
      }

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

  useEffect(() => {
    const closeCompactDetail = (event: KeyboardEvent) => {
      if (event.key === "Escape") setCompactDetailOpen(false);
    };
    window.addEventListener("keydown", closeCompactDetail);
    return () => window.removeEventListener("keydown", closeCompactDetail);
  }, []);

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

  /**
   * Lands a dragged row next to the one it was dropped on.
   *
   * The whole list is sent, not just the pair that moved. The vault stores
   * order as the order of its items, so "put A after B" only means something
   * once expressed as a sequence — and sending the sequence the user is
   * looking at means the result is what they saw, even when the view is
   * filtered to a folder.
   */
  function dropOnRow(source: string, { id: targetId, edge }: RowTarget) {
    if (source === targetId) return;

    const without = items.filter((item) => item.id !== source).map((item) => item.id);
    const at = without.indexOf(targetId);
    if (at < 0) return;

    const next = [
      ...without.slice(0, edge === "above" ? at : at + 1),
      source,
      ...without.slice(edge === "above" ? at : at + 1),
    ];

    // Reordered on screen first. A row that snaps back while the write lands
    // reads as the drag having failed.
    setItems((current) =>
      next
        .map((id) => current.find((item) => item.id === id))
        .filter((item): item is ItemSummary => item !== undefined),
    );

    void reorderItems(next).catch((caught) => {
      setError(errorMessage(caught));
      void refresh();
    });
  }

  function openContextMenu(item: ItemSummary, x: number, y: number) {
    menuOpenerRef.current = document.activeElement as HTMLElement | null;
    setSelectedId(item.id);

    // Measured rather than assumed. The menu used to be two rows and the
    // clamp was the 52px that took; it now carries a row per folder, and a
    // fixed number would push the bottom of it off the screen the moment a
    // third folder existed.
    const rows = 2 + folderNames.length + 1;
    const height = 8 + rows * 30 + 2 * 9 + 27;

    setContextMenu({
      item,
      x: Math.max(8, Math.min(x, window.innerWidth - 228)),
      y: Math.max(8, Math.min(y, window.innerHeight - height - 8)),
      confirming: false,
    });
  }

  /**
   * Files the item the menu was opened on.
   *
   * Closes first. The menu shows the folder the item is in, so leaving it open
   * would mean watching the tick move — which reads as a control you are still
   * operating rather than one that has done its job.
   */
  function moveContextItem(folder: string | null) {
    const item = contextMenu?.item;
    setContextMenu(null);
    if (!item || item.folder === folder) return;

    void setItemFolder(item.id, folder)
      .then(refresh)
      .catch((caught) => setError(errorMessage(caught)));
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

  const listMeta = loading ? "Updating…" : viewSubtitle(view, counts);

  return (
    <div
      className="app"
      data-wide={!showsItems || undefined}
      data-detail-open={compactDetailOpen || undefined}
    >
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
          // Leaving the Authenticator drops its filter, so coming back to it
          // does not silently hide most of the grid.
          setAuthQuery("");
          setSelectedId(null);
          setCompactDetailOpen(false);
        }}
        onLock={lock}
        folders={folderNames}
        onCreateFolder={(name) => {
          void createFolder(name)
            .then(refreshFolders)
            .catch((caught) => setError(errorMessage(caught)));
        }}
        onRenameFolder={(from, to) => {
          void renameFolder(from, to)
            .then(async () => {
              await refreshFolders();
              // The open view names the folder it is showing, so it has to
              // follow the rename or it points at something gone.
              if (view.kind === "folder" && view.name === from) {
                setView({ kind: "folder", name: to });
              }
              await refresh();
            })
            .catch((caught) => setError(errorMessage(caught)));
        }}
        onDeleteFolder={(name) => {
          void deleteFolder(name)
            .then(async () => {
              await refreshFolders();
              setView({ kind: "all" });
            })
            .catch((caught) => setError(errorMessage(caught)));
        }}
        dropTarget={drag.state.overFolder}
        onFolderDragBegin={drag.beginFolder}
      />

      {view.kind === "authenticator" ? (
        <AuthenticatorGrid
          items={items}
          query={authQuery}
          loading={loading}
          error={error}
          onQueryChange={setAuthQuery}
          onNew={() => setCreating(true)}
          onImport={() => setImporting(true)}
          onContextMenu={openContextMenu}
        />
      ) : showsItems ? (
        <>
          <div className="list-column">
            <header className="column__toolbar">
              <div className="column__heading">
                <h1 className="column__title">{viewTitle(view)}</h1>
                <p className="column__sub" aria-live="polite">{listMeta}</p>
              </div>
            </header>

            {/*
              The slot the search field used to hold. A button that fills the
              top of the list reads as belonging to it, which the old one — a
              hundred pixels short of the far edge, floating over the detail
              pane — never did.
            */}
            <div className="list-column__action">
              <button
                type="button"
                className="button button--primary vault-new-button"
                onClick={() => setCreating(true)}
              >
                <Icon name="plus" size={14} />
                <span>New item</span>
              </button>
            </div>

            <div className="list-column__items" aria-busy={loading}>
              {error && (
                <p className="notice notice--loud">
                  <Icon name="alert" size={13} />
                  {error}
                </p>
              )}

              <UpdateNotice />

              {view.kind === "subscriptions" ? (
                <SubscriptionsView onSelect={setSelectedId} />
              ) : loading ? (
                showLoading ? <ListSkeleton /> : <div className="list-wait" aria-hidden="true" />
              ) : items.length === 0 ? (
                <p className="empty">{emptyMessage(view)}</p>
              ) : (
                <ul className="rows">
                  {items.map((item) => (
                    <ItemRow
                      key={item.id}
                      item={item}
                      selected={item.id === selectedId}
                      dropEdge={
                        drag.state.overRow?.id === item.id
                          ? drag.state.overRow.edge
                          : undefined
                      }
                      lifted={drag.state.itemId === item.id}
                      onSelect={(id) => {
                        // A pointerup after moving still produces a click.
                        // Selecting the row you just filed elsewhere is not
                        // what was asked for.
                        if (drag.swallowClick()) return;
                        setSelectedId(id);
                        setCompactDetailOpen(true);
                      }}
                      onContextMenu={openContextMenu}
                      onDragBegin={drag.begin}
                    />
                  ))}
                </ul>
              )}
            </div>
          </div>

          <div className="detail-column">
            <button
              type="button"
              className="compact-detail-back"
              onClick={() => setCompactDetailOpen(false)}
            >
              <Icon name="chevronRight" size={13} />
              <span>Back to items</span>
            </button>
            {selected ? (
              <ItemDetail item={selected} />
            ) : (
              <EmptyState
                centred
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
            {view.kind === "agents" ? (
              <AgentAccess />
            ) : view.kind === "activity" ? (
              <AgentAccess historyOnly />
            ) : (
              <SyncView />
            )}
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
            {/* Edit takes the focus, not delete. The menu opens under the
                cursor and Enter is a reflex; the destructive row should not be
                the one already selected when it arrives. */}
            <button
              type="button"
              ref={menuItemRef}
              className="popover__item"
              role="menuitem"
              onClick={() => {
                setEditingItem(contextMenu.item);
                setContextMenu(null);
              }}
            >
              <Icon name="pencil" size={13} />
              <span>Edit…</span>
            </button>

            <div className="popover__separator" />

            {/*
              Filing without dragging. A drag needs both ends on screen at
              once, and a list scrolled past the folder it is going to leaves
              no way to aim — which is most of the time once the vault grows.

              The tick marks where the item is now, so the menu reads as the
              item's state rather than as a list of destinations.
            */}
            <p className="section-label">Move to</p>
            <div className="popover__options">
              {folderNames.map((folder) => (
                <button
                  key={folder}
                  type="button"
                  className="popover__item"
                  role="menuitemradio"
                  aria-checked={contextMenu.item.folder === folder}
                  data-chosen={contextMenu.item.folder === folder || undefined}
                  onClick={() => moveContextItem(folder)}
                >
                  <span className="popover__check" aria-hidden="true">
                    {contextMenu.item.folder === folder && <Icon name="check" size={11} />}
                  </span>
                  <span className="popover__label">{folder}</span>
                </button>
              ))}

              <button
                type="button"
                className="popover__item"
                role="menuitemradio"
                aria-checked={contextMenu.item.folder === null}
                data-chosen={contextMenu.item.folder === null || undefined}
                onClick={() => moveContextItem(null)}
              >
                <span className="popover__check" aria-hidden="true">
                  {contextMenu.item.folder === null && <Icon name="check" size={11} />}
                </span>
                <span className="popover__label">No folder</span>
              </button>
            </div>

            <div className="popover__separator" />

            <button
              type="button"
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

      {importing && (
        <ImportDialog
          onClose={() => setImporting(false)}
          onImported={() => void refresh()}
        />
      )}

      {editingItem && (
        <NewItemDialog
          key={editingItem.id}
          editing={editingItem}
          onClose={() => setEditingItem(null)}
          onCreated={(id) => {
            setEditingItem(null);
            setSelectedId(id);
            void refresh();
          }}
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

      {palette && (
        <CommandPalette
          onDismiss={() => setPalette(false)}
          onSelect={(item) => {
            // Land where the item actually is. Selecting a login while the
            // Cards collection is open would otherwise highlight an id the
            // visible list does not contain, and the detail pane would be the
            // only thing that moved.
            setView({ kind: "all" });
            setSelectedId(item.id);
            setCompactDetailOpen(true);
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
  title,
  body,
  action,
  centred,
  onAction,
}: {
  title: string;
  body: string;
  action?: string;
  centred?: boolean;
  onAction?: () => void;
}): JSX.Element {
  return (
    <div className="empty-state" data-centred={centred || undefined}>
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

function emptyMessage(view: View): string {
  if (view.kind === "all") return "No items yet. Use New item above when you're ready.";
  if (view.kind === "recent") return "No recently updated items yet.";
  if (view.kind === "type") return `No ${viewTitle(view).toLowerCase()} here yet.`;
  if (view.kind === "folder") return "Nothing has been added to this folder yet.";
  return "Nothing here yet.";
}
