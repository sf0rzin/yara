import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from "react";
import {
  errorMessage,
  listGrants,
  listItems,
  lockVault,
  recentItems,
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
import { SecurityView } from "../components/SecurityView";
import { Sidebar } from "../components/Sidebar";
import { SyncView } from "../components/SyncView";
import { UpdateNotice } from "../components/UpdateNotice";
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
  const [approvals, setApprovals] = useState<ApprovalPrompt[]>([]);
  const [grantCount, setGrantCount] = useState(0);

  const searchRef = useRef<HTMLInputElement>(null);

  const lock = useCallback(() => {
    void lockVault();
    onLock();
  }, [onLock]);

  const lockRemaining = useAutoLock(AUTO_LOCK_MS, lock);

  const refresh = useCallback(async () => {
    try {
      // Grants are fetched separately: failing to reach the broker should not
      // stop the vault from rendering.
      listGrants()
        .then((grants) => setGrantCount(grants.length))
        .catch(() => setGrantCount(0));

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

        {/* Only ever rendered behind the unlock screen: an update prompt is
            not something to answer before you have proven you own the vault. */}
        <UpdateNotice />

        <div className="main__body">
          {view.kind === "agents" ? (
            <AgentAccess />
          ) : view.kind === "sync" ? (
            <SyncView />
          ) : view.kind === "security" ? (
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
              grantCount={grantCount}
              selectedId={selectedId}
              onSelect={setSelectedId}
              onOpenSecurity={() => setView({ kind: "security" })}
              onOpenAgents={() => setView({ kind: "agents" })}
            />
          ) : (
            <>
              {/* Only on the authenticator screen: this brings in codes, and
                  offering it beside a list of cards would be noise. */}
              {view.kind === "authenticator" && !searching && (
                <ImportPanel onImported={() => void refresh()} />
              )}
              <ItemList
                items={items}
                selectedId={selectedId}
                onSelect={setSelectedId}
                emptyMessage={
                  searching ? "Nothing matches that." : "Nothing here yet."
                }
              />
            </>
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

function Overview({
  recent,
  health,
  grantCount,
  selectedId,
  onSelect,
  onOpenSecurity,
  onOpenAgents,
}: {
  recent: ItemSummary[];
  health: VaultHealth | null;
  grantCount: number;
  selectedId: string | null;
  onSelect: (id: string) => void;
  onOpenSecurity: () => void;
  onOpenAgents: () => void;
}): JSX.Element {
  const clean = health !== null && isClean(health);
  const affected = health ? affectedItemCount(health) : 0;

  const agentSummary =
    grantCount === 0
      ? "No program currently holds permission to use anything."
      : `${grantCount} active permission${grantCount === 1 ? "" : "s"}.`;

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

          <button type="button" className="card" onClick={onOpenAgents}>
            <span className="card__head">
              <Icon name="sparkle" size={15} />
              Agent access
            </span>
            <span className="card__body">
              {agentSummary}
            </span>
            <span className="card__action">Manage permissions</span>
          </button>
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
