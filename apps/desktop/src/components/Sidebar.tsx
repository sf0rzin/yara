import type { JSX } from "react";
import type { VaultCounts } from "../api";
import { formatCountdown } from "../lib/useAutoLock";
import { Icon, type IconName } from "./Icon";
import type { View } from "../views";

interface NavEntry {
  view: View;
  label: string;
  icon: IconName;
  count?: number;
}

interface SidebarProps {
  view: View;
  counts: VaultCounts | null;
  lockRemainingMs: number;
  onSelect: (view: View) => void;
  onFocusSearch: () => void;
  onLock: () => void;
}

function isSameView(a: View, b: View): boolean {
  return a.kind === b.kind && ("itemKind" in a ? a.itemKind : null) ===
    ("itemKind" in b ? b.itemKind : null);
}

export function Sidebar({
  view,
  counts,
  lockRemainingMs,
  onSelect,
  onFocusSearch,
  onLock,
}: SidebarProps): JSX.Element {
  const collections: NavEntry[] = [
    { view: { kind: "all" }, label: "All items", icon: "allItems" },
    { view: { kind: "recent" }, label: "Recent", icon: "recent" },
    { view: { kind: "security" }, label: "Security", icon: "security" },
    { view: { kind: "agents" }, label: "Agent access", icon: "sparkle" },
    { view: { kind: "sync" }, label: "Sync", icon: "download" },
  ];

  const types: NavEntry[] = [
    {
      view: { kind: "type", itemKind: "login" },
      label: "Logins",
      icon: "login",
      count: counts?.logins,
    },
    {
      view: { kind: "type", itemKind: "card" },
      label: "Cards",
      icon: "card",
      count: counts?.cards,
    },
    {
      view: { kind: "type", itemKind: "note" },
      label: "Notes",
      icon: "note",
      count: counts?.notes,
    },
    {
      view: { kind: "authenticator" },
      label: "Authenticator",
      icon: "authenticator",
      count: counts?.authenticator,
    },
  ];

  const renderEntry = (entry: NavEntry) => {
    const active = isSameView(view, entry.view);
    return (
      <li key={entry.label}>
        <button
          type="button"
          className="nav-item"
          data-active={active || undefined}
          aria-current={active ? "page" : undefined}
          onClick={() => onSelect(entry.view)}
        >
          <Icon name={entry.icon} size={15} />
          <span className="nav-item__label">{entry.label}</span>
          {entry.count !== undefined && (
            <span className="nav-item__count">{entry.count}</span>
          )}
        </button>
      </li>
    );
  };

  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__name">yara</span>
        <span className="sidebar__tagline">Password Vault</span>
      </div>

      <button type="button" className="sidebar__search" onClick={onFocusSearch}>
        <kbd className="kbd">Ctrl K</kbd>
        <span>Search</span>
      </button>

      <nav className="sidebar__nav">
        <p className="section-label">Collections</p>
        <ul>{collections.map(renderEntry)}</ul>

        <p className="section-label section-label--spaced">Types</p>
        <ul>{types.map(renderEntry)}</ul>
      </nav>

      <button type="button" className="sidebar__footer" onClick={onLock}>
        <span className="avatar" aria-hidden="true">
          <Icon name="lock" size={13} />
        </span>
        <span className="sidebar__footer-text">
          <span className="sidebar__footer-title">Local vault</span>
          <span className="sidebar__footer-sub">
            Locks in {formatCountdown(lockRemainingMs)}
          </span>
        </span>
      </button>
    </aside>
  );
}
