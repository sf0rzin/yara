import { useState, type JSX } from "react";
import { formatCountdown } from "../lib/useAutoLock";
import { AutoLockMenu } from "./AutoLockMenu";
import { Icon, type IconName } from "./Icon";
import type { View } from "../views";

interface NavEntry {
  view: View;
  label: string;
  icon: IconName;
}

interface SidebarProps {
  view: View;
  lockRemainingMs: number;
  autoLockSeconds: number | null;
  onSelect: (view: View) => void;
  onChangeAutoLock: (seconds: number | null) => void;
  onLock: () => void;
}

function isSameView(a: View, b: View): boolean {
  return (
    a.kind === b.kind &&
    ("itemKind" in a ? a.itemKind : null) === ("itemKind" in b ? b.itemKind : null)
  );
}

export function Sidebar({
  view,
  lockRemainingMs,
  autoLockSeconds,
  onSelect,
  onChangeAutoLock,
  onLock,
}: SidebarProps): JSX.Element {
  const [menuOpen, setMenuOpen] = useState(false);
  // Collections are ways of looking at the vault. Subscriptions sits here
  // rather than under Types because a subscription is an attachment on a
  // login, not a kind of item — a charge with no account behind it is trivia.
  //
  // Agent access is here for the same reason. It is a way of looking at the
  // vault — which credentials programs can reach — and it used to carry a
  // heading of its own, which meant a group label introducing exactly one row.
  // A heading that groups one thing is not grouping.
  const collections: NavEntry[] = [
    { view: { kind: "all" }, label: "All items", icon: "allItems" },
    { view: { kind: "recent" }, label: "Recent", icon: "recent" },
    { view: { kind: "subscriptions" }, label: "Subscriptions", icon: "calendar" },
    { view: { kind: "agents" }, label: "Agent access", icon: "sparkle" },
  ];

  const types: NavEntry[] = [
    {
      view: { kind: "type", itemKind: "login" },
      label: "Logins",
      icon: "login",
    },
    {
      view: { kind: "type", itemKind: "card" },
      label: "Cards",
      icon: "card",
    },
    {
      view: { kind: "type", itemKind: "note" },
      label: "Notes",
      icon: "note",
    },
    {
      view: { kind: "authenticator" },
      label: "Authenticator",
      icon: "authenticator",
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
          title={entry.label}
          onClick={() => onSelect(entry.view)}
        >
          <Icon name={entry.icon} size={16} />
          <span className="nav-item__label">{entry.label}</span>
        </button>
      </li>
    );
  };

  return (
    <aside className="sidebar">
      <div className="sidebar__brand">
        <span className="sidebar__name" aria-label="yara">yara</span>
      </div>

      <nav className="sidebar__nav">
        <p className="section-label">Collections</p>
        <ul>{collections.map(renderEntry)}</ul>

        <p className="section-label section-label--spaced">Types</p>
        <ul>{types.map(renderEntry)}</ul>
      </nav>

      {/*
        States what is true now — unlocked — and what happens next, rather than
        naming the vault twice. The countdown is the only moving thing in the
        sidebar, so it earns its place by being the one fact that changes.
      */}
      <div className="sidebar__footer-anchor">
        {menuOpen && (
          <AutoLockMenu
            current={autoLockSeconds}
            onChoose={(seconds) => {
              onChangeAutoLock(seconds);
              setMenuOpen(false);
            }}
            onLockNow={() => {
              setMenuOpen(false);
              onLock();
            }}
            onDismiss={() => setMenuOpen(false)}
          />
        )}

        <button
          type="button"
          className="sidebar__utility"
          data-active={view.kind === "sync" || undefined}
          aria-current={view.kind === "sync" ? "page" : undefined}
          title="Sync & settings"
          onClick={() => onSelect({ kind: "sync" })}
        >
          <Icon name="sync" size={15} />
          <span>Sync &amp; settings</span>
        </button>

        <button
          type="button"
          className="sidebar__footer"
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <span className="sidebar__footer-tile" aria-hidden="true">
            <Icon name="lock" size={14} />
          </span>
          <span className="sidebar__footer-text">
            <span className="sidebar__footer-title">Unlocked</span>
            <span className="sidebar__footer-sub">
              {autoLockSeconds === null
                ? "Until you lock it"
                : `Locks in ${formatCountdown(lockRemainingMs)}`}
            </span>
          </span>
        </button>
      </div>
    </aside>
  );
}
