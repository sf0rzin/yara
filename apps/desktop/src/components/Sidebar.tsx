import { useCallback, useRef, useState, type JSX } from "react";
import { formatCountdown } from "../lib/useAutoLock";
import type { View } from "../views";
import { AutoLockMenu } from "./AutoLockMenu";
import { Icon, type IconName } from "./Icon";
import { YaraLogo } from "./YaraLogo";

interface NavEntry {
  view: View;
  label: string;
  icon: IconName;
}

interface SidebarProps {
  view: View;
  lockRemainingMs: number;
  autoLockSeconds: number | null;
  folders: string[];
  onSelect: (view: View) => void;
  onChangeAutoLock: (seconds: number | null) => void;
  onLock: () => void;
  onCreateFolder: (name: string) => void;
  onRenameFolder: (from: string, to: string) => void;
  onDeleteFolder: (name: string) => void;
  dropTarget: { name: string | null } | null;
  onFolderDragBegin: (name: string, event: React.PointerEvent) => void;
}

const PRIMARY: NavEntry[] = [
  { view: { kind: "all" }, label: "All items", icon: "allItems" },
  { view: { kind: "authenticator" }, label: "Authenticator", icon: "authenticator" },
  { view: { kind: "agents" }, label: "AI access", icon: "sparkle" },
  { view: { kind: "activity" }, label: "Activity", icon: "recent" },
];

const COLLECTIONS: NavEntry[] = [
  { view: { kind: "type", itemKind: "login" }, label: "Logins", icon: "login" },
  { view: { kind: "type", itemKind: "card" }, label: "Cards", icon: "card" },
  { view: { kind: "type", itemKind: "note" }, label: "Secure notes", icon: "note" },
  { view: { kind: "subscriptions" }, label: "Subscriptions", icon: "calendar" },
];

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
  folders,
  onSelect,
  onChangeAutoLock,
  onLock,
  onCreateFolder,
  onRenameFolder,
  onDeleteFolder,
  dropTarget,
  onFolderDragBegin,
}: SidebarProps): JSX.Element {
  const [menuOpen, setMenuOpen] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const menuTriggerRef = useRef<HTMLButtonElement>(null);

  // Closing hands focus back to the button that opened it. The menu takes focus
  // when it opens, so dismissing it any other way would drop a keyboard user at
  // the top of the document — the same rule the item context menu follows.
  const closeMenu = useCallback(() => {
    setMenuOpen(false);
    menuTriggerRef.current?.focus();
  }, []);

  // Written once: the footer button shows this and its accessible name has to
  // contain it, or the name and the label stop agreeing the moment one changes.
  const lockSummary =
    autoLockSeconds === null
      ? "Until you lock it"
      : `Locks in ${formatCountdown(lockRemainingMs)}`;

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
          <Icon name={entry.icon} size={15} />
          <span className="nav-item__label">{entry.label}</span>
        </button>
      </li>
    );
  };

  return (
    <aside className="sidebar">
      <header className="sidebar__brand">
        <span className="sidebar__lockup">
          <YaraLogo className="sidebar__logo" decorative />
          <span className="sidebar__name">yara</span>
        </span>
        <span className="sidebar__vault-switch" aria-hidden="true">
          <Icon name="chevronsUpDown" size={13} />
        </span>
      </header>

      <nav className="sidebar__nav" aria-label="Vault navigation">
        <ul>{PRIMARY.map(renderEntry)}</ul>

        <p className="section-label section-label--spaced">Collections</p>
        <ul>{COLLECTIONS.map(renderEntry)}</ul>

        <>
            <div className="folders__head">
              <p className="section-label section-label--spaced">Folders</p>
              <button
                type="button"
                className="icon-button icon-button--tiny"
                aria-label="New folder"
                title="New folder"
                onClick={() => setAdding(true)}
              >
                <Icon name="plus" size={12} />
              </button>
            </div>

            <ul>
              {folders.map((folder) => {
                const active = view.kind === "folder" && view.name === folder;
                if (renaming === folder) {
                  return (
                    <li key={folder}>
                      <FolderInput
                        initial={folder}
                        onCommit={(name) => {
                          setRenaming(null);
                          if (name && name !== folder) onRenameFolder(folder, name);
                        }}
                        onCancel={() => setRenaming(null)}
                      />
                    </li>
                  );
                }

                return (
                  <li key={folder}>
                    <button
                      type="button"
                      className="nav-item"
                      title={folder}
                      data-active={active || undefined}
                      data-drop={dropTarget?.name === folder || undefined}
                      aria-current={active ? "page" : undefined}
                      data-folder-drop={folder}
                      onClick={() => onSelect({ kind: "folder", name: folder })}
                      onDoubleClick={() => setRenaming(folder)}
                      onPointerDown={(event) => onFolderDragBegin(folder, event)}
                    >
                      <Icon name="folder" size={15} />
                      <span className="nav-item__label">{folder}</span>
                    </button>
                  </li>
                );
              })}

              {adding && (
                <li>
                  <FolderInput
                    initial=""
                    onCommit={(name) => {
                      setAdding(false);
                      if (name) onCreateFolder(name);
                    }}
                    onCancel={() => setAdding(false)}
                  />
                </li>
              )}
            </ul>
        </>

        {view.kind === "folder" && (
          <button
            type="button"
            className="linkish folders__delete"
            onClick={() => onDeleteFolder(view.name)}
          >
            Delete “{view.name}” — its items stay
          </button>
        )}
      </nav>

      <footer className="sidebar__footer-anchor">
        <button
          type="button"
          className="sidebar__utility"
          data-active={view.kind === "sync" || undefined}
          aria-current={view.kind === "sync" ? "page" : undefined}
          onClick={() => onSelect({ kind: "sync" })}
        >
          <Icon name="sync" size={14} />
          <span>Settings</span>
        </button>

        <button
          type="button"
          ref={menuTriggerRef}
          className="sidebar__footer"
          /*
           * The name says the two things the old one did not: what the button
           * reads, and what pressing it does. It used to be "Lock vault", which
           * matched no word on screen — so voice control had no way to ask for
           * it — and described an action this control does not perform. It
           * opens a menu; locking is one row inside that menu.
           */
          aria-label={`Vault unlocked. ${lockSummary}. Change when it locks, or lock it now`}
          aria-haspopup="menu"
          aria-expanded={menuOpen}
          onClick={() => setMenuOpen((open) => !open)}
        >
          <span className="sidebar__footer-tile" aria-hidden="true">
            <Icon name="lock" size={14} />
          </span>
          <span className="sidebar__footer-text">
            <span className="sidebar__footer-title">Vault unlocked</span>
            <span className="sidebar__footer-sub">{lockSummary}</span>
          </span>
          <Icon name="chevronRight" size={13} />
        </button>

        {/* After its trigger, not before it. The popover is positioned against
            the anchor either way, but source order is what Tab follows, and a
            menu rendered ahead of the button that opens it is a menu Tab has
            already walked past by the time it exists. */}
        {menuOpen && (
          <AutoLockMenu
            current={autoLockSeconds}
            triggerRef={menuTriggerRef}
            onChoose={(seconds) => {
              onChangeAutoLock(seconds);
              closeMenu();
            }}
            onLockNow={() => {
              // Not closeMenu: locking unmounts this whole screen, so there is
              // no longer a button to hand focus back to.
              setMenuOpen(false);
              onLock();
            }}
            onDismiss={closeMenu}
          />
        )}
      </footer>
    </aside>
  );
}

function FolderInput({
  initial,
  onCommit,
  onCancel,
}: {
  initial: string;
  onCommit: (name: string) => void;
  onCancel: () => void;
}): JSX.Element {
  const [value, setValue] = useState(initial);

  return (
    <input
      className="input folders__input"
      value={value}
      autoFocus
      placeholder="Folder name"
      aria-label="Folder name"
      onChange={(event) => setValue(event.target.value)}
      onBlur={() => onCommit(value.trim())}
      onKeyDown={(event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          onCommit(value.trim());
        }
        if (event.key === "Escape") {
          event.preventDefault();
          onCancel();
        }
      }}
    />
  );
}
