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
  folders: string[];
  onSelect: (view: View) => void;
  onChangeAutoLock: (seconds: number | null) => void;
  onLock: () => void;
  onCreateFolder: (name: string) => void;
  onRenameFolder: (from: string, to: string) => void;
  onDeleteFolder: (name: string) => void;
  onReorderFolders: (names: string[]) => void;
  onDropItem: (itemId: string, folder: string | null) => void;
}

/** What a drag is carrying. Read on drop to tell an item from a folder. */
const ITEM_DRAG = "application/x-yara-item";
const FOLDER_DRAG = "application/x-yara-folder";

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
  onReorderFolders,
  onDropItem,
}: SidebarProps): JSX.Element {
  const [menuOpen, setMenuOpen] = useState(false);
  /** The folder a drag is currently over, so exactly one row can light up. */
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
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
                  data-active={active || undefined}
                  data-drop={dropTarget === folder || undefined}
                  aria-current={active ? "page" : undefined}
                  draggable
                  onClick={() => onSelect({ kind: "folder", name: folder })}
                  onDoubleClick={() => setRenaming(folder)}
                  onDragStart={(event) => {
                    event.dataTransfer.setData(FOLDER_DRAG, folder);
                    event.dataTransfer.effectAllowed = "move";
                  }}
                  onDragOver={(event) => {
                    // Only claim the drop if the drag is carrying something
                    // this row can accept, or the cursor lies about it.
                    const types = event.dataTransfer.types;
                    if (!types.includes(ITEM_DRAG) && !types.includes(FOLDER_DRAG)) return;
                    event.preventDefault();
                    event.dataTransfer.dropEffect = "move";
                    setDropTarget(folder);
                  }}
                  onDragLeave={() => setDropTarget((at) => (at === folder ? null : at))}
                  onDrop={(event) => {
                    event.preventDefault();
                    setDropTarget(null);

                    const item = event.dataTransfer.getData(ITEM_DRAG);
                    if (item) {
                      onDropItem(item, folder);
                      return;
                    }

                    const moved = event.dataTransfer.getData(FOLDER_DRAG);
                    if (moved && moved !== folder) {
                      const without = folders.filter((f) => f !== moved);
                      const at = without.indexOf(folder);
                      onReorderFolders([
                        ...without.slice(0, at),
                        moved,
                        ...without.slice(at),
                      ]);
                    }
                  }}
                >
                  <Icon name="folder" size={16} />
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

          {/*
            Dropping here takes an item out of its folder. Without it the only
            way back out would be the edit dialog, and a thing you can drag in
            should be draggable out.
          */}
          <li>
            <button
              type="button"
              className="nav-item nav-item--loose"
              data-drop={dropTarget === "" || undefined}
              onClick={() => onSelect({ kind: "all" })}
              onDragOver={(event) => {
                if (!event.dataTransfer.types.includes(ITEM_DRAG)) return;
                event.preventDefault();
                setDropTarget("");
              }}
              onDragLeave={() => setDropTarget((at) => (at === "" ? null : at))}
              onDrop={(event) => {
                event.preventDefault();
                setDropTarget(null);
                const item = event.dataTransfer.getData(ITEM_DRAG);
                if (item) onDropItem(item, null);
              }}
            >
              <Icon name="allItems" size={16} />
              <span className="nav-item__label">No folder</span>
            </button>
          </li>
        </ul>

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

/**
 * The inline box for naming a folder.
 *
 * Commits on Enter or on losing focus, cancels on Escape. A dialog for one
 * short string would be three interactions where one will do, and naming a
 * folder is not a decision that wants confirming.
 */
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
