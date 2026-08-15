import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { listItems, errorMessage, type ItemSummary } from "../api";
import { useModalDialog } from "../lib/useModalDialog";
import { Icon } from "./Icon";
import { Tile } from "./Tile";

interface CommandPaletteProps {
  onDismiss: () => void;
  onSelect: (item: ItemSummary) => void;
}

/** Enough to scroll through, few enough that the list stays a glance. */
const LIMIT = 8;

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host.replace(/^www\./, "");
  } catch {
    return url;
  }
}

/**
 * Search, as a layer rather than a field.
 *
 * The vault used to carry two search inputs — one in the sidebar, one above
 * the list — both bound to the same string, both filtering the column you
 * happened to be looking at. Neither could find an item outside the current
 * view, which is the thing you actually want search for.
 *
 * This searches the whole vault regardless of what is selected behind it, and
 * gives the space it vacated to the one action that belongs at the top of a
 * list: making a new item.
 */
export function CommandPalette({ onDismiss, onSelect }: CommandPaletteProps): JSX.Element {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<ItemSummary[]>([]);
  const [active, setActive] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLUListElement>(null);
  const dialogRef = useModalDialog<HTMLDivElement>();
  // Answers can land out of order. Only the newest request may write.
  const requestRef = useRef(0);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  useEffect(() => {
    const request = ++requestRef.current;
    let cancelled = false;

    void listItems({ query })
      .then((found) => {
        if (cancelled || request !== requestRef.current) return;
        setResults(found.slice(0, LIMIT));
        // Back to the top on every new query: the highlight is a statement
        // about this result set, and keeping an index across sets points it
        // at whatever happens to be in that slot now.
        setActive(0);
        setError(null);
      })
      .catch((caught) => {
        if (cancelled || request !== requestRef.current) return;
        setError(errorMessage(caught));
        setResults([]);
      });

    return () => {
      cancelled = true;
    };
  }, [query]);

  const choose = useCallback(
    (item: ItemSummary | undefined) => {
      if (!item) return;
      onSelect(item);
      onDismiss();
    },
    [onDismiss, onSelect],
  );

  // Bound to the palette rather than the window. The vault also listens for
  // "/" and Ctrl+K, and a window listener here would race it into reopening
  // the thing it just closed.
  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.preventDefault();
      onDismiss();
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      choose(results[active]);
      return;
    }
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;

    event.preventDefault();
    if (results.length === 0) return;

    // Wraps, because a list this short is faster to cycle than to reverse.
    const step = event.key === "ArrowDown" ? 1 : -1;
    const next = (active + step + results.length) % results.length;
    setActive(next);
    listRef.current?.children[next]?.scrollIntoView({ block: "nearest" });
  };

  return (
    <div className="overlay overlay--palette" onMouseDown={onDismiss}>
      <div
        className="palette"
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Search vault"
        onMouseDown={(event) => event.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="palette__field">
          <Icon name="search" size={15} />
          <input
            ref={inputRef}
            className="palette__input"
            type="text"
            value={query}
            placeholder="Search your vault"
            aria-label="Search your vault"
            // The results are the listbox this input drives; without the role
            // pair a screen reader hears typing and never hears the matches.
            role="combobox"
            aria-expanded
            aria-controls="palette-results"
            aria-activedescendant={results[active] ? `palette-option-${results[active].id}` : undefined}
            onChange={(event) => setQuery(event.target.value)}
          />
          <kbd className="kbd">Esc</kbd>
        </div>

        {error ? (
          <p className="palette__empty">{error}</p>
        ) : results.length === 0 ? (
          <p className="palette__empty">
            {query.trim() ? `Nothing matches “${query.trim()}”` : "No items yet."}
          </p>
        ) : (
          <ul className="palette__results" id="palette-results" role="listbox" ref={listRef}>
            {results.map((item, index) => {
              const host = hostOf(item.url);
              const subtitle = [item.username, host && host !== item.username ? host : null]
                .filter(Boolean)
                .join(" · ");

              return (
                <li key={item.id} role="presentation">
                  <button
                    type="button"
                    id={`palette-option-${item.id}`}
                    role="option"
                    aria-selected={index === active}
                    className="palette__row"
                    data-active={index === active || undefined}
                    // Pointer, not focus: moving the mouse across the list
                    // should move the highlight without stealing the caret
                    // out of the input you are still typing in.
                    onMouseMove={() => setActive(index)}
                    onClick={() => choose(item)}
                  >
                    <Tile name={item.name} kind={item.kind} url={item.url} />
                    <span className="palette__text">
                      <span className="palette__name">{item.name}</span>
                      {subtitle && <span className="palette__sub">{subtitle}</span>}
                    </span>
                    {item.hasTotp && <span className="palette__flag">2FA</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
