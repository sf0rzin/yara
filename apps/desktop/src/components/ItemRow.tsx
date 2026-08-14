import type { JSX } from "react";
import type { ItemSummary } from "../api";
import { Tile } from "./Tile";
import { TotpBadge } from "./TotpBadge";

/**
 * The row's element id, so the list can move focus to whichever option the
 * arrow keys just selected without holding a ref per row.
 */
export function itemOptionId(id: string): string {
  return `item-option-${id}`;
}

interface ItemRowProps {
  item: ItemSummary;
  selected: boolean;
  showTotpCode?: boolean;
  /** Where a drop would land this row: above it, below it, or nowhere. */
  dropEdge?: "above" | "below";
  /** Dimmed while it is the one being carried. */
  lifted?: boolean;
  onSelect: (id: string) => void;
  onContextMenu: (item: ItemSummary, x: number, y: number) => void;
  onDragBegin?: (id: string, event: React.PointerEvent) => void;
}

export function ItemRow({
  item,
  selected,
  showTotpCode = false,
  dropEdge,
  lifted,
  onSelect,
  onContextMenu,
  onDragBegin,
}: ItemRowProps): JSX.Element {
  const host = hostOf(item.url);
  const subtitle = [item.username, host && host !== item.username ? host : null]
    .filter(Boolean)
    .join(" · ");

  return (
    // The row is an option in the list's listbox, exactly as the palette does
    // it: the li carries the structure, the button carries the role. Selection
    // used to be marked with `data-selected` alone — a styling hook, which says
    // nothing to a screen reader, so walking the list with the arrow keys moved
    // a highlight that only sighted users could see.
    <li role="presentation">
      <button
        type="button"
        id={itemOptionId(item.id)}
        role="option"
        aria-selected={selected}
        className="row"
        data-selected={selected || undefined}
        data-drop-edge={dropEdge}
        data-lifted={lifted || undefined}
        // How the drag finds this row: hit-tested by position rather than by
        // an event the webview would have to let through.
        data-item-id={item.id}
        onClick={() => onSelect(item.id)}
        onPointerDown={(event) => onDragBegin?.(item.id, event)}
        onContextMenu={(event) => {
          event.preventDefault();
          // Shift+F10 and the Menu key raise this with no pointer behind them,
          // and report (0, 0). Taken literally that puts a menu whose only
          // entry is Delete in the window corner, nowhere near the row it acts
          // on — so a keyboard press anchors on the row instead.
          const rect = event.currentTarget.getBoundingClientRect();
          const keyboard = event.clientX === 0 && event.clientY === 0;
          onContextMenu(
            item,
            keyboard ? rect.left + rect.width / 3 : event.clientX,
            keyboard ? rect.bottom - 6 : event.clientY,
          );
        }}
      >
        <Tile name={item.name} kind={item.kind} url={item.url} />

        <span className="row__text">
          <span className="row__name">{item.name}</span>
          {subtitle && <span className="row__sub">{subtitle}</span>}
        </span>

        {item.hasTotp && <TotpBadge itemId={item.id} showCode={showTotpCode} />}
      </button>
    </li>
  );
}

function hostOf(url: string | null): string | null {
  if (!url) return null;
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).host;
  } catch {
    return url;
  }
}
