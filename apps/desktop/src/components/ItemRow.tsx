import type { JSX } from "react";
import type { ItemSummary } from "../api";
import { Tile } from "./Tile";
import { TotpBadge } from "./TotpBadge";

/** Matches the sidebar's reader. Both halves have to agree on the name. */
const ITEM_DRAG = "application/x-yara-item";

interface ItemRowProps {
  item: ItemSummary;
  selected: boolean;
  showTotpCode?: boolean;
  /** Where a drop would land this row: above it, below it, or nowhere. */
  dropEdge?: "above" | "below";
  onSelect: (id: string) => void;
  onContextMenu: (item: ItemSummary, x: number, y: number) => void;
  onDragStart?: (id: string) => void;
  onDragOverRow?: (id: string, edge: "above" | "below") => void;
  onDropRow?: (id: string) => void;
  onDragEnd?: () => void;
}

export function ItemRow({
  item,
  selected,
  showTotpCode = false,
  dropEdge,
  onSelect,
  onContextMenu,
  onDragStart,
  onDragOverRow,
  onDropRow,
  onDragEnd,
}: ItemRowProps): JSX.Element {
  const host = hostOf(item.url);
  const subtitle = [item.username, host && host !== item.username ? host : null]
    .filter(Boolean)
    .join(" · ");

  return (
    <li>
      <button
        type="button"
        className="row"
        data-selected={selected || undefined}
        data-drop-edge={dropEdge}
        draggable
        onClick={() => onSelect(item.id)}
        onDragStart={(event) => {
          event.dataTransfer.setData(ITEM_DRAG, item.id);
          event.dataTransfer.effectAllowed = "move";
          onDragStart?.(item.id);
        }}
        onDragOver={(event) => {
          if (!event.dataTransfer.types.includes(ITEM_DRAG)) return;
          event.preventDefault();
          event.dataTransfer.dropEffect = "move";
          // Which half of the row the cursor is in decides whether the drop
          // lands above or below it, so a drag can reach either end of a run
          // without having to aim at the gap between two rows.
          const box = event.currentTarget.getBoundingClientRect();
          const edge = event.clientY < box.top + box.height / 2 ? "above" : "below";
          onDragOverRow?.(item.id, edge);
        }}
        onDrop={(event) => {
          event.preventDefault();
          onDropRow?.(item.id);
        }}
        onDragEnd={() => onDragEnd?.()}
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
