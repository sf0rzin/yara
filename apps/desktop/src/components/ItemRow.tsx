import type { JSX } from "react";
import type { ItemSummary } from "../api";
import { Tile } from "./Tile";
import { TotpBadge } from "./TotpBadge";

interface ItemRowProps {
  item: ItemSummary;
  selected: boolean;
  showTotpCode?: boolean;
  onSelect: (id: string) => void;
  onContextMenu: (item: ItemSummary, x: number, y: number) => void;
}

export function ItemRow({
  item,
  selected,
  showTotpCode = false,
  onSelect,
  onContextMenu,
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
        onClick={() => onSelect(item.id)}
        onContextMenu={(event) => {
          event.preventDefault();
          onContextMenu(item, event.clientX, event.clientY);
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
