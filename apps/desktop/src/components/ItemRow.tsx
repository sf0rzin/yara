import type { JSX } from "react";
import type { ItemKind, ItemSummary } from "../api";
import { Icon, type IconName } from "./Icon";
import { TotpBadge } from "./TotpBadge";

const KIND_ICONS: Record<ItemKind, IconName> = {
  login: "login",
  card: "card",
  note: "note",
};

interface ItemRowProps {
  item: ItemSummary;
  selected: boolean;
  onSelect: (id: string) => void;
}

export function ItemRow({ item, selected, onSelect }: ItemRowProps): JSX.Element {
  // Prefer the username, fall back to the host so a row is never subtitle-less
  // just because no username was recorded.
  const subtitle = item.username ?? hostOf(item.url);

  return (
    <li>
      <button
        type="button"
        className="row"
        data-selected={selected || undefined}
        onClick={() => onSelect(item.id)}
      >
        <span className="row__icon" aria-hidden="true">
          <Icon name={KIND_ICONS[item.kind]} size={14} />
        </span>

        <span className="row__text">
          <span className="row__name">{item.name}</span>
          {subtitle && <span className="row__sub">{subtitle}</span>}
        </span>

        {item.hasTotp && <TotpBadge itemId={item.id} />}
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
