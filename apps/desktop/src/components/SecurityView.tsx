import type { JSX } from "react";
import type { ItemSummary, VaultHealth } from "../api";
import { affectedItemCount, isClean } from "../lib/health";
import { Icon } from "./Icon";

interface SecurityViewProps {
  health: VaultHealth;
  items: ItemSummary[];
  onSelect: (id: string) => void;
}

export function SecurityView({ health, items, onSelect }: SecurityViewProps): JSX.Element {
  const byId = new Map(items.map((item) => [item.id, item]));
  const name = (id: string) => byId.get(id)?.name ?? "Unknown item";

  const clean = isClean(health);
  const affected = affectedItemCount(health);

  return (
    <div className="security">
      <div className="security__summary">
        <Icon name={clean ? "check" : "alert"} size={16} />
        <p>
          {clean
            ? `No weak or reused passwords across ${health.itemsWithPasswords} items.`
            : `${affected} of ${health.itemsWithPasswords} passwords need attention.`}
        </p>
      </div>

      <Finding
        title="Reused passwords"
        empty="Every password is unique."
        description="One breach exposes every account sharing the password."
        count={health.reused.length}
      >
        {health.reused.map((group) => (
          <div key={group.items.join()} className="finding__group">
            {group.items.map((id) => (
              <button
                key={id}
                type="button"
                className="finding__item"
                onClick={() => onSelect(id)}
              >
                {name(id)}
                <Icon name="chevronRight" size={13} />
              </button>
            ))}
          </div>
        ))}
      </Finding>

      <Finding
        title="Weak passwords"
        empty="No weak passwords."
        description="Short or low-variety enough to be worth replacing."
        count={health.weak.length}
      >
        <div className="finding__group">
          {health.weak.map((id) => (
            <button
              key={id}
              type="button"
              className="finding__item"
              onClick={() => onSelect(id)}
            >
              {name(id)}
              <Icon name="chevronRight" size={13} />
            </button>
          ))}
        </div>
      </Finding>

      <Finding
        title="No second factor"
        empty="Every login has an authenticator."
        description="These accounts rest on the password alone."
        count={health.missingTotp.length}
      >
        <div className="finding__group">
          {health.missingTotp.map((id) => (
            <button
              key={id}
              type="button"
              className="finding__item"
              onClick={() => onSelect(id)}
            >
              {name(id)}
              <Icon name="chevronRight" size={13} />
            </button>
          ))}
        </div>
      </Finding>

      <p className="security__note">
        Checked entirely on this device. yara does not send anything derived
        from your passwords to a breach database or any other service.
      </p>
    </div>
  );
}

interface FindingProps {
  title: string;
  description: string;
  empty: string;
  count: number;
  children: React.ReactNode;
}

function Finding({ title, description, empty, count, children }: FindingProps): JSX.Element {
  return (
    <section className="finding">
      <header className="finding__head">
        <h3 className="finding__title">{title}</h3>
        <span className="finding__count">{count}</span>
      </header>
      <p className="finding__desc">{count === 0 ? empty : description}</p>
      {count > 0 && children}
    </section>
  );
}
