import { useEffect, useState, type JSX } from "react";
import {
  errorMessage,
  formatCharge,
  formatMoney,
  listSubscriptions,
  type SubscriptionView,
} from "../api";
import { Icon } from "./Icon";

/**
 * Everything charging you, grouped by when it lands.
 *
 * Grouped by time rather than by amount, because the question this answers is
 * "what is about to happen" — the expensive one you already know about is less
 * useful than the small one arriving on Thursday.
 *
 * Urgency is brightness. There is no colour to spend on it, so the nearest
 * group is simply first and its rows are the ones at full contrast.
 */
export function SubscriptionsView({
  onSelect,
}: {
  onSelect: (id: string) => void;
}): JSX.Element {
  const [subs, setSubs] = useState<SubscriptionView[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void listSubscriptions()
      .then(setSubs)
      .catch((caught) => setError(errorMessage(caught)));
  }, []);

  if (error) {
    return (
      <p className="notice notice--loud">
        <Icon name="alert" size={13} />
        {error}
      </p>
    );
  }

  if (subs === null) return <p className="empty" />;

  if (subs.length === 0) {
    return (
      <p className="empty">
        Nothing is charging you yet. Attach a subscription to a login from its
        detail pane.
      </p>
    );
  }

  const groups = groupByWhen(subs);

  return (
    <>
      <Total subs={subs} />

      {groups.map(([label, rows]) => (
        <section key={label}>
          <p className="section-label">{label}</p>
          <ul className="rows">
            {rows.map((sub) => (
              <li key={sub.itemId}>
                <button
                  type="button"
                  className="row"
                  onClick={() => onSelect(sub.itemId)}
                >
                  <span className="row__text">
                    <span className="row__name">{sub.itemName}</span>
                    <span className="row__sub">
                      {formatCharge(sub.nextCharge)}
                      {sub.paidWithName && ` · ${sub.paidWithName}`}
                    </span>
                  </span>
                  <span className="sub__amount">
                    {formatMoney(sub.amountMinor, sub.currency)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </>
  );
}

/**
 * What this costs to keep, per month.
 *
 * The sentence says how it was derived rather than just showing a number.
 * Yearly plans are spread across twelve months and usage-based ones are left
 * out entirely, and a total that hides either of those is a total somebody
 * will later find wrong.
 */
function Total({ subs }: { subs: SubscriptionView[] }): JSX.Element | null {
  const counted = subs.filter((sub) => sub.monthlyMinor !== null);
  if (counted.length === 0) return null;

  // Mixed currencies are not added together. Converting would need a rate this
  // app has no business fetching, and adding them regardless would be wrong.
  const currencies = new Set(counted.map((sub) => sub.currency));
  if (currencies.size > 1) {
    return (
      <p className="panel__note">
        {counted.length} subscriptions across {currencies.size} currencies. No
        total, because adding them would need an exchange rate this app does
        not fetch.
      </p>
    );
  }

  const currency = counted[0].currency;
  const total = counted.reduce((sum, sub) => sum + (sub.monthlyMinor ?? 0), 0);
  const yearly = counted.filter((sub) => sub.cadence === "yearly").length;
  const usage = subs.length - counted.length;

  const caveats = [
    yearly > 0 && `${yearly} yearly ${yearly === 1 ? "plan" : "plans"} spread across the year`,
    usage > 0 && `${usage} usage-based ${usage === 1 ? "plan" : "plans"} left out`,
  ].filter(Boolean);

  return (
    <p className="sub__total">
      <span className="sub__total-amount">{formatMoney(total, currency)}</span>
      <span className="sub__total-note">
        a month{caveats.length > 0 && `, with ${caveats.join(" and ")}`}
      </span>
    </p>
  );
}

/** Soonest first, undated last. */
function groupByWhen(subs: SubscriptionView[]): [string, SubscriptionView[]][] {
  const now = Date.now() / 1000;
  const buckets: Record<string, SubscriptionView[]> = {
    "This week": [],
    "Later this month": [],
    "Further out": [],
    "No fixed date": [],
  };

  for (const sub of subs) {
    if (sub.nextCharge === null) {
      buckets["No fixed date"].push(sub);
      continue;
    }
    const days = (sub.nextCharge - now) / 86_400;
    if (days <= 7) buckets["This week"].push(sub);
    else if (days <= 31) buckets["Later this month"].push(sub);
    else buckets["Further out"].push(sub);
  }

  return Object.entries(buckets).filter(([, rows]) => rows.length > 0);
}
