import type { ItemSummary, VaultHealth } from "../api";

/**
 * How many items the health report has something to say about.
 *
 * Reused passwords are counted per item rather than per group: two items
 * sharing one password is two items to fix, not one.
 */
export function affectedItemCount(health: VaultHealth): number {
  const names = new Set(health.weak);
  for (const group of health.reused) {
    for (const name of group.items) names.add(name);
  }
  return names.size;
}

export function isClean(health: VaultHealth): boolean {
  return health.weak.length === 0 && health.reused.length === 0;
}

/**
 * One sentence about a single item's password, for the detail pane.
 *
 * The security screen is gone: health is something you read where the password
 * is, not on a separate page you have to remember to visit. That trade costs
 * the aggregate view of reuse, so reuse is spelled out here instead — an item
 * says how many others share its password, which is the part you cannot work
 * out by looking at one item at a time.
 *
 * Strength comes from the backend rather than from "absent from the weak
 * list", which would make anything merely adequate read as strong.
 */
export function itemHealth(
  item: ItemSummary,
  health: VaultHealth | null,
): string | null {
  // `== null` rather than `=== null` on purpose: an absent rating and an
  // explicit one both mean "nothing to claim here", and the difference between
  // them must not decide whether a password gets called strong.
  if (!item.hasPassword || item.strength == null) return null;

  const strength =
    item.strength === "weak"
      ? "Weak"
      : item.strength === "fair"
        ? "Adequate"
        : "Strong";

  // Matched by id. The report identifies items by uuid, and two items are
  // allowed to share a name — matching on that would both miss real reuse and
  // invent it between unrelated entries.
  const shared = health
    ? (health.reused.find((group) => group.items.includes(item.id))?.items
        .length ?? 1) - 1
    : 0;

  if (shared <= 0) {
    return health === null ? strength : `${strength}, and used nowhere else`;
  }

  // "but" when the strength is reassuring and the reuse undercuts it; "and"
  // when both point the same way. The conjunction is doing the work a colour
  // would do elsewhere.
  const joiner = item.strength === "weak" ? "and" : "but";
  return `${strength}, ${joiner} reused on ${shared} other ${
    shared === 1 ? "item" : "items"
  }`;
}
