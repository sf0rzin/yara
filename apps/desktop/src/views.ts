import type { ItemKind, VaultCounts } from "./api";

/**
 * Which collection or type filter the list column is showing.
 *
 * Collections are ways of looking at the vault; Types say what an item is.
 * Subscriptions belongs to the first group because a subscription is an
 * attachment on a login rather than a fifth kind of item.
 *
 * There is no `security`. Password health moved onto the item itself, where
 * the password is, rather than living on a page you have to remember to open.
 */
export type View =
  | { kind: "all" }
  | { kind: "recent" }
  | { kind: "subscriptions" }
  | { kind: "agents" }
  | { kind: "activity" }
  | { kind: "sync" }
  | { kind: "authenticator" }
  | { kind: "type"; itemKind: ItemKind }
  | { kind: "folder"; name: string };

const KIND_TITLES: Record<ItemKind, string> = {
  login: "Logins",
  card: "Cards",
  note: "Notes",
};

export function viewTitle(view: View): string {
  switch (view.kind) {
    case "all":
      return "All items";
    case "recent":
      return "Recent";
    case "subscriptions":
      return "Subscriptions";
    case "agents":
      return "Agent access";
    case "activity":
      return "Activity";
    case "sync":
      return "Sync";
    case "authenticator":
      return "Authenticator";
    case "type":
      return KIND_TITLES[view.itemKind];
    case "folder":
      return view.name;
  }
}

/** The line under the page title. Plural handling included. */
export function viewSubtitle(view: View, counts: VaultCounts | null): string {
  if (view.kind === "agents") {
    return "What programs have been allowed to use";
  }
  if (view.kind === "activity") {
    return "";
  }
  if (view.kind === "sync") {
    return "Keeping this vault on more than one machine";
  }
  if (view.kind === "subscriptions") {
    return "What is charging you, and on which card";
  }
  if (view.kind === "recent") {
    return "Most recently updated";
  }
  // Counted from what is on screen rather than from VaultCounts, which has no
  // per-folder tally and would need one kept in step for no gain.
  if (view.kind === "folder") {
    return "Drag to reorder";
  }

  const total =
    counts === null
      ? null
      : view.kind === "all"
        ? counts.total
        : view.kind === "authenticator"
          ? counts.authenticator
          : view.itemKind === "login"
            ? counts.logins
            : view.itemKind === "card"
              ? counts.cards
              : counts.notes;

  if (total === null) return "";
  return `${total} ${total === 1 ? "item" : "items"}`;
}

/** Views that show a list of items rather than a screen of their own. */
export function isItemList(view: View): boolean {
  return view.kind !== "agents" && view.kind !== "activity" && view.kind !== "sync";
}
