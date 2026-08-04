import type { ItemKind, VaultCounts } from "./api";

/** Which collection or type filter the main pane is showing. */
export type View =
  | { kind: "all" }
  | { kind: "recent" }
  | { kind: "security" }
  | { kind: "agents" }
  | { kind: "sync" }
  | { kind: "authenticator" }
  | { kind: "type"; itemKind: ItemKind };

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
    case "security":
      return "Security";
    case "agents":
      return "Agent access";
    case "sync":
      return "Sync";
    case "authenticator":
      return "Authenticator";
    case "type":
      return KIND_TITLES[view.itemKind];
  }
}

/** The line under the page title. Plural handling included. */
export function viewSubtitle(view: View, counts: VaultCounts | null): string {
  if (view.kind === "security") {
    return "Password health across your vault";
  }
  if (view.kind === "agents") {
    return "What programs have been allowed to use";
  }
  if (view.kind === "sync") {
    return "Keeping this vault on more than one machine";
  }
  if (view.kind === "recent") {
    return "Most recently updated";
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
