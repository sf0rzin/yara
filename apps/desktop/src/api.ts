import { invoke } from "@tauri-apps/api/core";

export type ItemKind = "login" | "card" | "note";

export type Strength = "weak" | "fair" | "strong";

/**
 * An item as the backend hands it over.
 *
 * There is no password field here, and that is deliberate rather than an
 * oversight: secrets cannot reach the UI through ordinary listing, only through
 * `revealPassword` for one named item.
 */
export interface ItemSummary {
  id: string;
  name: string;
  kind: ItemKind;
  username: string | null;
  url: string | null;
  folder: string | null;
  tags: string[];
  hasPassword: boolean;
  hasTotp: boolean;
  updatedAt: number;
  createdAt: number;
}

export interface TotpCode {
  code: string;
  secondsRemaining: number;
  period: number;
}

export interface VaultCounts {
  total: number;
  logins: number;
  cards: number;
  notes: number;
  authenticator: number;
}

/**
 * What a scanned QR code contained.
 *
 * Note what is absent: the secret. The backend keeps the scanned enrollment and
 * hands over only this description plus one live code, which is enough for the
 * user to confirm they scanned the right thing.
 */
export interface TotpPreview {
  issuer: string | null;
  account: string | null;
  algorithm: string;
  digits: number;
  period: number;
  sampleCode: string;
}

/** A custom field being written. */
export interface NewField {
  label: string;
  value: string;
  secret: boolean;
}

/**
 * A custom field being read.
 *
 * `value` is null for a secret — reading one takes an explicit `revealField`,
 * the same as the password. A null here means "ask", never "empty".
 */
export interface FieldView {
  label: string;
  value: string | null;
  secret: boolean;
}

export interface ItemExtras {
  hasNotes: boolean;
  fields: FieldView[];
}

export interface NewItem {
  name: string;
  kind?: ItemKind;
  username?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
  totp_uri?: string | null;
  /** Attach the enrollment most recently read from a QR code. */
  use_scanned_totp?: boolean;
  fields?: NewField[];
  tags?: string[];
}

/**
 * An edit. What arrives replaces what is stored, so a cleared box clears the
 * value — except for `password`, where `null` means "leave it alone" and `""`
 * means "remove it". The form never receives the current password, so those
 * two intentions cannot be told apart by value and have to be said outright.
 */
export interface ItemEdit {
  name: string;
  kind: ItemKind;
  username: string | null;
  password: string | null;
  url: string | null;
  notes: string | null;
  fields: NewField[];
}

export const scanQrFromPath = (path: string) =>
  invoke<TotpPreview>("scan_qr_from_path", { path });

export const scanQrFromClipboard = () =>
  invoke<TotpPreview>("scan_qr_from_clipboard");

export const clearScannedTotp = () => invoke<void>("clear_scanned_totp");

/** An agent is asking for a credential and the answer is yours. */
export interface ApprovalPrompt {
  id: string;
  program: string;
  programPath: string | null;
  pid: number;
  item: string;
  field: string;
  mode: "run" | "reveal";
  command: string | null;
  envVar: string | null;
  reason: string;
  /**
   * The command would hand the value back rather than use it — a shell, or an
   * interpreter given a program to evaluate. True for an outright reveal too.
   *
   * When this is set the user is answering "may it see this?", whatever the
   * request called itself, and the dialog has to say so.
   */
  discloses: boolean;
}

export interface Grant {
  id: string;
  item: string;
  field: string;
  program: string;
  scope: "run" | "reveal";
  /** The exact thing it authorises, e.g. "run `npm run migrate`". */
  permits: string;
  secondsRemaining: number;
  remainingUses: number;
}

export interface AuditEntry {
  id: string;
  at: number;
  program: string;
  item: string;
  summary: string;
  reason: string;
  allowed: boolean;
  notable: boolean;
}

export type ApprovalChoice = "deny" | "once" | "window";

export const resolveApproval = (
  id: string,
  choice: ApprovalChoice,
  minutes?: number,
) => invoke<void>("resolve_approval", { id, choice, minutes: minutes ?? null });

export const listGrants = () => invoke<Grant[]>("list_grants");

export const revokeGrant = (id: string) => invoke<boolean>("revoke_grant", { id });

export const auditEntries = (limit = 50) =>
  invoke<AuditEntry[]>("audit_entries", { limit });

export interface ListFilter {
  query?: string;
  kind?: ItemKind;
  withTotp?: boolean;
  folder?: string | null;
}

/**
 * Whether a vault file is at the live path.
 *
 * Not what the app asks at startup any more, and not what anything else should
 * ask either: a false here covers both "no vault yet" and "a save was
 * interrupted and the vault is beside itself", which want opposite offers. Use
 * `vaultStartup` for that question.
 */
export const vaultExists = () => invoke<boolean>("vault_exists");

/**
 * Which of the three situations this machine is in at startup.
 *
 * `vault_exists` answers a question with two answers, and there are three. A
 * save interrupted between its two renames leaves no file at the live path
 * while a complete copy sits beside it — which read as "no vault yet", so the
 * app offered first-run setup and the vault created there deleted the last
 * surviving copy on its own first save. `recover` is that third state, and the
 * interface must never offer to create a vault while it is showing.
 */
export type Startup = "setup" | "locked" | "recover";

export const vaultStartup = () => invoke<Startup>("vault_startup");

/**
 * Puts a surviving copy back at the live path.
 *
 * Copies rather than moves, so an interruption during recovery still leaves
 * something to recover from. Throws if there is nothing there that parses as a
 * vault, or if a vault has appeared at the live path since.
 */
export const recoverVault = () => invoke<void>("recover_vault");

export const isUnlocked = () => invoke<boolean>("is_unlocked");

export const createVault = (password: string) =>
  invoke<void>("create_vault", { password });

export const unlockVault = (password: string) =>
  invoke<void>("unlock_vault", { password });

export const lockVault = () => invoke<void>("lock_vault");

export const listItems = (filter: ListFilter = {}) =>
  invoke<ItemSummary[]>("list_items", {
    query: filter.query ?? "",
    kind: filter.kind ?? null,
    withTotp: filter.withTotp ?? null,
    folder: filter.folder ?? null,
  });

export const recentItems = (limit = 5) =>
  invoke<ItemSummary[]>("recent_items", { limit });

export const vaultCounts = () => invoke<VaultCounts>("vault_counts");

export const folders = () => invoke<string[]>("folders");

export const createFolder = (name: string) =>
  invoke<void>("create_folder", { name });

export const renameFolder = (from: string, to: string) =>
  invoke<void>("rename_folder", { from, to });

/** Removes the folder. Its items stay in the vault, without one. */
export const deleteFolder = (name: string) =>
  invoke<number>("delete_folder", { name });

export const reorderFolders = (names: string[]) =>
  invoke<void>("reorder_folders", { names });

export const setItemFolder = (id: string, folder: string | null) =>
  invoke<void>("set_item_folder", { id, folder });

export const reorderItems = (ids: string[]) =>
  invoke<void>("reorder_items", { ids });

export const addItem = (item: NewItem) => invoke<string>("add_item", { item });

export const updateItem = (id: string, edit: ItemEdit) =>
  invoke<void>("update_item", { id, edit });

export const itemExtras = (id: string) =>
  invoke<ItemExtras>("item_extras", { id });

export const deleteItem = (id: string) => invoke<void>("delete_item", { id });

export const revealPassword = (id: string) =>
  invoke<string>("reveal_password", { id });

export const revealField = (id: string, label: string) =>
  invoke<string>("reveal_field", { id, label });

export const revealNotes = (id: string) =>
  invoke<string>("reveal_notes", { id });

export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });

export const estimateStrength = (password: string) =>
  invoke<Strength>("estimate_strength", { password });

export interface PasswordRecipe {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export const generatePassword = (recipe: PasswordRecipe) =>
  invoke<string>("generate_password", { recipe });

/**
 * Re-wraps the vault key under a new master password.
 *
 * The current password is proof, not a formality: the command re-opens the
 * file on disk with it before writing anything. Without that step this re-keyed
 * the vault on the word of whoever called it, so anything running inside the
 * webview could have locked the user out of their own vault while it sat
 * unlocked in front of them.
 *
 * A current password that does not open the file comes back as the vault's
 * ordinary decrypt error, which says "wrong password or corrupted data" and
 * means either. Callers show it as it is — narrowing it to "wrong password"
 * would be the frontend inventing a distinction the vault refuses to make.
 */
export const changeMasterPassword = (currentPassword: string, newPassword: string) =>
  invoke<void>("change_master_password", { currentPassword, newPassword });

/**
 * What one copy did, in terms the interface may repeat to the user.
 *
 * `excludedFromHistory` is the whole reason this goes through the backend: no
 * amount of JavaScript can place the clipboard formats that keep an entry out
 * of Win+V and the Cloud Clipboard, and when Windows will not take them the
 * interface has to stop claiming the copy is private to this machine.
 */
export interface Copied {
  excludedFromHistory: boolean;
  /** Seconds until the copy is wiped. */
  clearsIn: number;
  /** Which copy this is. The clear that follows carries the same number. */
  token: number;
}

/**
 * What became of a copy when its time was up.
 *
 * Three outcomes rather than a boolean, because "we did not take it off" and
 * "somebody else's copy is on there now" are opposite facts: one leaves a
 * password on the clipboard and one does not.
 */
export type Cleared =
  | { outcome: "wiped" }
  | { outcome: "alreadyGone" }
  | { outcome: "failed"; detail: string };

export const copySecret = (value: string) => invoke<Copied>("copy_secret", { value });

/** Takes a copied secret off the clipboard now rather than on the timer. */
export const clearClipboard = () => invoke<Cleared>("clear_clipboard");

export interface ImportProblem {
  name: string;
  reason: string;
}

/**
 * What an import would do, before it does any of it.
 *
 * Names only. No seed crosses the IPC boundary at any point — the codes are
 * parsed in the backend and written straight into the vault.
 */
export interface ImportPreview {
  ready: string[];
  duplicates: string[];
  skipped: ImportProblem[];
}

export const previewImport = (path: string) =>
  invoke<ImportPreview>("preview_import", { path });

/** Returns how many items were added. */
export const runImport = (path: string) => invoke<number>("run_import", { path });

export interface SyncStatus {
  enrolled: boolean;
  baseUrl: string | null;
  accountId: string | null;
  deviceId: string | null;
  lastSyncedAt: number | null;
}

/**
 * Shown once, at enrolment, and never again.
 *
 * Not stored anywhere: it is the second half of what protects the account, and
 * keeping a copy on the machine the password already unlocks would undo the
 * reason for having it. Losing it means losing the account.
 */
export interface RecoveryKit {
  accountId: string;
  kit: string;
}

export interface SyncReport {
  pulled: number;
  pushed: number;
  conflicts: number;
  /**
   * Deletions the server offered without a proof this account made them.
   *
   * Ignored rather than obeyed, and counted rather than swallowed: a run of
   * these is what a compromised server trying to wipe every enrolled machine
   * looks like from here, and it is the only place that would ever show.
   */
  unprovenDeletes: number;
  revision: number;
}

export const syncStatus = () => invoke<SyncStatus>("sync_status");

export const syncEnrol = (
  baseUrl: string,
  invite: string,
  password: string,
  label?: string,
) =>
  invoke<RecoveryKit>("sync_enrol", {
    baseUrl,
    invite,
    password,
    label: label ?? null,
  });

/**
 * Joins an account this machine has never seen, with a recovery kit.
 *
 * The mirror of {@link syncEnrol}: that one creates an account and hands back a
 * kit, this one spends a kit somebody wrote down. It is for a second machine,
 * not for resetting a forgotten password — the kit is one half of what unwraps
 * the account, and the master password is the other.
 */
export const syncJoin = (
  baseUrl: string,
  accountId: string,
  password: string,
  kit: string,
  label?: string,
) =>
  invoke<SyncReport>("sync_join", {
    baseUrl,
    accountId,
    password,
    kit,
    label: label ?? null,
  });

export const syncNow = () => invoke<SyncReport>("sync_now");

export const syncForget = () => invoke<void>("sync_forget");

/** Tauri sends command errors across as plain strings. */
export function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "Something went wrong.";
}

/**
 * Idle seconds before the vault locks itself, or null for never.
 *
 * Stored inside the vault rather than beside it: how long this machine stays
 * unlocked deserves the same protection as what it is protecting, and a
 * setting kept in the clear could be edited to "never" by anything running as
 * the user.
 */
export const autoLockSeconds = () => invoke<number | null>("auto_lock_seconds");

export const setAutoLockSeconds = (seconds: number | null) =>
  invoke<void>("set_auto_lock_seconds", { seconds });

export type Cadence = "monthly" | "yearly" | "usage";

/**
 * A recurring charge attached to a login.
 *
 * `paidWithName` is resolved in the backend. The interface would otherwise
 * need the card list to render one row, and a card since deleted would show as
 * a bare uuid.
 */
export interface SubscriptionView {
  itemId: string;
  itemName: string;
  plan: string | null;
  amountMinor: number;
  currency: string;
  cadence: Cadence;
  nextCharge: number | null;
  paidWith: string | null;
  paidWithName: string | null;
  /** Cost per month in minor units; null for usage-based plans. */
  monthlyMinor: number | null;
}

export interface SubscriptionInput {
  plan: string | null;
  amountMinor: number;
  currency: string;
  cadence: Cadence;
  nextCharge: number | null;
  paidWith: string | null;
}

export const listSubscriptions = () =>
  invoke<SubscriptionView[]>("list_subscriptions");

export const itemSubscription = (id: string) =>
  invoke<SubscriptionView | null>("item_subscription", { id });

export const setSubscription = (id: string, subscription: SubscriptionInput | null) =>
  invoke<void>("set_subscription", { id, subscription });

/** Minor units to something a person reads. */
export function formatMoney(minor: number, currency: string): string {
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency,
    }).format(minor / 100);
  } catch {
    // An unknown or mistyped currency code must not blank the amount.
    return `${(minor / 100).toFixed(2)} ${currency}`;
  }
}

/** "14 August · in 10 days", as the design words it. */
export function formatCharge(at: number | null): string {
  if (at === null) return "No fixed date";

  const date = new Date(at * 1000).toLocaleDateString(undefined, {
    day: "numeric",
    month: "long",
  });

  const days = Math.round((at - Date.now() / 1000) / 86_400);
  if (days < 0) return `${date} · overdue`;
  if (days === 0) return `${date} · today`;
  if (days === 1) return `${date} · tomorrow`;
  return `${date} · in ${days} days`;
}

/**
 * The icon for a domain, as a data URL, or null if there is not one.
 *
 * Fetched through the origin's proxy rather than from the site: asking
 * github.com directly would tell github.com that this vault holds a GitHub
 * account, and doing it per row would put the shape of the vault on the wire.
 */
export const iconFor = (domain: string) =>
  invoke<string | null>("icon_for", { domain });

export const iconsEnabled = () => invoke<boolean>("icons_enabled");

export const setIconsEnabled = (enabled: boolean) =>
  invoke<void>("set_icons_enabled", { enabled });
