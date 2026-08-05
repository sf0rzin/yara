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
  tags: string[];
  hasPassword: boolean;
  hasTotp: boolean;
  updatedAt: number;
  createdAt: number;
  /**
   * How the password rates, or null when there is no password.
   *
   * Rated in the backend, where the plaintext is. Deriving it here from the
   * health report's list of weak passwords would leave everything else to be
   * called strong, which overclaims for a merely adequate one.
   */
  strength: Strength | null;
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

/** Items sharing one password, by id. */
export interface ReusedGroup {
  items: string[];
}

/**
 * The health report. Every list identifies items by **id**, not by name —
 * two items may share a name, and matching on one would both miss real reuse
 * and invent it between unrelated entries.
 */
export interface VaultHealth {
  weak: string[];
  reused: ReusedGroup[];
  missingTotp: string[];
  itemsWithPasswords: number;
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
  tags?: string[];
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
}

export const vaultExists = () => invoke<boolean>("vault_exists");

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
  });

export const recentItems = (limit = 5) =>
  invoke<ItemSummary[]>("recent_items", { limit });

export const vaultCounts = () => invoke<VaultCounts>("vault_counts");

export const vaultHealth = () => invoke<VaultHealth>("vault_health");

export const addItem = (item: NewItem) => invoke<string>("add_item", { item });

export const deleteItem = (id: string) => invoke<void>("delete_item", { id });

export const revealPassword = (id: string) =>
  invoke<string>("reveal_password", { id });

export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });

export const estimateStrength = (password: string) =>
  invoke<Strength>("estimate_strength", { password });

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
