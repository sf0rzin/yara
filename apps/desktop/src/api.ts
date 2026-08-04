import { invoke } from "@tauri-apps/api/core";

export type ItemKind = "login" | "card" | "note";

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

export interface ReusedGroup {
  items: string[];
}

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

export type Strength = "weak" | "fair" | "strong";

export const estimateStrength = (password: string) =>
  invoke<Strength>("estimate_strength", { password });

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
