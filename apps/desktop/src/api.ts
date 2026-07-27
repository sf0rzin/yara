import { invoke } from "@tauri-apps/api/core";

/**
 * An item as the backend hands it over: no secrets.
 *
 * There is no `password` field here by design. Plaintext only crosses the IPC
 * boundary through `revealPassword`, one item at a time.
 */
export interface ItemSummary {
  id: string;
  name: string;
  username: string | null;
  url: string | null;
  tags: string[];
  hasPassword: boolean;
  hasTotp: boolean;
  updatedAt: number;
}

interface RawItemSummary {
  id: string;
  name: string;
  username: string | null;
  url: string | null;
  tags: string[];
  has_password: boolean;
  has_totp: boolean;
  updated_at: number;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
  period: number;
}

export interface NewItem {
  name: string;
  username?: string | null;
  password?: string | null;
  url?: string | null;
  notes?: string | null;
  totp_uri?: string | null;
  tags?: string[];
}

function toItem(raw: RawItemSummary): ItemSummary {
  return {
    id: raw.id,
    name: raw.name,
    username: raw.username,
    url: raw.url,
    tags: raw.tags,
    hasPassword: raw.has_password,
    hasTotp: raw.has_totp,
    updatedAt: raw.updated_at,
  };
}

export const vaultExists = () => invoke<boolean>("vault_exists");

export const isUnlocked = () => invoke<boolean>("is_unlocked");

export const createVault = (password: string) =>
  invoke<void>("create_vault", { password });

export const unlockVault = (password: string) =>
  invoke<void>("unlock_vault", { password });

export const lockVault = () => invoke<void>("lock_vault");

export const listItems = async (query = ""): Promise<ItemSummary[]> => {
  const raw = await invoke<RawItemSummary[]>("list_items", { query });
  return raw.map(toItem);
};

export const addItem = (item: NewItem) => invoke<string>("add_item", { item });

export const deleteItem = (id: string) => invoke<void>("delete_item", { id });

export const revealPassword = (id: string) =>
  invoke<string>("reveal_password", { id });

export const totpCode = (id: string) => invoke<TotpCode>("totp_code", { id });

/** Tauri sends command errors across as plain strings. */
export function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return "something went wrong";
}
