import type { VaultHealth } from "../api";

/**
 * How many distinct items have something wrong with them.
 *
 * Adding the finding counts together would double-count: a password that is
 * both weak and reused appears in two lists, and reporting "4 of 5" for what
 * are really two items overstates the problem and erodes trust in the number.
 */
export function affectedItemCount(health: VaultHealth): number {
  const ids = new Set(health.weak);
  for (const group of health.reused) {
    for (const id of group.items) ids.add(id);
  }
  return ids.size;
}

export function isClean(health: VaultHealth): boolean {
  return health.weak.length === 0 && health.reused.length === 0;
}
