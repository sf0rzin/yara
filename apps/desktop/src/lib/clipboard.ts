/** How long a copied secret is allowed to sit on the clipboard. */
const CLEAR_AFTER_MS = 20_000;

let clearTimer: ReturnType<typeof setTimeout> | undefined;

/**
 * Copies a secret, then clears the clipboard again a short while later.
 *
 * Without this a password stays in the clipboard indefinitely, readable by
 * every other application on the machine and often synced to a phone. The
 * clear is best-effort — the user may well have copied something else in the
 * meantime, which we cannot detect, so we only overwrite if nothing since.
 */
export async function copySecret(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);

  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => {
    void navigator.clipboard
      .readText()
      .then((current) => {
        if (current === value) {
          return navigator.clipboard.writeText("");
        }
      })
      .catch(() => {
        // Reading the clipboard can be refused; losing the clear is acceptable.
      });
  }, CLEAR_AFTER_MS);
}

export const clipboardClearSeconds = CLEAR_AFTER_MS / 1000;
