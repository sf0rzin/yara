/**
 * Update checking.
 *
 * Every artifact is signed with a key that exists only in CI, and the public
 * half is compiled into this binary. The server that offers an update therefore
 * cannot forge one — it can withhold or corrupt a download, and that is the
 * whole of what a compromised host gets. Verification happens in Rust, inside
 * the plugin, before anything is executed.
 *
 * The check runs once at launch and is deliberately quiet about failure: an
 * unreachable update server is indistinguishable here from "you are current",
 * because a network problem must not be able to make the app feel broken. The
 * cost is that a permanently broken endpoint goes unnoticed, which is the right
 * trade for a background check and the wrong one for a button the user pressed.
 */

export interface AvailableUpdate {
  /** The version being offered, for display. Never trust it for comparison. */
  version: string;
  /** Release notes from the manifest, shown verbatim. */
  notes: string | null;
  /**
   * Downloads, verifies, installs, and relaunches.
   *
   * This ends the process, so the vault locks. Callers must have said so
   * before getting here.
   */
  install: () => Promise<void>;
}

/** False in a browser dev session, where there is no plugin to call. */
function insideTauri(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export async function checkForUpdate(): Promise<AvailableUpdate | null> {
  if (!insideTauri()) return null;

  try {
    // Imported lazily so a browser dev session never loads the plugin at all.
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (!update) return null;

    return {
      version: update.version,
      notes: update.body?.trim() || null,
      install: async () => {
        await update.downloadAndInstall();
        const { relaunch } = await import("@tauri-apps/plugin-process");
        await relaunch();
      },
    };
  } catch {
    return null;
  }
}
