/**
 * Update checking.
 *
 * Every artifact is signed with a key that exists only in CI, and the public
 * half is compiled into this binary. The server that offers an update therefore
 * cannot forge one — it can withhold or corrupt a download, and that is the
 * whole of what a compromised host gets. Verification happens in Rust, inside
 * the plugin, before anything is executed.
 *
 * The check runs once at launch and stays quiet: an unreachable update server
 * must not be able to make the app feel broken.
 *
 * Quiet is not the same as silent, and this used to be silent. Every failure
 * was swallowed into `null`, which is the same value that means "you are
 * current" — so a check that reached the server, got a valid manifest, and then
 * failed was indistinguishable from having nothing to offer. That state is not
 * hypothetical: it happened, and diagnosing it took the origin's access log to
 * establish that the request was even being made.
 *
 * So the outcome is now a value with three cases, the last one is kept for the
 * settings screen to show, and nothing about it interrupts anybody.
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

export type UpdateCheck =
  | { state: "current" }
  | { state: "available"; update: AvailableUpdate }
  /** The check itself did not complete. Says why, for someone reading it. */
  | { state: "failed"; reason: string }
  /** Outside Tauri, where there is no plugin to ask. */
  | { state: "unavailable" };

export interface CheckRecord {
  at: number;
  result: UpdateCheck;
}

/**
 * The last check, kept at module scope.
 *
 * The notice and the settings screen both want this and never mount together,
 * so passing it between them would mean lifting it to the top of the app to
 * serve two consumers that never meet.
 */
let last: CheckRecord | null = null;

export function lastUpdateCheck(): CheckRecord | null {
  return last;
}

/** False in a browser dev session, where there is no plugin to call. */
function insideTauri(): boolean {
  return "__TAURI_INTERNALS__" in window;
}

export async function checkForUpdate(): Promise<UpdateCheck> {
  const record = (result: UpdateCheck): UpdateCheck => {
    last = { at: Math.floor(Date.now() / 1000), result };
    return result;
  };

  if (!insideTauri()) return record({ state: "unavailable" });

  try {
    // Imported lazily so a browser dev session never loads the plugin at all.
    const { check } = await import("@tauri-apps/plugin-updater");
    const update = await check();
    if (!update) return record({ state: "current" });

    return record({
      state: "available",
      update: {
        version: update.version,
        notes: update.body?.trim() || null,
        install: async () => {
          await update.downloadAndInstall();
          const { relaunch } = await import("@tauri-apps/plugin-process");
          await relaunch();
        },
      },
    });
  } catch (caught) {
    return record({ state: "failed", reason: describe(caught) });
  }
}

/** The version this build reports, which is the number a check compares against. */
export async function runningVersion(): Promise<string | null> {
  if (!insideTauri()) return null;
  try {
    const { getVersion } = await import("@tauri-apps/api/app");
    return await getVersion();
  } catch {
    return null;
  }
}

function describe(caught: unknown): string {
  if (caught instanceof Error) return caught.message;
  if (typeof caught === "string") return caught;
  return "the check failed without saying why";
}
