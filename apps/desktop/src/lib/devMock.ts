/**
 * A fake Tauri IPC layer, for iterating on the interface in a plain browser.
 *
 * Installs itself only in a dev build that is not running inside Tauri, so it
 * can never reach a shipped binary. The data is invented; nothing here touches
 * a real vault, and no real cryptography runs.
 */

import { version as runningVersion } from "../../package.json";
// Types only, erased at build time: the mock stays a standalone stand-in for
// the IPC, but the shapes it answers with are the ones the app expects rather
// than a second opinion about them.
import type { Cleared, PasswordRecipe, Startup } from "../api";

/**
 * The version an offered update would carry.
 *
 * Read from the manifest rather than written down, because a literal here goes
 * stale at every release and then quietly lies about which version is running
 * — which is the one thing the updates section exists to tell the truth about.
 */
function nextVersion(current: string): string {
  const parts = current.split(".");
  const patch = Number(parts[2] ?? 0);
  return [parts[0] ?? "0", parts[1] ?? "0", String(patch + 1)].join(".");
}

interface MockField {
  label: string;
  value: string;
  secret: boolean;
}

interface MockItem {
  id: string;
  name: string;
  kind: "login" | "card" | "note";
  username: string | null;
  password: string | null;
  url: string | null;
  notes: string | null;
  folder: string | null;
  totpSeed: number | null;
  fields: MockField[];
  tags: string[];
  updatedAt: number;
}

const items: MockItem[] = [
  {
    id: "1",
    name: "GitHub",
    kind: "login",
    username: "anthony@axono.dev",
    password: "7Gk!pQ2vXm#9Lz@4Rw",
    url: "https://github.com",
    totpSeed: 11,
    folder: null,
    notes: null,
    fields: [],
    tags: ["work"],
    updatedAt: 1_753_000_000,
  },
  {
    id: "2",
    name: "Figma",
    kind: "login",
    username: "anthony@axono.dev",
    password: "hunter2",
    url: "https://figma.com",
    totpSeed: null,
    folder: null,
    notes: null,
    fields: [],
    tags: ["design"],
    updatedAt: 1_752_900_000,
  },
  {
    id: "3",
    name: "AWS Console",
    kind: "login",
    username: "root",
    password: "Tz3$vLp8Qn!wEr5Ka",
    url: "https://console.aws.amazon.com",
    totpSeed: 29,
    folder: null,
    notes: null,
    fields: [],
    tags: ["infra"],
    updatedAt: 1_752_800_000,
  },
  {
    id: "4",
    name: "Linear",
    kind: "login",
    username: "anthony@axono.dev",
    password: "hunter2",
    url: "https://linear.app",
    totpSeed: null,
    folder: null,
    notes: null,
    fields: [],
    tags: [],
    updatedAt: 1_752_700_000,
  },
  {
    id: "5",
    name: "Stripe",
    kind: "login",
    username: "finance@axono.dev",
    password: "Bq7#mXt2Vd!5Zc9Ln",
    url: "https://dashboard.stripe.com",
    totpSeed: 47,
    folder: "Work",
    notes: "Live keys rotate every 90 days. The restricted key below is the\nonly one safe to paste into a script.",
    // One of each, so the detail pane has both shapes to render and the rule
    // about which values a listing may carry is exercised.
    fields: [
      { label: "Merchant ID", value: "acct_1M2n3O4p5Q", secret: false },
      { label: "Restricted key", value: "rk_live_51M2n3O4p5Q6r7S", secret: true },
    ],
    tags: ["finance"],
    updatedAt: 1_752_600_000,
  },
  {
    id: "6",
    name: "Personal Visa",
    kind: "card",
    username: null,
    password: null,
    url: null,
    totpSeed: null,
    folder: null,
    notes: null,
    fields: [],
    tags: [],
    updatedAt: 1_752_500_000,
  },
  {
    id: "7",
    name: "Recovery codes",
    kind: "note",
    username: null,
    password: null,
    url: null,
    totpSeed: null,
    folder: null,
    notes: null,
    fields: [],
    tags: [],
    updatedAt: 1_752_400_000,
  },
  // What an authenticator export leaves behind: a name and a code, nothing to
  // log in to. It carries the login kind because there is no other one, and it
  // is here so the rule that keeps it out of Logins is exercised rather than
  // assumed.
  {
    id: "8",
    name: "Banco Inter",
    kind: "login",
    username: "anthony",
    password: null,
    url: null,
    totpSeed: 53,
    folder: null,
    notes: null,
    fields: [],
    tags: [],
    updatedAt: 1_752_300_000,
  },
];

let unlocked = false;

/**
 * The dev vault's master password.
 *
 * `unlock_vault` takes whatever it is given — there is no cryptography here to
 * refuse anything, and a browser session locked out of an invented vault helps
 * nobody — but it remembers it. That memory is what gives
 * `change_master_password` something to check the current password against,
 * and checking it is the entire reason that command asks for one.
 */
let mockMasterPassword = "hunter2";

/** Set once `recover_vault` has run, so startup stops offering the recovery. */
let mockRecovered = false;

let mockAutoLock: number | null = 15 * 60;
let mockIcons = true;

/* --- the clipboard ------------------------------------------------------ */

/** Matches `CLIPBOARD_CLEARED_EVENT` in `src-tauri/src/lib.rs`. */
const CLIPBOARD_CLEARED_EVENT = "clipboard://cleared";
/** Matches `CLEAR_AFTER_SECONDS` in `src-tauri/src/clipboard.rs`. */
const CLEAR_AFTER_SECONDS = 20;

/** One of the two reasons `Cleared::Failed` carries a string at all. */
const CLIPBOARD_REFUSED = "the clipboard could not be opened (Access is denied. (os error 5))";

/** Copies handed out whose clear has not fired yet, by token. */
const pendingClears = new Map<number, ReturnType<typeof setTimeout>>();
let clipboardToken = 0;
/** Whether anything of this app's is still on the imaginary clipboard. */
let clipboardHolds = false;

/**
 * `?clipboard=` picks what the timed clear reports.
 *
 * `history` is Windows refusing the exclusion formats — the case where the
 * interface must stop calling the copy private. `failed` is the clear itself
 * being refused, which leaves the secret sitting there. `taken` is somebody
 * else's copy arriving first, which is not a failure at all. None of the three
 * can be produced on demand on a real machine.
 */
function askedOfClipboard(): string | null {
  return new URLSearchParams(window.location.search).get("clipboard");
}

function clearedAs(outcome: Cleared["outcome"]): Cleared {
  return outcome === "failed" ? { outcome, detail: CLIPBOARD_REFUSED } : { outcome };
}

function timedOutcome(): Cleared {
  const asked = askedOfClipboard();
  if (asked === "failed") return clearedAs("failed");
  if (asked === "taken") return clearedAs("alreadyGone");
  return clearedAs("wiped");
}

/**
 * A copy's time being up.
 *
 * Mirrors `SecretClipboard::clear_copy`: a copy that a later one has replaced
 * reports `alreadyGone` rather than emptying a clipboard it no longer owns —
 * and it still reports, which is exactly the event the frontend's token filter
 * has to throw away.
 */
function fireClear(token: number, forced?: Cleared): void {
  const timer = pendingClears.get(token);
  if (timer === undefined) return;
  clearTimeout(timer);
  pendingClears.delete(token);

  const superseded = token !== clipboardToken || !clipboardHolds;
  const result = forced ?? (superseded ? clearedAs("alreadyGone") : timedOutcome());
  if (result.outcome === "wiped") clipboardHolds = false;

  emit(CLIPBOARD_CLEARED_EVENT, { token, result });
}

let mockFolders: string[] = ["Work", "Personal"];

const unixNow = () => Math.floor(Date.now() / 1000);

/** Enrolled by default: the screen worth looking at is the one with state on it. */
let mockSync: {
  enrolled: boolean;
  baseUrl: string | null;
  accountId: string | null;
  deviceId: string | null;
  lastSyncedAt: number | null;
} = {
  enrolled: true,
  baseUrl: "https://yara.lat",
  accountId: "9f2c41a8-0e77-4c19-b3de-5a1f8c66d204",
  deviceId: "d41d8cd9-8f00-3204-a980-0998ecf8427e",
  lastSyncedAt: unixNow() - 1_800,
};

let mockRevision = 41;

interface MockSubscription {
  plan: string | null;
  amountMinor: number;
  currency: string;
  cadence: "monthly" | "yearly" | "usage";
  nextCharge: number | null;
  paidWith: string | null;
}

const day = 86_400;
const soon = (days: number) => Math.floor(Date.now() / 1000) + days * day;

/**
 * Invented charges, chosen to exercise the cases the view has to get right:
 * one this week, one later this month, a yearly plan that has to be spread,
 * and a usage-based one that must stay out of the total.
 */
const subscriptions: Record<string, MockSubscription> = {
  "1": {
    plan: "GitHub Pro",
    amountMinor: 400,
    currency: "USD",
    cadence: "monthly",
    nextCharge: soon(3),
    paidWith: "6",
  },
  "2": {
    plan: "Figma Professional",
    amountMinor: 1500,
    currency: "USD",
    cadence: "monthly",
    nextCharge: soon(19),
    paidWith: "6",
  },
  "3": {
    plan: "AWS",
    amountMinor: 0,
    currency: "USD",
    cadence: "usage",
    nextCharge: null,
    paidWith: null,
  },
  "5": {
    plan: "Stripe Atlas",
    amountMinor: 24_000,
    currency: "USD",
    cadence: "yearly",
    nextCharge: soon(96),
    // Points at a card that is not in the list, so the "gone" path is
    // reachable in a dev session rather than only in production.
    paidWith: "99",
  },
};

const subView = (itemId: string, sub: MockSubscription) => ({
  itemId,
  itemName: items.find((i) => i.id === itemId)?.name ?? "Unknown",
  ...sub,
  paidWithName:
    items.find((i) => i.id === sub.paidWith && i.kind === "card")?.name ?? null,
  monthlyMinor:
    sub.cadence === "usage"
      ? null
      : sub.cadence === "yearly"
        ? Math.floor(sub.amountMinor / 12)
        : sub.amountMinor,
});

const summary = (item: MockItem) => {
  const reused =
    item.password !== null &&
    items.some((other) => other.id !== item.id && other.password === item.password);

  return {
    id: item.id,
    name: item.name,
    kind: item.kind,
    username: item.username,
    url: item.url,
    folder: item.folder,
    tags: item.tags,
    hasPassword: item.password !== null,
    hasTotp: item.totpSeed !== null,
    reused,
    missingSecondFactor:
      item.kind === "login" && item.password !== null && item.totpSeed === null,
    updatedAt: item.updatedAt,
    // Invented, like everything else here — but present, because a field the
    // mock omits renders as "Unknown" or, worse, as a claim the real backend
    // would never make.
    createdAt: item.updatedAt - 86_400 * 420,
  };
};

function matches(item: MockItem, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const plain = [item.name, item.username, item.url]
    .filter((field): field is string => Boolean(field))
    .some((field) => field.toLowerCase().includes(q));

  // Mirrors `Item::matches`: a field's label is always searchable, its value
  // only when it is not a secret. Never the password.
  return (
    plain ||
    item.fields.some(
      (field) =>
        field.label.toLowerCase().includes(q) ||
        (!field.secret && field.value.toLowerCase().includes(q)),
    )
  );
}

/**
 * A stand-in authenticator export.
 *
 * Entries rather than a file: nothing here parses anything, and what the import
 * screen needs is a preview carrying all three outcomes at once, so every
 * branch of the confirm step — will be added, already here, cannot be read —
 * is reachable in a browser session. "Banco Inter" is already in the vault
 * above, which is what makes the duplicate branch real rather than declared.
 */
const importFixture: { entries: string[]; skipped: { name: string; reason: string }[] } = {
  entries: ["Cloudflare", "Namecheap", "Banco Inter"],
  skipped: [
    { name: "Old router", reason: "the URI carries no secret" },
    { name: "line 14", reason: "not an otpauth:// URI" },
  ],
};

/**
 * The real command matches by seed, because the same code saved under two
 * labels is still the same code. The fixture has no seeds to match on, so this
 * matches by name against the items that already carry one — close enough to
 * exercise the branch, and said out loud so nobody reads it as the rule.
 */
function alreadyImported(name: string): boolean {
  return items.some((item) => item.name === name && item.totpSeed !== null);
}

function strengthOf(password: string): "weak" | "fair" | "strong" {
  if (password.length < 12) return "weak";
  let charset = 0;
  if (/[a-z]/.test(password)) charset += 26;
  if (/[A-Z]/.test(password)) charset += 26;
  if (/[0-9]/.test(password)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charset += 33;
  const bits = password.length * Math.log2(Math.max(charset, 2));
  return bits < 50 ? "weak" : bits < 75 ? "fair" : "strong";
}

function generatedPassword(recipe: PasswordRecipe): string {
  if (recipe.length < 12) {
    throw new Error("cannot generate a password: length is below the minimum");
  }
  if (recipe.length > 128) {
    throw new Error("cannot generate a password: length is above the maximum");
  }

  const classes = [
    recipe.lowercase ? "abcdefghijklmnopqrstuvwxyz" : "",
    recipe.uppercase ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "",
    recipe.digits ? "0123456789" : "",
    recipe.symbols ? "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~" : "",
  ].filter(Boolean);
  if (classes.length === 0) {
    throw new Error("cannot generate a password: no character classes are enabled");
  }

  const randomIndex = (length: number) => {
    const accepted = 256 - (256 % length);
    const byte = new Uint8Array(1);
    do {
      crypto.getRandomValues(byte);
    } while (byte[0] >= accepted);
    return byte[0] % length;
  };

  const alphabet = classes.join("");
  const characters = classes.map(
    (characters) => characters[randomIndex(characters.length)],
  );
  while (characters.length < recipe.length) {
    characters.push(alphabet[randomIndex(alphabet.length)]);
  }
  for (let upper = characters.length - 1; upper > 0; upper -= 1) {
    const other = randomIndex(upper + 1);
    [characters[upper], characters[other]] = [characters[other], characters[upper]];
  }
  return characters.join("");
}

const handlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  // Kept in step with the backend, which still has this command, though nothing
  // in the interface asks it any more: it cannot tell a first run from a save
  // that was interrupted, and `vault_startup` was added because those two want
  // opposite offers.
  vault_exists: () => !new URLSearchParams(window.location.search).has("setup"),

  vault_startup: (): Startup => {
    if (mockRecovered) return "locked";
    // `?recover` is the only way this screen will ever be looked at. Reaching
    // it for real needs a vault file to have vanished between two renames,
    // which is not a state anybody can arrange on purpose.
    if (new URLSearchParams(window.location.search).has("recover")) return "recover";
    return new URLSearchParams(window.location.search).has("setup") ? "setup" : "locked";
  },

  recover_vault: () => {
    // `?recover=broken` refuses, so the screen's failure line can be read
    // without arranging a corrupted backup.
    if (new URLSearchParams(window.location.search).get("recover") === "broken") {
      throw new Error("nothing beside this vault could be read as one");
    }
    mockRecovered = true;
  },

  is_unlocked: () => unlocked,
  create_vault: (args) => {
    mockMasterPassword = String(args.password ?? "");
    unlocked = true;
  },
  unlock_vault: (args) => {
    mockMasterPassword = String(args.password ?? "");
    unlocked = true;
  },
  lock_vault: () => {
    unlocked = false;
  },

  list_items: (args) => {
    const query = String(args.query ?? "");
    const kind = args.kind as MockItem["kind"] | null;
    const withTotp = args.withTotp as boolean | null;
    const folder = args.folder as string | null;

    return items
      .filter((item) => matches(item, query))
      // Mirrors the same rule in `list_items`: a bare two-factor seed carries
      // the login kind for want of another, and is not a login.
      .filter((item) =>
        kind === "login"
          ? item.kind === "login" && item.password !== null
          : !kind || item.kind === kind,
      )
      .filter((item) => withTotp !== true || item.totpSeed !== null)
      .filter((item) => !folder || item.folder === folder)
      .map(summary);
  },

  recent_items: (args) =>
    [...items]
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, Number(args.limit ?? 5))
      .map(summary),

  // The two calls the updates section makes. Without them a dev session
  // reported "the check failed", which is honest about the mock and useless
  // for looking at the screen — the state worth seeing is a real answer.
  //
  // `?update=available` offers one, so the notice can be looked at without
  // waiting for a release; `?update=broken` fails, so the sentence that says
  // why can be looked at without breaking anything.
  "plugin:app|version": () => runningVersion,
  "plugin:updater|check": () => {
    const asked = new URLSearchParams(window.location.search).get("update");
    if (asked === "broken") throw new Error("could not reach the update server");
    if (asked !== "available") return null;
    return {
      available: true,
      currentVersion: runningVersion,
      version: nextVersion(runningVersion),
      date: null,
      body: "One fix, and a smaller sidebar.",
      rid: 1,
      rawJson: {},
    };
  },

  folders: () => mockFolders,

  create_folder: (args) => {
    const name = String(args.name ?? "").trim();
    if (name && !mockFolders.includes(name)) mockFolders.push(name);
  },

  rename_folder: (args) => {
    const from = String(args.from);
    const to = String(args.to).trim();
    const at = mockFolders.indexOf(from);
    if (at < 0) throw new Error("no folder called " + from);
    if (mockFolders.includes(to)) throw new Error(to + " already exists");
    mockFolders[at] = to;
    // Both halves, like the vault: an item still pointing at the old name is
    // an item that has quietly left its folder.
    for (const item of items) if (item.folder === from) item.folder = to;
  },

  delete_folder: (args) => {
    const name = String(args.name);
    mockFolders = mockFolders.filter((f) => f !== name);
    let freed = 0;
    // The items outlive the folder.
    for (const item of items) {
      if (item.folder === name) {
        item.folder = null;
        freed += 1;
      }
    }
    return freed;
  },

  reorder_folders: (args) => {
    const names = (args.names as string[]) ?? [];
    const kept = names.filter((n) => mockFolders.includes(n));
    mockFolders = [...kept, ...mockFolders.filter((n) => !kept.includes(n))];
  },

  set_item_folder: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    if (!item) throw new Error("item not found");
    const folder = (args.folder as string | null) ?? null;
    if (folder && !mockFolders.includes(folder)) {
      throw new Error("no folder called " + folder);
    }
    item.folder = folder;
  },

  reorder_items: (args) => {
    const ids = (args.ids as string[]) ?? [];
    const moved: MockItem[] = [];
    for (const id of ids) {
      const at = items.findIndex((i) => i.id === id);
      if (at >= 0) moved.push(items.splice(at, 1)[0]);
    }
    // What the caller did not mention keeps its relative place, rather than
    // being dropped by a stale list.
    items.unshift(...moved);
  },

  vault_counts: () => ({
    total: items.length,
    logins: items.filter((i) => i.kind === "login" && i.password !== null).length,
    cards: items.filter((i) => i.kind === "card").length,
    notes: items.filter((i) => i.kind === "note").length,
    authenticator: items.filter((i) => i.totpSeed !== null).length,
  }),

  list_subscriptions: () =>
    Object.entries(subscriptions)
      .map(([itemId, sub]) => subView(itemId, sub))
      .sort((a, b) => {
        if (a.nextCharge === null) return 1;
        if (b.nextCharge === null) return -1;
        return a.nextCharge - b.nextCharge;
      }),

  item_subscription: (args) => {
    const sub = subscriptions[String(args.id)];
    return sub ? subView(String(args.id), sub) : null;
  },

  set_subscription: (args) => {
    const id = String(args.id);
    if (args.subscription === null) delete subscriptions[id];
    else subscriptions[id] = args.subscription as MockSubscription;
  },

  // No network in a dev session, and none wanted: the point of the proxy is
  // that the browser never reaches a site directly, so the mock returning null
  // exercises exactly the fallback a blocked or iconless domain produces.
  icon_for: () => null,
  icons_enabled: () => mockIcons,
  set_icons_enabled: (args) => {
    mockIcons = Boolean(args.enabled);
  },

  // Sync. Absent until now, which meant the settings screen opened with
  // "mock: no handler for sync_status" in a loud notice at the top — the
  // screen could not be looked at, let alone designed.
  sync_status: () => mockSync,
  sync_enrol: (args) => {
    mockSync = {
      enrolled: true,
      baseUrl: String(args.baseUrl ?? "https://yara.lat"),
      accountId: "9f2c41a8-0e77-4c19-b3de-5a1f8c66d204",
      deviceId: "d41d8cd9-8f00-3204-a980-0998ecf8427e",
      lastSyncedAt: unixNow(),
    };
    return {
      kit: "K7QM-3XPD-9WRF-2LHN-8BVC-4TGS",
      accountId: mockSync.accountId,
    };
  },
  /*
   * Joining an existing account with a recovery kit.
   *
   * Refuses on a kit that is not the shape `SecretKey::from_kit` accepts, so
   * the screen's failure path is reachable — and refuses with the same wording
   * for a bad kit and a bad password, because the real command deliberately
   * cannot tell you which half you got wrong.
   */
  sync_join: (args) => {
    const kit = String(args.kit ?? "").trim();
    const accountId = String(args.accountId ?? "").trim();
    const password = String(args.password ?? "");

    const shaped = /^[0-9A-Za-z]{4}(-[0-9A-Za-z]{4}){3,5}$/.test(kit);
    if (!shaped || accountId.length === 0 || password.length === 0) {
      throw new Error("that account, password and recovery kit do not go together");
    }

    mockSync = {
      enrolled: true,
      baseUrl: String(args.baseUrl ?? "https://yara.lat"),
      accountId,
      deviceId: "b7e2f0a1-55cc-4f3e-9a12-6d0c4471aa93",
      lastSyncedAt: unixNow(),
    };
    mockRevision += 1;
    return {
      pulled: 6,
      pushed: items.length,
      conflicts: 0,
      unprovenDeletes: 0,
      revision: mockRevision,
    };
  },
  sync_now: () => {
    mockSync = { ...mockSync, lastSyncedAt: unixNow() };
    mockRevision += 1;
    // `revision` is not optional in `SyncReport`. Omitting it made the mock's
    // report a shape the real command never returns, which is exactly the kind
    // of drift that lets a field be added to the type and never rendered.
    //
    // `unprovenDeletes` is here for the same reason: it is the count that says
    // a server tried to delete something it could not prove, and a mock that
    // never reports one is a mock in which that line can never be seen.
    return {
      pulled: 2,
      pushed: 1,
      conflicts: 0,
      unprovenDeletes: new URLSearchParams(window.location.search).has("unproven") ? 3 : 0,
      revision: mockRevision,
    };
  },
  sync_forget: () => {
    mockSync = {
      enrolled: false,
      baseUrl: null,
      accountId: null,
      deviceId: null,
      lastSyncedAt: null,
    };
  },

  auto_lock_seconds: () => mockAutoLock,
  set_auto_lock_seconds: (args) => {
    mockAutoLock = (args.seconds as number | null) ?? null;
  },

  // Both failures are errors in the real command, and an empty string is not
  // one of its answers. Returning "" here meant a dev session showed a blank
  // password field where the app would in fact have shown a reason.
  reveal_password: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    if (!item) throw new Error(`item ${args.id} not found`);
    if (item.password === null) throw new Error("this item has no password");
    return item.password;
  },

  totp_code: (args) => {
    const item = items.find((i) => i.id === args.id);
    const period = 30;
    const now = Math.floor(Date.now() / 1000);
    const step = Math.floor(now / period);
    const code = String(((step * 7919 + (item?.totpSeed ?? 0) * 104729) % 1_000_000)).padStart(6, "0");
    return { code, secondsRemaining: period - (now % period), period };
  },

  estimate_strength: (args) => strengthOf(String(args.password ?? "")),

  generate_password: (args) => generatedPassword(args.recipe as PasswordRecipe),

  // These used to be stubs — `add_item` returned the string "new" and
  // `delete_item` did nothing — so nothing written in a dev session survived
  // the next render and editing could not be exercised at all.
  add_item: (args) => {
    const item = args.item as Record<string, unknown>;
    const id = String(items.length + 1);
    items.push({
      id,
      name: String(item.name ?? "Untitled"),
      kind: (item.kind as MockItem["kind"]) ?? "login",
      username: (item.username as string) ?? null,
      password: (item.password as string) ?? null,
      url: (item.url as string) ?? null,
      notes: (item.notes as string) ?? null,
      folder: (item.folder as string) ?? null,
      totpSeed: item.use_scanned_totp || item.totp_uri ? 17 : null,
      fields: ((item.fields as MockField[]) ?? []).map((f) => ({ ...f })),
      tags: (item.tags as string[]) ?? [],
      updatedAt: unixNow(),
    });
    return id;
  },

  update_item: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    if (!item) throw new Error(`item ${args.id} not found`);
    const edit = args.edit as Record<string, unknown>;

    item.name = String(edit.name ?? item.name);
    item.kind = (edit.kind as MockItem["kind"]) ?? item.kind;
    item.username = (edit.username as string) ?? null;
    item.url = (edit.url as string) ?? null;
    item.notes = (edit.notes as string) ?? null;
    item.fields = ((edit.fields as MockField[]) ?? []).map((f) => ({ ...f }));
    // Null leaves the password alone; empty string removes it. Mirrors the
    // same distinction in `update_item` — the form never sees the current
    // password, so it cannot say "unchanged" by sending the same value.
    if (edit.password !== null && edit.password !== undefined) {
      item.password = String(edit.password) || null;
    }
    item.updatedAt = unixNow();
  },

  item_extras: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    return {
      hasNotes: Boolean(item?.notes),
      fields: (item?.fields ?? []).map((f) => ({
        label: f.label,
        // A secret's value is withheld here exactly as the backend withholds
        // it: null means "ask", never "empty".
        value: f.secret ? null : f.value,
        secret: f.secret,
      })),
    };
  },

  reveal_field: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    const field = item?.fields.find((f) => f.label === String(args.label));
    if (!field) throw new Error(`this item has no field called ${args.label}`);
    return field.value;
  },

  reveal_notes: (args) => {
    const item = items.find((i) => i.id === String(args.id));
    if (!item?.notes) throw new Error("this item has no notes");
    return item.notes;
  },

  delete_item: (args) => {
    const index = items.findIndex((i) => i.id === String(args.id));
    if (index >= 0) items.splice(index, 1);
  },

  /*
   * The file picker, which is the first thing the Import dialog reaches for.
   *
   * Without it the dialog failed on "Choose an export file" and the preview it
   * exists to show could never be reached — so the two handlers below would
   * have been unreachable on their own. Returns a path rather than null,
   * because a cancelled picker is the one outcome that renders nothing.
   */
  "plugin:dialog|open": () => "C:\\Users\\anthony\\Downloads\\proton-authenticator-export.txt",

  // Import. Absent until now, so the dialog opened straight into "mock: no
  // handler for preview_import" — the same failure the sync handlers above
  // were added to fix, on the one screen whose entire job is to show you what
  // is about to happen before it happens.
  preview_import: () => ({
    ready: importFixture.entries.filter((name) => !alreadyImported(name)),
    duplicates: importFixture.entries.filter(alreadyImported),
    skipped: importFixture.skipped.map((problem) => ({ ...problem })),
  }),

  run_import: () => {
    const ready = importFixture.entries.filter((name) => !alreadyImported(name));
    for (const name of ready) {
      items.push({
        id: String(items.length + 1),
        name,
        kind: "login",
        // What an authenticator export leaves behind: a code and nothing to log
        // in to. Same shape as Banco Inter above.
        username: null,
        password: null,
        url: null,
        notes: null,
        folder: null,
        totpSeed: 60 + items.length,
        fields: [],
        tags: [],
        updatedAt: unixNow(),
      });
    }
    // Written for real, so importing the same file twice reports everything as
    // a duplicate and the "Nothing to import" branch is reachable too.
    return ready.length;
  },

  /*
   * It has a caller now: the Settings screen.
   *
   * The current password is checked here rather than waved through, because
   * that check is the whole of what this command is for — it exists so nothing
   * running inside the webview can re-key a vault on its own say-so, and a mock
   * that accepted anything would hide the one path worth looking at. The
   * refusal is worded as the vault words it: both possible causes, neither
   * confirmed.
   */
  change_master_password: (args) => {
    if (String(args.currentPassword ?? "") !== mockMasterPassword) {
      throw new Error("could not decrypt: wrong password or corrupted data");
    }
    mockMasterPassword = String(args.newPassword ?? "");
  },

  /*
   * The clipboard, which is a backend concern now.
   *
   * The frontend used to write, wait and read back through `navigator`, so a
   * dev session exercised the real webview clipboard and none of what the
   * interface now has to say about a copy. These two plus the event below are
   * what make those sentences reachable in a browser.
   */
  copy_secret: () => {
    const token = ++clipboardToken;
    clipboardHolds = true;
    pendingClears.set(
      token,
      setTimeout(() => fireClear(token), CLEAR_AFTER_SECONDS * 1000),
    );
    return {
      excludedFromHistory: askedOfClipboard() !== "history",
      clearsIn: CLEAR_AFTER_SECONDS,
      token,
    };
  },

  clear_clipboard: (): Cleared => {
    if (!clipboardHolds) return clearedAs("alreadyGone");
    clipboardHolds = false;
    // The timer is left running, exactly as the real command leaves it: when it
    // fires it will find nothing of ours and say so.
    return clearedAs("wiped");
  },

  // No real decoding here — the mock exists to exercise the interface, and
  // wiring an actual QR decoder into it would just be a second implementation
  // to keep in step with the Rust one.
  scan_qr_from_clipboard: () => ({
    issuer: "GitHub",
    account: "anthony@axono.dev",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    sampleCode: "482915",
  }),
  scan_qr_from_path: () => ({
    issuer: "GitHub",
    account: "anthony@axono.dev",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    sampleCode: "482915",
  }),
  clear_scanned_totp: () => undefined,

  list_grants: () => [
    {
      id: "g1",
      item: "AWS Console",
      field: "password",
      program: "claude.exe",
      scope: "run",
      permits: "run `terraform apply`",
      secondsRemaining: 540,
      remainingUses: 4,
    },
  ],
  revoke_grant: () => true,
  audit_entries: () => [
    {
      id: "a1",
      at: Math.floor(Date.now() / 1000) - 30,
      program: "claude.exe",
      item: "AWS Console",
      summary: "ran `terraform apply` with $AWS_SECRET_ACCESS_KEY",
      reason: "apply the staging plan",
      allowed: true,
      notable: false,
    },
    {
      id: "a2",
      at: Math.floor(Date.now() / 1000) - 900,
      program: "claude.exe",
      item: "Stripe",
      summary: "revealed the plaintext",
      reason: "paste into a config file",
      allowed: true,
      notable: true,
    },
    {
      id: "a3",
      at: Math.floor(Date.now() / 1000) - 3600,
      program: "unknown.exe",
      item: "GitHub",
      summary: "revealed the plaintext",
      reason: "sync repositories",
      allowed: false,
      notable: true,
    },
  ],
  resolve_approval: () => undefined,
};

/**
 * Minimal stand-in for Tauri's event plumbing.
 *
 * Enough for `listen` to work, plus a hook so an approval prompt can be fired
 * by hand from the console — that dialog is the most consequential screen in
 * the app and iterating on it should not require a full rebuild.
 */
interface Registration {
  event: string;
  handler: (event: unknown) => void;
}

/** Matches `APPROVAL_EVENT` in `src-tauri/src/broker.rs`. */
const APPROVAL_EVENT = "broker://approval";

let nextEventId = 1;
const listeners = new Map<number, Registration>();

function registerListener(args: Record<string, unknown>): number {
  const id = nextEventId++;
  const event = String(args.event);
  listeners.set(id, {
    event,
    handler: args.handler as (event: unknown) => void,
  });
  if (event === APPROVAL_EVENT) flushPendingSample();
  return id;
}

/**
 * Unregistering has to actually unregister.
 *
 * React's strict mode mounts effects twice, so a mock that ignores this ends up
 * with two listeners and delivers every event twice — which looks exactly like
 * an application bug and is not one.
 */
function unregisterListener(args: Record<string, unknown>): void {
  listeners.delete(Number(args.eventId));
}

/** Returns how many listeners took delivery, which is how a sample knows to stop waiting. */
function emit(event: string, payload: unknown): number {
  let delivered = 0;
  for (const registration of listeners.values()) {
    if (registration.event === event) {
      registration.handler({ event, id: 0, payload });
      delivered += 1;
    }
  }
  return delivered;
}

/**
 * The samples carry no id of their own.
 *
 * The broker mints a fresh uuid per request, and the dialog is keyed on it. A
 * fixture that reused one id made React treat a queued second request as the
 * same dialog and keep the first one's state — so the new prompt arrived
 * already reading "Denying…" with every button disabled.
 */
const SAMPLE_PROMPTS: Record<string, Record<string, unknown>> = {
  run: {
    program: "claude.exe",
    programPath: "C:\\Users\\anthony\\AppData\\Local\\Programs\\claude\\claude.exe",
    pid: 21804,
    item: "AWS Console",
    field: "password",
    mode: "run",
    command: "terraform apply -auto-approve",
    envVar: "AWS_SECRET_ACCESS_KEY",
    reason: "apply the staging plan I just showed you",
    discloses: false,
  },
  reveal: {
    program: "unknown.exe",
    programPath: null,
    pid: 9931,
    item: "Stripe",
    field: "password",
    mode: "reveal",
    command: null,
    envVar: null,
    reason: "I need to read it to continue",
    discloses: true,
  },
  // A run that is a reveal in disguise, so the heavier wording can be seen
  // without a real broker to talk to.
  shell: {
    program: "claude.exe",
    programPath: "C:\\Users\\anthony\\AppData\\Local\\Programs\\claude\\claude.exe",
    pid: 21804,
    item: "AWS Console",
    field: "password",
    mode: "run",
    command: "cmd /C echo %AWS_SECRET_ACCESS_KEY%",
    envVar: "AWS_SECRET_ACCESS_KEY",
    reason: "just checking the value is set",
    discloses: true,
  },
};

type SampleKind = keyof typeof SAMPLE_PROMPTS;

let nextPromptId = 1;

function sample(kind: SampleKind): Record<string, unknown> {
  return { ...SAMPLE_PROMPTS[kind], id: `p-${kind}-${nextPromptId++}` };
}

/**
 * A sample asked for by query string, waiting for somebody to hear it.
 *
 * The vault starts locked and only the unlocked screen subscribes to approval
 * events, so firing on a timer meant firing into an empty room: on any normal
 * load the sample was emitted, delivered to nobody, and silently lost.
 */
let pendingSample: SampleKind | null = null;

function flushPendingSample(): void {
  const kind = pendingSample;
  if (kind === null) return;

  // Deferred, and cleared only once a listener has actually taken delivery.
  // React's strict mode subscribes, tears that subscription down and
  // subscribes again, so the registration that triggered this may be gone by
  // the time the timer runs.
  setTimeout(() => {
    if (pendingSample !== kind) return;
    if (emit(APPROVAL_EVENT, sample(kind)) > 0) pendingSample = null;
  }, 50);
}

export function installDevMock(): void {
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: {
      invoke: (command: string, args: Record<string, unknown> = {}) => {
        if (command === "plugin:event|listen") {
          return Promise.resolve(registerListener(args));
        }
        if (command === "plugin:event|unlisten") {
          unregisterListener(args);
          return Promise.resolve(undefined);
        }

        const handler = handlers[command];
        if (!handler) {
          return Promise.reject(`mock: no handler for ${command}`);
        }
        try {
          return Promise.resolve(handler(args));
        } catch (caught) {
          // Several handlers report a refusal by throwing, and the internals
          // this stands in for hand every outcome back as a promise. Without
          // this the two differ for anyone holding the internals directly
          // rather than going through `invoke`, which is what a test does.
          return Promise.reject(caught);
        }
      },
      transformCallback: (callback: unknown) => callback,
    },
    configurable: true,
  });

  /*
   * The second global the event API reaches for.
   *
   * `@tauri-apps/api` calls `__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener`
   * on the line *before* it invokes `plugin:event|unlisten`. With only
   * `__TAURI_INTERNALS__` defined that line threw, so the invoke never ran and
   * the mock's own unregister was unreachable — every unlisten was a silent
   * no-op and listeners accumulated. React's strict mode subscribes twice on
   * mount, so the very first render left two, and from then on a single
   * approval request arrived as two queued prompts. It reads exactly like a
   * broker bug and is not one.
   */
  Object.defineProperty(window, "__TAURI_EVENT_PLUGIN_INTERNALS__", {
    value: {
      unregisterListener: (_event: string, eventId: number) =>
        listeners.delete(Number(eventId)),
    },
    configurable: true,
  });

  // In the browser console: __yaraApproval("run" | "reveal" | "shell")
  Object.defineProperty(window, "__yaraApproval", {
    value: (kind: SampleKind = "run") => emit(APPROVAL_EVENT, sample(kind)),
    configurable: true,
  });

  /*
   * In the browser console: __yaraClipboard("wiped" | "alreadyGone" | "failed")
   *
   * Brings the outstanding clear forward instead of waiting the twenty seconds
   * the real one takes. Without it, looking at what the app says when a clear
   * fails means copying something and then sitting still for twenty seconds,
   * three times over.
   */
  Object.defineProperty(window, "__yaraClipboard", {
    value: (outcome: Cleared["outcome"] = "wiped") =>
      fireClear(clipboardToken, clearedAs(outcome)),
    configurable: true,
  });

  // Ctrl+Shift+A, R and S. "shell" is the run that is really a reveal, and it
  // is the variant worth looking at most often.
  const shortcuts: Record<string, SampleKind> = {
    a: "run",
    r: "reveal",
    s: "shell",
  };

  window.addEventListener("keydown", (event) => {
    if (!event.ctrlKey || !event.shiftKey) return;
    const kind = shortcuts[event.key.toLowerCase()];
    if (kind) emit(APPROVAL_EVENT, sample(kind));
  });

  // A query string makes the safety-critical dialog directly reviewable in a
  // browser screenshot without exposing a trigger in the shipped interface.
  // Held rather than fired: see `pendingSample`.
  const requested = new URLSearchParams(window.location.search).get("approval");
  if (requested !== null && requested in SAMPLE_PROMPTS) {
    pendingSample = requested;
    flushPendingSample();
  }
}
