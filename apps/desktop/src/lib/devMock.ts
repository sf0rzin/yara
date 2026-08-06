/**
 * A fake Tauri IPC layer, for iterating on the interface in a plain browser.
 *
 * Installs itself only in a dev build that is not running inside Tauri, so it
 * can never reach a shipped binary. The data is invented; nothing here touches
 * a real vault, and no real cryptography runs.
 */

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
    notes: null,
    fields: [],
    tags: [],
    updatedAt: 1_752_300_000,
  },
];

let unlocked = false;

let mockAutoLock: number | null = 15 * 60;
let mockIcons = true;

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
  baseUrl: "https://yara.rindexx.cc",
  accountId: "9f2c41a8-0e77-4c19-b3de-5a1f8c66d204",
  deviceId: "d41d8cd9-8f00-3204-a980-0998ecf8427e",
  lastSyncedAt: unixNow() - 1_800,
};

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

const summary = (item: MockItem) => ({
  id: item.id,
  name: item.name,
  kind: item.kind,
  username: item.username,
  url: item.url,
  tags: item.tags,
  hasPassword: item.password !== null,
  hasTotp: item.totpSeed !== null,
  updatedAt: item.updatedAt,
  // Invented, like everything else here — but present, because a field the
  // mock omits renders as "Unknown" or, worse, as a claim the real backend
  // would never make.
  createdAt: item.updatedAt - 86_400 * 420,
});

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

const handlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  vault_exists: () => true,
  is_unlocked: () => unlocked,
  create_vault: () => {
    unlocked = true;
  },
  unlock_vault: () => {
    unlocked = true;
  },
  lock_vault: () => {
    unlocked = false;
  },

  list_items: (args) => {
    const query = String(args.query ?? "");
    const kind = args.kind as MockItem["kind"] | null;
    const withTotp = args.withTotp as boolean | null;

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
      .map(summary);
  },

  recent_items: (args) =>
    [...items]
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .slice(0, Number(args.limit ?? 5))
      .map(summary),

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
      baseUrl: String(args.baseUrl ?? "https://yara.rindexx.cc"),
      accountId: "9f2c41a8-0e77-4c19-b3de-5a1f8c66d204",
      deviceId: "d41d8cd9-8f00-3204-a980-0998ecf8427e",
      lastSyncedAt: unixNow(),
    };
    return {
      kit: "K7QM-3XPD-9WRF-2LHN-8BVC-4TGS",
      accountId: mockSync.accountId,
    };
  },
  sync_now: () => {
    mockSync = { ...mockSync, lastSyncedAt: unixNow() };
    return { pulled: 2, pushed: 1, conflicts: 0 };
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

  reveal_password: (args) =>
    items.find((i) => i.id === args.id)?.password ?? "",

  totp_code: (args) => {
    const item = items.find((i) => i.id === args.id);
    const period = 30;
    const now = Math.floor(Date.now() / 1000);
    const step = Math.floor(now / period);
    const code = String(((step * 7919 + (item?.totpSeed ?? 0) * 104729) % 1_000_000)).padStart(6, "0");
    return { code, secondsRemaining: period - (now % period), period };
  },

  estimate_strength: (args) => strengthOf(String(args.password ?? "")),

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

  change_master_password: () => undefined,

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
        return Promise.resolve(handler(args));
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
