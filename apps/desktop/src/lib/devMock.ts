/**
 * A fake Tauri IPC layer, for iterating on the interface in a plain browser.
 *
 * Installs itself only in a dev build that is not running inside Tauri, so it
 * can never reach a shipped binary. The data is invented; nothing here touches
 * a real vault, and no real cryptography runs.
 */

interface MockItem {
  id: string;
  name: string;
  kind: "login" | "card" | "note";
  username: string | null;
  password: string | null;
  url: string | null;
  totpSeed: number | null;
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
    tags: [],
    updatedAt: 1_752_400_000,
  },
];

let unlocked = false;

let mockAutoLock: number | null = 15 * 60;

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
  strength: rateMock(item.password),
});

/**
 * A crude stand-in for the backend's rating.
 *
 * Deliberately not the real algorithm: the point is that the interface gets a
 * value of the right shape, so a dev session shows "Adequate" where production
 * would rather than defaulting everything to the most flattering answer.
 */
function rateMock(password: string | null): "weak" | "fair" | "strong" | null {
  if (password === null) return null;
  if (password.length < 10) return "weak";
  return password.length < 16 ? "fair" : "strong";
}

function matches(item: MockItem, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [item.name, item.username, item.url]
    .filter((field): field is string => Boolean(field))
    .some((field) => field.toLowerCase().includes(q));
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
      .filter((item) => !kind || item.kind === kind)
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
    logins: items.filter((i) => i.kind === "login").length,
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

  auto_lock_seconds: () => mockAutoLock,
  set_auto_lock_seconds: (args) => {
    mockAutoLock = (args.seconds as number | null) ?? null;
  },

  vault_health: () => {
    const withPasswords = items.filter((i) => i.password);
    const weak = withPasswords
      .filter((i) => strengthOf(i.password!) === "weak")
      .map((i) => i.id);

    const groups = new Map<string, string[]>();
    for (const item of withPasswords) {
      const bucket = groups.get(item.password!) ?? [];
      bucket.push(item.id);
      groups.set(item.password!, bucket);
    }

    return {
      weak,
      reused: [...groups.values()]
        .filter((ids) => ids.length > 1)
        .map((ids) => ({ items: ids })),
      missingTotp: withPasswords.filter((i) => !i.totpSeed).map((i) => i.id),
      itemsWithPasswords: withPasswords.length,
    };
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

  add_item: () => "new",
  delete_item: () => undefined,
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

let nextEventId = 1;
const listeners = new Map<number, Registration>();

function registerListener(args: Record<string, unknown>): number {
  const id = nextEventId++;
  listeners.set(id, {
    event: String(args.event),
    handler: args.handler as (event: unknown) => void,
  });
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

function emit(event: string, payload: unknown): void {
  for (const registration of listeners.values()) {
    if (registration.event === event) {
      registration.handler({ event, id: 0, payload });
    }
  }
}

const SAMPLE_PROMPTS: Record<string, unknown> = {
  run: {
    id: "p-run",
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
    id: "p-reveal",
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
    id: "p-shell",
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

  // In the browser console: __yaraApproval("run") or __yaraApproval("reveal")
  Object.defineProperty(window, "__yaraApproval", {
    value: (kind: "run" | "reveal" = "run") =>
      emit("broker://approval", SAMPLE_PROMPTS[kind]),
    configurable: true,
  });
}
