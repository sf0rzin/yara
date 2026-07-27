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
});

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
};

export function installDevMock(): void {
  Object.defineProperty(window, "__TAURI_INTERNALS__", {
    value: {
      invoke: (command: string, args: Record<string, unknown> = {}) => {
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
}
