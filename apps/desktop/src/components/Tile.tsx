import { useEffect, useState, type JSX } from "react";
import { iconFor, type ItemKind } from "../api";
import { Icon, type IconName } from "./Icon";

/**
 * Icons already asked for, so scrolling a list does not re-ask.
 *
 * Module-level and never evicted: it holds a few hundred small strings at
 * most, and the alternative — refetching as rows mount and unmount — is the
 * thing the disk cache downstream exists to prevent.
 *
 * `null` is a remembered miss. Without it a domain with no icon would be
 * retried on every render for the rest of the session.
 */
const seen = new Map<string, string | null>();

const KIND_ICONS: Record<ItemKind, IconName> = {
  login: "login",
  card: "card",
  note: "note",
};

/**
 * The square at the left of a row, and the big one in the detail header.
 *
 * The design puts a favicon here. It does not fetch one, and will not: asking
 * github.com for its icon tells github.com that this vault holds a GitHub
 * account, and doing it for every row hands the whole list to whoever is
 * watching the network. For a password manager that promises the vault never
 * leaves the machine, that is not a small contradiction.
 *
 * A monogram gets the same thing the favicon was there for — every row
 * distinct at a glance, names aligned on a common left edge — out of data that
 * is already local.
 *
 * Cards and notes keep their type glyph. A card's initial would be the bank's,
 * which is worse than useless next to a name that already says it.
 */
export function Tile({
  name,
  kind,
  url,
  large,
}: {
  name: string;
  kind: ItemKind;
  url?: string | null;
  large?: boolean;
}): JSX.Element {
  const domain = kind === "login" ? domainOf(url) : null;
  const [icon, setIcon] = useState<string | null>(() =>
    domain ? (seen.get(domain) ?? null) : null,
  );

  useEffect(() => {
    if (!domain || seen.has(domain)) return;

    let live = true;
    void iconFor(domain)
      .then((found) => {
        seen.set(domain, found);
        if (live) setIcon(found);
      })
      .catch(() => seen.set(domain, null));

    return () => {
      live = false;
    };
  }, [domain]);

  const monogram = kind === "login" ? initialsOf(name) : null;

  return (
    <span
      className={large ? "tile tile--large" : "tile"}
      data-monogram={!icon && monogram ? "" : undefined}
      data-icon={icon ? "" : undefined}
      aria-hidden="true"
    >
      {/*
        The monogram is the fallback rather than a placeholder that gets
        replaced. A tile that starts blank and fills in a moment later makes
        the whole list twitch as it loads.
      */}
      {icon ? (
        <img src={icon} alt="" />
      ) : (
        (monogram ?? <Icon name={KIND_ICONS[kind]} size={large ? 20 : 16} />)
      )}
    </span>
  );
}

/** The host an icon would belong to, or null if there is nothing to ask about. */
function domainOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return host.includes(".") ? host : null;
  } catch {
    return null;
  }
}

/**
 * One letter, or two when the name is several words.
 *
 * Words are what people distinguish by — "Amazon Web Services" reads as AWS
 * long before it reads as A. Capped at two so the tile never has to shrink its
 * type to fit.
 */
function initialsOf(name: string): string | null {
  const words = name
    .trim()
    .split(/[\s—–-]+/)
    .filter((word) => /[\p{L}\p{N}]/u.test(word));

  if (words.length === 0) return null;
  if (words.length === 1) return firstChar(words[0]).toUpperCase();

  return (firstChar(words[0]) + firstChar(words[1])).toUpperCase();
}

/** Grapheme-aware enough for a first letter: avoids splitting a surrogate. */
function firstChar(word: string): string {
  return [...word][0] ?? "";
}
