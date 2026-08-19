import type { JSX } from "react";

/**
 * A small stroke-based icon set, drawn inline.
 *
 * Bundled rather than pulled from an icon library: the set is small, the app
 * must work offline, and a strict CSP rules out fetching anything at runtime.
 * Every glyph is on a 16px grid at 1.5 stroke so they sit at the same optical
 * weight as the type around them.
 */
const paths = {
  search: (
    <>
      <circle cx="7" cy="7" r="4.75" />
      <path d="M10.5 10.5 14 14" />
    </>
  ),
  arrowRight: <path d="M2.5 8h11M9.5 4l4 4-4 4" />,
  chevronsUpDown: (
    <>
      <path d="m5.25 6 2.75-2.75L10.75 6" />
      <path d="m5.25 10 2.75 2.75L10.75 10" />
    </>
  ),
  allItems: <path d="M8 1.75 14.25 8 8 14.25 1.75 8Z" />,
  download: (
    <>
      <path d="M8 2.25v7.5" />
      <path d="M4.75 6.75 8 10l3.25-3.25" />
      <path d="M2.75 12.25h10.5" />
    </>
  ),
  /* Two arcs chasing each other: reconciliation, not a download. */
  sync: (
    <>
      <path d="M2.4 8a5.6 5.6 0 0 1 9.56-3.96l1.64 1.6" />
      <path d="M13.6 8a5.6 5.6 0 0 1-9.56 3.96l-1.64-1.6" />
      <path d="M13.6 2.6v3.04h-3.04" />
      <path d="M2.4 13.4v-3.04h3.04" />
    </>
  ),
  calendar: (
    <>
      <rect x="2.1" y="3.4" width="11.8" height="10.5" rx="2.2" />
      <path d="M2.1 6.6h11.8" />
      <path d="M5.4 2.1v2.6" />
      <path d="M10.6 2.1v2.6" />
    </>
  ),
  ellipsis: (
    <>
      <circle cx="3.4" cy="8" r="0.95" fill="currentColor" stroke="none" />
      <circle cx="8" cy="8" r="0.95" fill="currentColor" stroke="none" />
      <circle cx="12.6" cy="8" r="0.95" fill="currentColor" stroke="none" />
    </>
  ),
  pencil: (
    <>
      <path d="M10.35 2.85a1.63 1.63 0 0 1 2.3 2.3l-7 7-3.05.75.75-3.05Z" />
      <path d="M9.3 3.9l2.3 2.3" />
    </>
  ),
  recent: (
    <>
      <circle cx="8" cy="8" r="6.25" />
      <path d="M8 4.5V8l2.5 1.5" />
    </>
  ),
  security: (
    <path d="M8 1.75l5.25 2v4.1c0 3.4-2.2 5.9-5.25 6.4-3.05-.5-5.25-3-5.25-6.4V3.75Z" />
  ),
  login: (
    <>
      <circle cx="8" cy="8" r="5.75" />
      <circle cx="8" cy="8" r="1.9" fill="currentColor" stroke="none" />
    </>
  ),
  card: (
    <>
      <rect x="1.75" y="3.75" width="12.5" height="8.5" rx="2" />
      <path d="M1.75 6.75h12.5" />
    </>
  ),
  note: (
    <>
      <rect x="3" y="1.75" width="10" height="12.5" rx="2" />
      <path d="M5.75 5.5h4.5M5.75 8h4.5M5.75 10.5h2.5" />
    </>
  ),
  authenticator: <circle cx="8" cy="8" r="5.75" />,
  sparkle: (
    <path d="M8 1.5 9.45 6.55 14.5 8 9.45 9.45 8 14.5 6.55 9.45 1.5 8 6.55 6.55Z" />
  ),
  check: <path d="M3 8.5 6.5 12 13 4.5" />,
  plus: <path d="M8 3.25v9.5M3.25 8h9.5" />,
  copy: (
    <>
      <rect x="5.75" y="5.75" width="8.5" height="8.5" rx="2" />
      <path d="M10.75 5.75v-2a2 2 0 0 0-2-2h-5a2 2 0 0 0-2 2v5a2 2 0 0 0 2 2h2" />
    </>
  ),
  eye: (
    <>
      <path d="M1.25 8S4 3.5 8 3.5 14.75 8 14.75 8 12 12.5 8 12.5 1.25 8 1.25 8Z" />
      <circle cx="8" cy="8" r="2.1" />
    </>
  ),
  eyeOff: (
    <>
      <path d="M6.4 4a6.7 6.7 0 0 1 1.6-.2c4 0 6.75 4.2 6.75 4.2a12 12 0 0 1-2 2.4M4.2 5.3A12.2 12.2 0 0 0 1.25 8S4 12.2 8 12.2c.9 0 1.7-.2 2.4-.5" />
      <path d="M2 2l12 12" />
    </>
  ),
  trash: (
    <>
      <path d="M2.75 4.25h10.5M6.5 4.25V2.9a1 1 0 0 1 1-1h1a1 1 0 0 1 1 1v1.35" />
      <path d="M4 4.25l.6 8.4a1.5 1.5 0 0 0 1.5 1.35h3.8a1.5 1.5 0 0 0 1.5-1.35l.6-8.4" />
    </>
  ),
  lock: (
    <>
      <rect x="2.75" y="6.75" width="10.5" height="7.5" rx="2" />
      <path d="M5.25 6.75V4.9a2.75 2.75 0 0 1 5.5 0v1.85" />
    </>
  ),
  logout: (
    <>
      <path d="M6.5 2.25H3.75a1.5 1.5 0 0 0-1.5 1.5v8.5a1.5 1.5 0 0 0 1.5 1.5H6.5" />
      <path d="M7.5 8h6.25M11 5.25 13.75 8 11 10.75" />
    </>
  ),
  close: <path d="M3.5 3.5l9 9M12.5 3.5l-9 9" />,
  alert: (
    <>
      <circle cx="8" cy="8" r="6.25" />
      <path d="M8 4.75v3.75" />
      <circle cx="8" cy="11.1" r="0.85" fill="currentColor" stroke="none" />
    </>
  ),
  chevronRight: <path d="M6 3.5 10.5 8 6 12.5" />,
  folder: (
    <path d="M1.75 4.25a1 1 0 0 1 1-1h3l1.5 1.75h5a1 1 0 0 1 1 1v6a1 1 0 0 1-1 1h-9.5a1 1 0 0 1-1-1Z" />
  ),
  key: (
    <>
      <circle cx="5" cy="11" r="3.25" />
      <path d="M7.3 8.7 13.5 2.5M11 5l1.75 1.75" />
    </>
  ),
} as const;

export type IconName = keyof typeof paths;

interface IconProps {
  name: IconName;
  size?: number;
  className?: string;
}

export function Icon({ name, size = 16, className }: IconProps): JSX.Element {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {paths[name]}
    </svg>
  );
}
