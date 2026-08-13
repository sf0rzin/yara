import type { JSX } from "react";
import logoUrl from "../assets/yara-logo.png";

interface YaraLogoProps {
  className?: string;
  decorative?: boolean;
}

/** The approved Yara mark, kept as a single shared asset across the app. */
export function YaraLogo({
  className,
  decorative = false,
}: YaraLogoProps): JSX.Element {
  return (
    <img
      className={className}
      src={logoUrl}
      alt={decorative ? "" : "Yara"}
      aria-hidden={decorative || undefined}
    />
  );
}

export { logoUrl as yaraLogoUrl };
