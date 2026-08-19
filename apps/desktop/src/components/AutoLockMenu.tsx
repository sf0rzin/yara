import { useEffect, useRef, type JSX } from "react";
import { Icon } from "./Icon";

/**
 * How long the vault stays unlocked, and a way to lock it now.
 *
 * A popover rather than a settings page. This is the one preference that has a
 * visible consequence — the countdown in the sidebar, right under it — so it
 * belongs next to the thing it changes.
 *
 * "Only when I say so" is offered rather than hidden. Somebody working in a
 * locked room will otherwise find a way to defeat the timer that is worse than
 * turning it off, and an option that is refused is an option that gets faked.
 */
const CHOICES: { label: string; seconds: number | null }[] = [
  { label: "After 1 minute", seconds: 60 },
  { label: "After 5 minutes", seconds: 300 },
  { label: "After 15 minutes", seconds: 900 },
  { label: "After 1 hour", seconds: 3600 },
  { label: "Only when I say so", seconds: null },
];

interface AutoLockMenuProps {
  current: number | null;
  /** The button this was opened from, which is not "elsewhere". */
  triggerRef: React.RefObject<HTMLButtonElement | null>;
  onChoose: (seconds: number | null) => void;
  onLockNow: () => void;
  onCreateVault: () => void;
  onLogout: () => void;
  onDismiss: () => void;
}

export function AutoLockMenu({
  current,
  triggerRef,
  onChoose,
  onLockNow,
  onCreateVault,
  onLogout,
  onDismiss,
}: AutoLockMenuProps): JSX.Element {
  const ref = useRef<HTMLDivElement>(null);
  const firstItemRef = useRef<HTMLButtonElement>(null);

  // Focused here rather than with `autoFocus`, for the same reason the item
  // context menu in Vault.tsx does it this way: React does not apply autoFocus
  // to an element mounted after the first render. Without it this menu opened
  // with focus still on the sidebar button behind it, and since the popover is
  // drawn above that button, Tab walked out of the sidebar entirely — a menu
  // raised from the keyboard that could not then be operated from one.
  useEffect(() => {
    firstItemRef.current?.focus();
  }, []);

  // Escape and a click elsewhere both dismiss. Neither changes the setting:
  // dismissing a menu is not choosing from it.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onDismiss();
    };
    const onDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (ref.current?.contains(target)) return;
      // A press on the trigger belongs to the trigger. Dismissing here as well
      // closed the menu on pointerdown and let the button's own click reopen
      // it a moment later, so the one gesture everybody tries — press it again
      // — could open this menu and never shut it.
      if (triggerRef.current?.contains(target)) return;
      onDismiss();
    };

    window.addEventListener("keydown", onKey);
    window.addEventListener("pointerdown", onDown, true);
    return () => {
      window.removeEventListener("keydown", onKey);
      window.removeEventListener("pointerdown", onDown, true);
    };
  }, [onDismiss, triggerRef]);

  return (
    <div className="popover" ref={ref} role="menu" aria-label="Lock this vault">
      <p className="section-label">Lock this vault</p>

      <div className="popover__options">
        {CHOICES.map((choice, index) => {
          const chosen = choice.seconds === current;
          return (
            <button
              key={choice.label}
              type="button"
              ref={index === 0 ? firstItemRef : undefined}
              role="menuitemradio"
              aria-checked={chosen}
              className="popover__item"
              data-chosen={chosen || undefined}
              onClick={() => onChoose(choice.seconds)}
            >
              <span className="popover__check" aria-hidden="true">
                {chosen && <Icon name="check" size={12} />}
              </span>
              <span className="popover__label">{choice.label}</span>
            </button>
          );
        })}
      </div>

      <div className="popover__separator" />

      <div className="popover__options">
        <button
          type="button"
          role="menuitem"
          className="popover__item"
          onClick={onLockNow}
        >
          <span className="popover__check" aria-hidden="true" />
          <span className="popover__label">Lock now</span>
          <kbd className="kbd">Ctrl L</kbd>
        </button>
      </div>

      <div className="popover__separator" />

      <div className="popover__options">
        <button
          type="button"
          role="menuitem"
          className="popover__item"
          onClick={onCreateVault}
        >
          <span className="popover__check" aria-hidden="true">
            <Icon name="plus" size={12} />
          </span>
          <span className="popover__label">Create another Vault</span>
        </button>
        <button
          type="button"
          role="menuitem"
          className="popover__item"
          onClick={onLogout}
        >
          <span className="popover__check" aria-hidden="true">
            <Icon name="logout" size={12} />
          </span>
          <span className="popover__label">Log out</span>
        </button>
      </div>
    </div>
  );
}
