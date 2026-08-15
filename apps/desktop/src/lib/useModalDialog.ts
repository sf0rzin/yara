import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE_SELECTOR = "a[href], button, input, textarea, select, [tabindex]";

function isFocusable(element: Element): element is HTMLElement {
  if (!(element instanceof HTMLElement)) return false;
  if (element.hasAttribute("disabled")) return false;
  if (element.hidden) return false;
  if (element.getAttribute("tabindex") === "-1") return false;
  const rect = element.getBoundingClientRect();
  return rect.width > 0 && rect.height > 0;
}

/** The dialog's current focusable descendants, in DOM order. */
function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)).filter(isFocusable);
}

/**
 * Traps Tab inside a dialog, and hands focus back to whatever had it once the
 * dialog is gone.
 *
 * One hook rather than four copies of the same fifteen lines, which is what
 * this codebase had before: an overlay that stopped the mouse and nothing
 * else, so Tab could walk out of a dialog into whatever was behind it, and
 * closing one never gave a keyboard user their place back.
 *
 * The focusable set is queried fresh on every Tab rather than captured once
 * at mount. These dialogs grow and shrink while they are open — a field added
 * to `NewItemDialog`, a step change in `ImportPanel` — and a ring captured at
 * mount goes stale the first time the DOM does.
 *
 * Escape is deliberately not handled here. Every dialog already has its own
 * listener for it, and at least one of them — `ApprovalDialog` — means
 * something more specific by it than "close". This hook has no business
 * overriding either.
 */
export function useModalDialog<T extends HTMLElement>(): RefObject<T | null> {
  const ref = useRef<T | null>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      const container = ref.current;
      if (!container) return;

      const elements = focusableElements(container);
      if (elements.length === 0) return;

      const first = elements[0];
      const last = elements[elements.length - 1];
      // Not just the boundary case: a click on a non-focusable part of the
      // dialog (a paragraph, a heading) leaves `document.activeElement` on
      // `body`, and without this a trap that only reacts at `first`/`last`
      // never engages at all — the next Tab walks straight into whatever is
      // behind the overlay. `ApprovalDialog` is exactly the dialog where that
      // matters: it decides whether an agent gets a credential.
      const inside = container.contains(document.activeElement);

      if (event.shiftKey && (!inside || document.activeElement === first)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (!inside || document.activeElement === last)) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      // The trigger that opened this dialog is often what its own action
      // removed — check before focusing back into nothing.
      if (previouslyFocused instanceof HTMLElement && document.contains(previouslyFocused)) {
        previouslyFocused.focus();
      }
    };
  }, []);

  return ref;
}
