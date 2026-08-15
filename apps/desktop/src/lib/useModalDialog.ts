import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE_SELECTOR = "a[href], button, input, textarea, select, [tabindex]";

/**
 * `disabled`, `hidden` and `[tabindex="-1"]` are exercised by the test suite;
 * the zero-size check is not. jsdom never lays anything out, so every element
 * — a genuinely hidden one and an ordinary visible button alike — reports a
 * zero-size bounding box unless a test overrides `getBoundingClientRect`
 * itself, and doing that for every element would stop the override from
 * being able to tell the two apart. This branch is verified by hand in a
 * real browser instead.
 */
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

interface StackEntry {
  container: HTMLElement;
  front: boolean;
}

/**
 * Every open dialog's container, most recently mounted last.
 *
 * `Vault.tsx` can have `ApprovalDialog` mounted over `NewItemDialog` at the
 * same time — on purpose, an agent is blocked waiting on the answer — which
 * means two of this hook's instances can be listening for Tab at once. Only
 * the one on top of this stack may act: without it, both containers' keydown
 * handlers fire on the same Tab, both see focus outside themselves, and both
 * call `preventDefault` and pull focus into their own dialog. Where focus
 * ends up is then whichever handler happens to be registered second, and on
 * the way there it lands — briefly, but for a real `focus` event — on a
 * control in the dialog behind the one that is supposed to be modal.
 *
 * Mount order is not the same thing as paint order. `ApprovalDialog` sits
 * above every other overlay via `overlay--front`'s `z-index` — nothing in
 * `Vault.tsx` stops the command palette or `NewItemDialog` from opening
 * while an approval prompt is already up, and doing so would mount that
 * second dialog later, putting it on top of a stack ordered by mount time
 * alone even though `ApprovalDialog` stays on top on screen. `front`
 * exists so the entry that is pinned above everything by CSS is also
 * pinned above everything here, regardless of when it mounted.
 */
const stack: StackEntry[] = [];

function topmost(): HTMLElement | undefined {
  for (let index = stack.length - 1; index >= 0; index -= 1) {
    if (stack[index].front) return stack[index].container;
  }
  return stack.length > 0 ? stack[stack.length - 1].container : undefined;
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
 *
 * @param options.front - Set for a dialog that is pinned above every other
 * overlay by CSS (currently only `ApprovalDialog`, via `overlay--front`), so
 * that this hook's idea of "topmost" agrees with what is actually on screen
 * even if something else mounts later. See the comment on `stack`.
 */
export function useModalDialog<T extends HTMLElement>(options?: {
  front?: boolean;
}): RefObject<T | null> {
  const ref = useRef<T | null>(null);
  const front = options?.front ?? false;

  useEffect(() => {
    const container = ref.current;
    if (!container) return;

    stack.push({ container, front });
    const previouslyFocused = document.activeElement;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Tab") return;
      // Only the topmost dialog traps Tab — see the comment on `stack`.
      if (topmost() !== container) return;

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
      const position = stack.findIndex((entry) => entry.container === container);
      if (position !== -1) stack.splice(position, 1);
      // The trigger that opened this dialog is often what its own action
      // removed — check before focusing back into nothing.
      if (previouslyFocused instanceof HTMLElement && document.contains(previouslyFocused)) {
        previouslyFocused.focus();
      }
    };
  }, [front]);

  return ref;
}
