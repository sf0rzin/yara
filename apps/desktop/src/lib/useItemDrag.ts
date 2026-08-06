import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Dragging items, built on pointer events rather than HTML5 drag and drop.
 *
 * Not a style preference. Tauri registers its own drop target on the webview
 * so the window can accept files — which is how a QR image gets dropped into
 * the enrolment box — and on Windows that swallows HTML5 drag events entirely.
 * Tauri's own documentation says as much: "Disabling it is required to use
 * HTML5 drag and drop on the frontend on Windows."
 *
 * So the choice was between HTML5 dragging and accepting dropped files, and
 * this takes neither horn: pointer events are untouched by that interception,
 * and the file drop keeps working.
 *
 * Worth recording how this was missed. The HTML5 version was verified in a
 * browser, which is the one environment where Tauri's interception does not
 * exist — the feature was tested in the only place it could not fail.
 */

/** Where a dragged row would land. */
export interface RowTarget {
  id: string;
  edge: "above" | "below";
}

export interface DragState {
  /** The item being dragged, or null when nothing is. */
  itemId: string | null;
  /** The folder being dragged, for reordering the sidebar. */
  folderName: string | null;
  /** The row it would drop next to. */
  overRow: RowTarget | null;
  /**
   * The folder it would be filed in. `null` inside the object means "no
   * folder"; the object itself being null means the cursor is not over one.
   */
  overFolder: { name: string | null } | null;
}

const IDLE: DragState = {
  itemId: null,
  folderName: null,
  overRow: null,
  overFolder: null,
};

/**
 * How far the pointer travels before this counts as a drag.
 *
 * Without it every click on a row would begin one, and a row is a button
 * first — the common gesture is selecting, not moving.
 */
const THRESHOLD = 5;

interface Options {
  onReorder: (itemId: string, target: RowTarget) => void;
  onFile: (itemId: string, folder: string | null) => void;
  /** Dropping a folder onto another puts it in that one's place. */
  onMoveFolder: (name: string, before: string) => void;
}

export function useItemDrag({ onReorder, onFile, onMoveFolder }: Options) {
  const [state, setState] = useState<DragState>(IDLE);

  // Read inside listeners that are attached once, so they must not close over
  // stale renders.
  const live = useRef<{
    itemId: string | null;
    folderName: string | null;
    from: { x: number; y: number };
    started: boolean;
    target: DragState;
  } | null>(null);
  const handlers = useRef({ onReorder, onFile, onMoveFolder });
  handlers.current = { onReorder, onFile, onMoveFolder };

  /** Set when a drag happened, so the click that follows can be swallowed. */
  const dragged = useRef(false);

  const begin = useCallback((itemId: string, event: React.PointerEvent) => {
    // Left button only. A right-press opens the context menu and a middle one
    // means nothing here.
    if (event.button !== 0) return;
    live.current = {
      itemId,
      folderName: null,
      from: { x: event.clientX, y: event.clientY },
      started: false,
      target: { ...IDLE, itemId },
    };
  }, []);

  const beginFolder = useCallback((name: string, event: React.PointerEvent) => {
    if (event.button !== 0) return;
    live.current = {
      itemId: null,
      folderName: name,
      from: { x: event.clientX, y: event.clientY },
      started: false,
      target: { ...IDLE, folderName: name },
    };
  }, []);

  /**
   * Whether the click now arriving is the tail of a drag.
   *
   * A row is a button, and a pointerup after moving still produces a click.
   * Selecting the item you just filed somewhere else is not what was asked
   * for, so the caller checks this before acting.
   */
  const swallowClick = useCallback(() => {
    if (!dragged.current) return false;
    dragged.current = false;
    return true;
  }, []);

  useEffect(() => {
    const move = (event: PointerEvent) => {
      const drag = live.current;
      if (!drag) return;

      if (!drag.started) {
        const far =
          Math.abs(event.clientX - drag.from.x) > THRESHOLD ||
          Math.abs(event.clientY - drag.from.y) > THRESHOLD;
        if (!far) return;
        drag.started = true;
        // Stops the pointer painting a selection across every row it crosses.
        document.body.style.userSelect = "none";
      }

      // Hit-tested by position rather than by events reaching the target,
      // which is the whole point: nothing here depends on the webview letting
      // a drag event through.
      const under = document.elementFromPoint(event.clientX, event.clientY);
      const folderEl = under?.closest<HTMLElement>("[data-folder-drop]");
      const rowEl = under?.closest<HTMLElement>("[data-item-id]");

      const carried = { itemId: drag.itemId, folderName: drag.folderName };
      let next: DragState;

      if (folderEl) {
        const name = folderEl.getAttribute("data-folder-drop");
        // A folder dropped on itself is not a move, and "No folder" is not a
        // place a folder can go.
        const sameFolder = drag.folderName !== null && (name === drag.folderName || !name);
        next = {
          ...carried,
          overRow: null,
          overFolder: sameFolder ? null : { name: name || null },
        };
      } else if (rowEl && drag.itemId) {
        const id = rowEl.getAttribute("data-item-id") ?? "";
        const box = rowEl.getBoundingClientRect();
        // Which half the cursor is in decides above or below, so either end of
        // a run is reachable without aiming at the seam between two rows.
        const edge = event.clientY < box.top + box.height / 2 ? "above" : "below";
        next = {
          ...carried,
          overRow: id === drag.itemId ? null : { id, edge },
          overFolder: null,
        };
      } else {
        next = { ...carried, overRow: null, overFolder: null };
      }

      drag.target = next;
      setState(next);
    };

    const finish = (commit: boolean) => {
      const drag = live.current;
      live.current = null;
      document.body.style.userSelect = "";
      setState(IDLE);
      if (!drag?.started) return;

      dragged.current = true;
      if (!commit) return;

      const { itemId, folderName, target } = drag;

      if (folderName !== null) {
        const before = target.overFolder?.name;
        if (before) handlers.current.onMoveFolder(folderName, before);
        return;
      }

      if (itemId === null) return;
      if (target.overFolder) handlers.current.onFile(itemId, target.overFolder.name);
      else if (target.overRow) handlers.current.onReorder(itemId, target.overRow);
    };

    const up = () => finish(true);
    const cancel = () => finish(false);
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape" && live.current) cancel();
    };

    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", cancel);
    window.addEventListener("keydown", key);
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", cancel);
      window.removeEventListener("keydown", key);
    };
  }, []);

  return { state, begin, beginFolder, swallowClick };
}
