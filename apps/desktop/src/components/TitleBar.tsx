import type { JSX } from "react";

/**
 * The window's own title bar.
 *
 * The frame is off, so this strip is what drags the window and what closes it.
 * It is a strip rather than a bar: no title, no icon, nothing but the drag
 * region and three controls. The window already says what it is — the sidebar
 * has the wordmark — and repeating it in chrome is the kind of thing a native
 * app does not do.
 *
 * `data-tauri-drag-region` is what makes the empty space draggable. It has to
 * be on the element the pointer actually lands on, which is why the buttons
 * sit outside it rather than inside.
 */
export function TitleBar(): JSX.Element {
  const act = async (what: "minimise" | "maximise" | "close") => {
    try {
      const { getCurrentWindow } = await import("@tauri-apps/api/window");
      const win = getCurrentWindow();
      if (what === "minimise") await win.minimize();
      else if (what === "maximise") await win.toggleMaximize();
      else await win.close();
    } catch {
      // A browser dev session has no window to drive.
    }
  };

  return (
    <div className="titlebar">
      <div className="titlebar__drag" data-tauri-drag-region />

      <div className="titlebar__controls">
        <button
          type="button"
          className="titlebar__button"
          aria-label="Minimise"
          onClick={() => void act("minimise")}
        >
          <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
            <path d="M1 4h6" stroke="currentColor" strokeWidth="1.1" strokeLinecap="round" />
          </svg>
        </button>

        <button
          type="button"
          className="titlebar__button"
          aria-label="Maximise"
          onClick={() => void act("maximise")}
        >
          <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
            <rect
              x="1.2"
              y="1.2"
              width="5.6"
              height="5.6"
              rx="1.4"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.1"
            />
          </svg>
        </button>

        {/*
          Close is last and, unusually, not marked out. There is no red to give
          it, and a vault that closes is a vault that locks — which is the safe
          direction, so it does not need a warning.
        */}
        <button
          type="button"
          className="titlebar__button titlebar__button--close"
          aria-label="Close"
          onClick={() => void act("close")}
        >
          <svg width="8" height="8" viewBox="0 0 8 8" aria-hidden="true">
            <path
              d="M1.5 1.5l5 5M6.5 1.5l-5 5"
              stroke="currentColor"
              strokeWidth="1.1"
              strokeLinecap="round"
            />
          </svg>
        </button>
      </div>
    </div>
  );
}
