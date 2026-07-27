import { useCallback, useEffect, useState, type JSX } from "react";
import {
  clearScannedTotp,
  errorMessage,
  scanQrFromClipboard,
  scanQrFromPath,
  type TotpPreview,
} from "../api";
import { Icon } from "./Icon";

const IMAGE_EXTENSIONS = ["png", "jpg", "jpeg", "gif", "bmp", "webp"];

interface QrCaptureProps {
  preview: TotpPreview | null;
  onScanned: (preview: TotpPreview | null) => void;
}

/**
 * Enrolls a second factor from a QR code.
 *
 * Three ways in, because which one is convenient depends on where the code is:
 * paste covers a Win+Shift+S snip of a code on screen, drag-and-drop covers a
 * saved screenshot, and the file picker covers everything else.
 *
 * The image never reaches this component. Paste is read from the clipboard in
 * Rust, and the other two paths pass a file path — so the shared secret inside
 * the code stays out of the JavaScript heap entirely.
 */
export function QrCapture({ preview, onScanned }: QrCaptureProps): JSX.Element {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);

  const run = useCallback(
    async (scan: () => Promise<TotpPreview>) => {
      setBusy(true);
      setError(null);
      try {
        onScanned(await scan());
      } catch (caught) {
        setError(errorMessage(caught));
        onScanned(null);
      } finally {
        setBusy(false);
      }
    },
    [onScanned],
  );

  // Ctrl+V anywhere in the dialog, which is how most people will reach for this.
  useEffect(() => {
    if (preview) return;

    const onPaste = (event: Event) => {
      event.preventDefault();
      void run(scanQrFromClipboard);
    };

    window.addEventListener("paste", onPaste);
    return () => window.removeEventListener("paste", onPaste);
  }, [preview, run]);

  // Tauri delivers dropped files as paths rather than through the DOM.
  useEffect(() => {
    if (preview) return;
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    void (async () => {
      try {
        const { getCurrentWebview } = await import("@tauri-apps/api/webview");
        const stop = await getCurrentWebview().onDragDropEvent((event) => {
          if (event.payload.type === "over" || event.payload.type === "enter") {
            setDragging(true);
          } else if (event.payload.type === "leave") {
            setDragging(false);
          } else if (event.payload.type === "drop") {
            setDragging(false);
            const path = event.payload.paths.find((candidate) =>
              IMAGE_EXTENSIONS.some((extension) =>
                candidate.toLowerCase().endsWith(`.${extension}`),
              ),
            );
            if (path) {
              void run(() => scanQrFromPath(path));
            } else {
              setError("That file is not an image.");
            }
          }
        });
        if (cancelled) stop();
        else unlisten = stop;
      } catch {
        // Running outside Tauri (the dev preview); drag and drop is simply
        // unavailable there, and the other two paths still work.
      }
    })();

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [preview, run]);

  async function chooseFile() {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog");
      const selected = await open({
        multiple: false,
        filters: [{ name: "Image", extensions: IMAGE_EXTENSIONS }],
      });
      if (typeof selected === "string") {
        await run(() => scanQrFromPath(selected));
      }
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  function remove() {
    void clearScannedTotp();
    onScanned(null);
    setError(null);
  }

  if (preview) {
    const label =
      [preview.issuer, preview.account].filter(Boolean).join(" · ") ||
      "Authenticator";

    return (
      <div className="qr qr--done">
        <div className="qr__done-text">
          <span className="qr__done-title">
            <Icon name="check" size={14} />
            {label}
          </span>
          <span className="qr__done-sub">
            {preview.algorithm} · {preview.digits} digits · {preview.period}s
          </span>
        </div>

        <span className="qr__sample" title="A live code, to confirm it works">
          {preview.sampleCode}
        </span>

        <button
          type="button"
          className="icon-button"
          onClick={remove}
          aria-label="Remove scanned code"
        >
          <Icon name="close" size={14} />
        </button>
      </div>
    );
  }

  return (
    <div className="qr" data-dragging={dragging || undefined} data-busy={busy || undefined}>
      <Icon name="authenticator" size={18} />

      <p className="qr__hint">
        {busy
          ? "Reading the code…"
          : dragging
            ? "Drop the image to read it"
            : "Drop a QR image here, or paste one with Ctrl+V"}
      </p>

      <div className="qr__actions">
        <button
          type="button"
          className="button button--quiet"
          disabled={busy}
          onClick={() => void run(scanQrFromClipboard)}
        >
          Paste
        </button>
        <button
          type="button"
          className="button button--quiet"
          disabled={busy}
          onClick={() => void chooseFile()}
        >
          Choose image
        </button>
      </div>

      {error && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {error}
        </p>
      )}
    </div>
  );
}
