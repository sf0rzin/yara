import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { clipboardClearSeconds, copySecret } from "./clipboard";

/**
 * A clipboard that remembers, because the whole behaviour under test is a
 * comparison against what is on it at the moment the timer fires.
 */
function installClipboard() {
  let text = "";
  const clipboard = {
    writeText: vi.fn(async (value: string) => {
      text = value;
    }),
    readText: vi.fn(async () => text),
    /** What some other application put there while the timer was running. */
    takenOverBy: (value: string) => {
      text = value;
    },
    get contents() {
      return text;
    },
  };

  Object.defineProperty(navigator, "clipboard", {
    value: clipboard,
    configurable: true,
  });

  return clipboard;
}

describe("copySecret", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("clears the clipboard when it still holds the secret", async () => {
    const clipboard = installClipboard();

    await copySecret("7Gk!pQ2vXm#9Lz@4Rw");
    expect(clipboard.contents).toBe("7Gk!pQ2vXm#9Lz@4Rw");

    await vi.advanceTimersByTimeAsync(clipboardClearSeconds * 1000);

    expect(clipboard.contents).toBe("");
    expect(clipboard.writeText).toHaveBeenLastCalledWith("");
  });

  it("leaves the clipboard alone once something else has taken it", async () => {
    const clipboard = installClipboard();

    await copySecret("7Gk!pQ2vXm#9Lz@4Rw");
    // The user copied an address, a git hash, anything. Twenty seconds later
    // yara has no business wiping it — that is somebody else's work, and a
    // password manager that silently empties the clipboard is one people stop
    // trusting with the clipboard.
    clipboard.takenOverBy("https://example.com/orders/1182");

    await vi.advanceTimersByTimeAsync(clipboardClearSeconds * 1000);

    expect(clipboard.contents).toBe("https://example.com/orders/1182");
    expect(clipboard.writeText).not.toHaveBeenCalledWith("");
  });
});
