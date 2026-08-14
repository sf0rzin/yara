import { beforeEach, describe, expect, it } from "vitest";
import { copySecret, type Cleared } from "../api";
import { describeCleared, describeCopy, onCleared } from "./clipboard";
import { installDevMock } from "./devMock";

/**
 * What the app is allowed to say about a copy.
 *
 * These used to be assertions about a clipboard object in a variable, because
 * the clearing was done here: write, wait, read back, overwrite. That work
 * moved into Rust, where it can set the formats that keep a password out of
 * Win+V and where a refused clear is a value rather than a discarded rejection.
 * What is left in this file is the part that turns those three outcomes into
 * sentences, and the part that decides which copy a sentence is about — both of
 * which can be got wrong in ways that put a lie on the screen.
 */

/** Windows would not take the exclusion formats. */
const IN_HISTORY = { excludedFromHistory: false, clearsIn: 20, token: 1 };
const KEPT_OUT = { excludedFromHistory: true, clearsIn: 20, token: 1 };

describe("what may be said about a copy", () => {
  it("does not call the copy private when Windows kept it in history", () => {
    const said = describeCopy("Password", IN_HISTORY);

    // The value is in Win+V and on any machine sharing a Cloud Clipboard. The
    // twenty-second clear does not touch either, so a sentence about clearing
    // on its own would read as "and then it is gone", which is false.
    expect(said.message).toMatch(/clipboard history/i);
    expect(said.message).toMatch(/Win\+V/);
    expect(said.loud).toBe(true);

    const kept = describeCopy("Password", KEPT_OUT);
    expect(kept.message).toMatch(/20 seconds/);
    expect(kept.loud).toBe(false);
    expect(kept.message).not.toMatch(/Win\+V/);
  });

  it("says the secret is still there when the clear failed", () => {
    const said = describeCleared("Password", {
      outcome: "failed",
      detail: "the clipboard could not be opened (Access is denied. (os error 5))",
    });

    // The old implementation threw this rejection away, which is how the clear
    // could fail every time while the interface promised it had happened.
    expect(said.message).toMatch(/still on the clipboard/i);
    expect(said.message).toMatch(/Access is denied/);
    expect(said.loud).toBe(true);
    // And the user is given something to do about it, because there is
    // something to do about it.
    expect(said.offerClear).toBe(true);
  });

  it("does not report a clipboard somebody else took as a failure", () => {
    const said = describeCleared("Password", { outcome: "alreadyGone" });

    // Nothing went wrong here: the user copied something else, so there was
    // nothing of ours to remove and removing anything would have taken theirs.
    expect(said.loud).toBe(false);
    expect(said.offerClear).toBe(false);
    expect(said.message).not.toMatch(/fail|could not|error|still/i);

    const wiped = describeCleared("Password", { outcome: "wiped" });
    expect(wiped.loud).toBe(false);
    expect(wiped.message).not.toMatch(/fail|could not|error/i);
  });
});

describe("the clear that arrives later", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("ignores the outcome of a copy that is no longer the one on the clipboard", async () => {
    // Copy, then copy again inside the twenty seconds. Both timers report, and
    // the first one reports about a clipboard the second one owns — so without
    // the token filter the pane would show "something else was on the clipboard
    // by then" over a password that is still on it.
    const first = await copySecret("7Gk!pQ2vXm#9Lz@4Rw");
    const second = await copySecret("Tz3$vLp8Qn!wEr5Ka");
    expect(second.token).not.toBe(first.token);

    const stale: Cleared[] = [];
    const heard: Cleared[] = [];
    const stopStale = onCleared(first.token, (result) => stale.push(result));
    const stop = onCleared(second.token, (result) => heard.push(result));
    await subscribed();

    fireClipboardClear();
    await subscribed();

    expect(heard).toEqual([{ outcome: "wiped" }]);
    expect(stale).toEqual([]);

    stopStale();
    stop();
  });

  it("stops hearing once it has been cancelled", async () => {
    const copied = await copySecret("7Gk!pQ2vXm#9Lz@4Rw");
    const heard: Cleared[] = [];
    const stop = onCleared(copied.token, (result) => heard.push(result));
    await subscribed();

    // A pane that has moved on to another item must not have the last item's
    // clipboard outcome appear on it twenty seconds later.
    stop();
    fireClipboardClear();
    await subscribed();

    expect(heard).toEqual([]);
  });
});

/**
 * Lets the subscription land.
 *
 * `onCleared` reaches the event plugin through a dynamic import and two
 * promises, so the registration is several microtask turns away from the call
 * that asked for it. A macrotask drains all of them.
 */
function subscribed(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

/** The mock's console hook, which brings the pending clear forward. */
function fireClipboardClear(outcome: Cleared["outcome"] = "wiped"): void {
  (window as unknown as { __yaraClipboard: (o: Cleared["outcome"]) => void })
    .__yaraClipboard(outcome);
}
