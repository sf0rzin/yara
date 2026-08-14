/**
 * Copying a secret, and saying honestly what happened to it.
 *
 * This file used to do the work: write with `navigator.clipboard`, wait twenty
 * seconds, read the clipboard back and overwrite it if nothing had changed. Two
 * things were wrong with that, and both of them ended as a promise to the user
 * that the app could not keep.
 *
 * The webview cannot register the clipboard formats that keep an entry out of
 * Windows Clipboard History and the Cloud Clipboard, so every "copied" was also
 * a copy sitting in Win+V. And `readText()` is permission-gated in WebView2
 * while this app requests no clipboard-read capability, so the read that
 * decided whether to clear could be refused every single time — the rejection
 * was discarded, and the interface went on saying "Clipboard clears shortly".
 *
 * The copy now happens in Rust, which knows all three of those things and says
 * so. What is left here is the part that turns those facts into sentences, and
 * one hook so every caller says the same ones.
 */

import { listen } from "@tauri-apps/api/event";
import { useCallback, useEffect, useState } from "react";
import {
  clearClipboard,
  copySecret,
  errorMessage,
  type Cleared,
  type Copied,
} from "../api";

/** Matches `CLIPBOARD_CLEARED_EVENT` in `src-tauri/src/lib.rs`. */
const CLEARED_EVENT = "clipboard://cleared";

/** The payload of that event. */
interface ClipboardCleared {
  token: number;
  result: Cleared;
}

/** Something the interface may say out loud about the clipboard. */
export interface Announcement {
  /** What it is about — "Password", a field's label — so a follow-up can name it. */
  what: string;
  message: string;
  /**
   * Full brightness rather than muted. There is no status colour in this app,
   * so the thing the user must not miss is raised out of the copy around it.
   */
  loud: boolean;
  /** The secret is on the clipboard right now, so offering to take it off is worth it. */
  offerClear: boolean;
}

/**
 * Hears the clear that belongs to one copy.
 *
 * Filtered on the token, and that filter is the point. Copy twice inside the
 * window and the first copy's timer still reports — about a clipboard the
 * second copy owns. Without the token that report would be read as the newer
 * copy's, and "something else was on the clipboard" would appear over a
 * password that is still sitting on it.
 *
 * Returns a canceller that works even before the subscription has been made.
 */
export function onCleared(
  token: number,
  handler: (result: Cleared) => void,
): () => void {
  let cancelled = false;
  let stop: (() => void) | undefined;

  void (async () => {
    try {
      const unlisten = await listen<ClipboardCleared>(CLEARED_EVENT, (event) => {
        if (event.payload.token === token) handler(event.payload.result);
      });
      if (cancelled) unlisten();
      else stop = unlisten;
    } catch {
      // Outside Tauri there is no clipboard to hear from, and no copy either.
    }
  })();

  return () => {
    cancelled = true;
    stop?.();
  };
}

/** What may be claimed the moment a copy lands. */
export function describeCopy(what: string, copied: Copied): Announcement {
  const clears = `It comes off the clipboard in ${copied.clearsIn} seconds`;

  if (copied.excludedFromHistory) {
    return {
      what,
      message: `${what} copied. ${clears}, and Windows was asked to keep it out of clipboard history.`,
      loud: false,
      offerClear: false,
    };
  }

  // Windows would not take the exclusion formats, so the value is in Win+V and
  // possibly on the user's other machines through the Cloud Clipboard. Clearing
  // the clipboard later does not remove either, and only the user can.
  return {
    what,
    message:
      `${what} copied. ${clears}, but Windows would not keep it out of clipboard ` +
      `history — it is in Win+V until you clear that yourself.`,
    loud: true,
    offerClear: false,
  };
}

/** What may be claimed once the clear has reported. */
export function describeCleared(what: string, result: Cleared): Announcement {
  switch (result.outcome) {
    case "wiped":
      return {
        what,
        message: `${what} is off the clipboard.`,
        loud: false,
        offerClear: false,
      };

    // Not a failure, and it must not read as one: something else was on the
    // clipboard by the time the timer ran, so there was nothing of ours to take
    // off — and emptying it would have thrown away whatever the user copied.
    case "alreadyGone":
      return {
        what,
        message: "Something else was on the clipboard by then, so it was left as it is.",
        loud: false,
        offerClear: false,
      };

    // The one the old implementation swallowed. The secret is still there.
    case "failed":
      return {
        what,
        message: `${what} is still on the clipboard — ${result.detail}.`,
        loud: true,
        offerClear: true,
      };
  }
}

/**
 * One copy at a time, and the sentence that goes with it.
 *
 * A hook rather than a call because a copy is not over when it returns: the
 * clear arrives twenty seconds later and can change what is true. A screen that
 * copies has to keep listening, and every screen that copies should say the
 * same thing about the same outcome.
 */
export function useSecretCopy(): {
  said: Announcement | null;
  /** Copies a secret through the backend. Throws if the clipboard refused it. */
  copy: (what: string, value: string) => Promise<void>;
  /** Says something about a copy that carried no secret, in the same place. */
  note: (message: string) => void;
  /** Takes the secret off the clipboard now, after a clear that failed. */
  clearNow: (what: string) => Promise<void>;
  /** Drops what belongs to the thing being left behind. See below. */
  forget: () => void;
} {
  const [said, setSaid] = useState<Announcement | null>(null);
  /** The copy whose clear has not reported yet, and what to call it. */
  const [pending, setPending] = useState<{ what: string; token: number } | null>(null);

  useEffect(() => {
    if (pending === null) return;
    return onCleared(pending.token, (result) => {
      setPending(null);
      setSaid(describeCleared(pending.what, result));
    });
  }, [pending]);

  // A quiet message has said its piece and can go. A loud one is a state the
  // user is in — a password in Win+V, a clear that failed — and a warning that
  // removes itself after two seconds is a warning nobody read.
  //
  // Nothing expires while a clear is still to report, because what is on screen
  // is then a promise about something that has not happened yet.
  useEffect(() => {
    if (said === null || said.loud || pending !== null) return;
    const timer = setTimeout(() => setSaid(null), 2_500);
    return () => clearTimeout(timer);
  }, [said, pending]);

  const copy = useCallback(async (what: string, value: string) => {
    const copied = await copySecret(value);
    setSaid(describeCopy(what, copied));
    setPending({ what, token: copied.token });
  }, []);

  const note = useCallback((message: string) => {
    setSaid({ what: message, message, loud: false, offerClear: false });
    setPending(null);
  }, []);

  const clearNow = useCallback(async (what: string) => {
    try {
      setSaid(describeCleared(what, await clearClipboard()));
    } catch (caught) {
      // The retry is offered because the secret is still there; a retry that
      // fails leaves it exactly as still-there, so the offer stands.
      setSaid({ what, message: errorMessage(caught), loud: true, offerClear: true });
    }
  }, []);

  /**
   * Moving on — to another item, usually.
   *
   * Quiet lines go with what they were about: "Username copied" belongs to the
   * row you have just left. A loud one does not. "Your password is still on the
   * clipboard" is a fact about the machine, and it does not stop being true
   * because you clicked a different item; silencing it there would be the
   * interface making a warning easy to lose.
   *
   * A clear that has not reported is kept for the same reason. It is the only
   * thing that can turn into that warning.
   */
  const forget = useCallback(() => {
    setSaid((current) => (current === null || current.loud ? current : null));
  }, []);

  return { said, copy, note, clearNow, forget };
}
