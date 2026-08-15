import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState, type JSX } from "react";
import { beforeEach, describe, expect, it } from "vitest";
import { useModalDialog } from "./useModalDialog";

/**
 * The focus trap and focus-restore behaviour shared by every dialog.
 *
 * jsdom lays nothing out, so every element reports a zero-size bounding box
 * by default — a real, visible button included. The hook filters those out
 * on purpose, because that is how a genuinely hidden control gets excluded
 * in a real browser, so every test here gives elements the kind of size a
 * browser would actually report for something on screen, rather than
 * disabling the check to make the suite pass.
 */
beforeEach(() => {
  Element.prototype.getBoundingClientRect = () =>
    ({
      width: 100,
      height: 24,
      top: 0,
      left: 0,
      right: 100,
      bottom: 24,
      x: 0,
      y: 0,
      toJSON() {},
    }) as DOMRect;
});

function ThreeInARing(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  return (
    <div ref={ref}>
      <button type="button">First</button>
      <button type="button">Middle</button>
      <button type="button">Last</button>
    </div>
  );
}

function WithATrailingDisabledControl(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  return (
    <div ref={ref}>
      <button type="button">First</button>
      <button type="button">Last</button>
      <button type="button" disabled>
        Disabled
      </button>
    </div>
  );
}

function Growable(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  const [grown, setGrown] = useState(false);
  return (
    <div ref={ref}>
      <button type="button">First</button>
      <button type="button" onClick={() => setGrown(true)}>
        Grow
      </button>
      {grown && <button type="button">Added</button>}
    </div>
  );
}

function DialogBody(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  return (
    <div ref={ref}>
      <button type="button">Inside</button>
    </div>
  );
}

/** Two independent dialogs, mounted at once — `Outer` first, `Inner` second. */
function Outer(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  return (
    <div ref={ref}>
      <button type="button">Outer first</button>
      <button type="button">Outer last</button>
    </div>
  );
}

function Inner(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>();
  return (
    <div ref={ref}>
      <button type="button">Inner first</button>
      <button type="button">Inner last</button>
    </div>
  );
}

/** Stands in for `ApprovalDialog`: pinned to the front regardless of mount order. */
function Front(): JSX.Element {
  const ref = useModalDialog<HTMLDivElement>({ front: true });
  return (
    <div ref={ref}>
      <button type="button">Front first</button>
      <button type="button">Front last</button>
    </div>
  );
}

/** `Front` already open, `Outer` mounting on top of it in a later commit. */
function FrontThenOuter({ outerOpen }: { outerOpen: boolean }): JSX.Element {
  return (
    <>
      <Front />
      {outerOpen && <Outer />}
    </>
  );
}

/** A page with a trigger, a dialog it can open, and a way to remove the trigger. */
function Page(): JSX.Element {
  const [openerPresent, setOpenerPresent] = useState(true);
  const [dialogOpen, setDialogOpen] = useState(false);

  return (
    <div>
      {openerPresent && (
        <button type="button" onClick={() => setDialogOpen(true)}>
          Open
        </button>
      )}
      <button type="button" onClick={() => setOpenerPresent(false)}>
        Remove opener
      </button>
      {dialogOpen && (
        <div>
          <DialogBody />
          <button type="button" onClick={() => setDialogOpen(false)}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}

describe("useModalDialog", () => {
  it("wraps Tab from the last focusable element to the first", async () => {
    const user = userEvent.setup();
    render(<ThreeInARing />);

    screen.getByText("Last").focus();
    await user.tab();

    expect(document.activeElement).toBe(screen.getByText("First"));
  });

  it("wraps Shift+Tab from the first focusable element to the last", async () => {
    const user = userEvent.setup();
    render(<ThreeInARing />);

    screen.getByText("First").focus();
    await user.tab({ shift: true });

    expect(document.activeElement).toBe(screen.getByText("Last"));
  });

  it("pulls focus back in when it starts outside the dialog entirely", async () => {
    // A click on a non-focusable part of the dialog — a paragraph, a heading
    // — leaves `document.activeElement` on `body`, which is neither `first`
    // nor `last`. A trap that only compares against those two boundaries
    // never engages here, and the next Tab walks straight into whatever is
    // behind the overlay.
    const user = userEvent.setup();
    render(<ThreeInARing />);

    (document.activeElement as HTMLElement | null)?.blur();
    expect(document.activeElement).toBe(document.body);

    await user.tab();

    expect(document.activeElement).toBe(screen.getByText("First"));
  });

  it("does not treat a disabled control as the ring's boundary", async () => {
    const user = userEvent.setup();
    render(<WithATrailingDisabledControl />);

    // "Disabled" sits after "Last" in the DOM but cannot be focused. If the
    // hook's own idea of "last" did not exclude it, Tab from "Last" would
    // find nothing to wrap to.
    screen.getByText("Last").focus();
    await user.tab();

    expect(document.activeElement).toBe(screen.getByText("First"));
  });

  it("includes a control added after mount in the ring on the next Tab", async () => {
    // A ring captured once at mount would still be [First, Grow] here, so
    // Tab from a button added later would find no match for "last" and never
    // wrap. These dialogs grow while open — a field added to `NewItemDialog`,
    // a step change in `ImportPanel` — so the ring has to be read fresh.
    const user = userEvent.setup();
    render(<Growable />);

    await user.click(screen.getByText("Grow"));
    screen.getByText("Added").focus();
    await user.tab();

    expect(document.activeElement).toBe(screen.getByText("First"));
  });

  it("restores focus to whatever had it before the dialog opened", async () => {
    const user = userEvent.setup();
    render(<Page />);

    const opener = screen.getByText("Open");
    await user.click(opener);
    await user.click(screen.getByText("Close"));

    expect(document.activeElement).toBe(opener);
  });

  it("only traps Tab in the topmost dialog when two are open at once", async () => {
    // `Vault.tsx` mounts `ApprovalDialog` over `NewItemDialog` on purpose — an
    // agent can be blocked waiting on an answer while someone is filling in a
    // form. Without the stack, both hooks' keydown listeners fire on the same
    // Tab and both call `preventDefault` and pull focus into their own
    // dialog; the visible result is right only because the later-registered
    // listener wins by overwriting the first, and on the way there a real
    // `focus` event lands on a control in the dialog behind the modal one.
    const user = userEvent.setup();
    render(
      <>
        <Outer />
        <Inner />
      </>,
    );

    const focused: string[] = [];
    for (const button of screen.getAllByRole("button")) {
      button.addEventListener("focus", () => focused.push(button.textContent ?? ""));
    }

    screen.getByText("Inner last").focus();
    focused.length = 0; // that call is the setup, not the Tab under test

    await user.tab();

    expect(focused).toEqual(["Inner first"]);
    expect(document.activeElement).toBe(screen.getByText("Inner first"));
  });

  it("keeps a front-pinned dialog trapping Tab even when another dialog mounts on top of it later", async () => {
    // `ApprovalDialog` is pinned above every overlay by CSS (`overlay--front`),
    // but nothing stops the command palette or `NewItemDialog` from opening
    // while it's already up — mounting *after* it, in a later commit. A stack
    // ordered by mount time alone would hand the trap to that later dialog,
    // even though the front one is what's actually on screen.
    const user = userEvent.setup();
    const { rerender } = render(<FrontThenOuter outerOpen={false} />);
    rerender(<FrontThenOuter outerOpen={true} />);

    screen.getByText("Outer last").focus();
    await user.tab();

    expect(document.activeElement).toBe(screen.getByText("Front first"));
  });

  it("does not throw when the previously focused element is gone by the time the dialog unmounts", async () => {
    const user = userEvent.setup();
    render(<Page />);

    await user.click(screen.getByText("Open"));
    // The trigger that had focus before the dialog opened is removed from
    // the document while the dialog is still up.
    await user.click(screen.getByText("Remove opener"));
    await user.click(screen.getByText("Close"));

    expect(screen.queryByText("Inside")).toBeNull();
  });
});
