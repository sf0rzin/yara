import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ItemSummary } from "../api";
import { installDevMock } from "../lib/devMock";
import { NewItemDialog } from "./NewItemDialog";

/**
 * The rule the whole file is really here to guard: an untouched password box
 * sends `null` and means "leave it", a box typed into and then cleared sends
 * `""` and means "remove it", and `update_item` on the other side reads those
 * as `Option<String>`. Three lines in two files, correct today, with nothing
 * pinning them together — the failure mode is silently destroying a password
 * the user meant to keep.
 *
 * Against the dev mock rather than a hand-rolled fake of `../api`: this is
 * the largest component in the app and the only one that both creates and
 * edits, and the mock is already the realistic backend every other screen's
 * tests run against.
 */
const GITHUB: ItemSummary = {
  id: "1",
  name: "GitHub",
  kind: "login",
  username: "anthony@axono.dev",
  url: "https://github.com",
  folder: null,
  tags: ["work"],
  hasPassword: true,
  hasTotp: false,
  reused: false,
  // Follows from `hasTotp: false` on an item that has a password. A fixture
  // that contradicts the rule it stands in for is a trap for the next test.
  missingSecondFactor: true,
  updatedAt: 1_753_000_000,
  createdAt: 1_700_000_000,
};

/** The one seed item carrying custom fields — one plain, one secret. */
const STRIPE: ItemSummary = {
  id: "5",
  name: "Stripe",
  kind: "login",
  username: "finance@axono.dev",
  url: "https://dashboard.stripe.com",
  folder: "Work",
  tags: ["finance"],
  hasPassword: true,
  hasTotp: true,
  reused: false,
  missingSecondFactor: false,
  updatedAt: 1_752_600_000,
  createdAt: 1_752_600_000 - 86_400 * 420,
};

/** The IPC, wrapped, so a test can assert about the exact arguments a call carried. */
function watchIpc() {
  const internals = (
    window as unknown as {
      __TAURI_INTERNALS__: {
        invoke: (command: string, args: Record<string, unknown>) => Promise<unknown>;
      };
    }
  ).__TAURI_INTERNALS__;

  const invoke = vi.fn(internals.invoke);
  internals.invoke = invoke;
  return invoke;
}

/** The arguments of every call to `command`, in order. */
const askedTo = (invoke: ReturnType<typeof watchIpc>, command: string) =>
  invoke.mock.calls.filter(([called]) => called === command).map(([, args]) => args);

/**
 * The password box, on an edit.
 *
 * Not `getByLabelText("Password")`: the empty-box hint lives inside the same
 * `<label>`, so the label's full text is "Password" followed by that whole
 * sentence whenever the hint is showing, and an exact match against the bare
 * word finds nothing.
 */
const passwordBox = () => screen.getByLabelText(/^Password/);

/**
 * Redirects one command to `respond` and leaves every other command going to
 * the dev mock underneath. For the two cases the mock cannot produce on its
 * own: a save that never resolves, and a lookup that fails outright.
 *
 * Returns the restore function rather than relying on the next `beforeEach`
 * to paper over it — the interception outlives the test otherwise, and a
 * later test in the same file asserting against `add_item` or `item_extras`
 * would be silently talking to this override instead of the mock.
 */
function interceptCommand(
  command: string,
  respond: (args: Record<string, unknown>) => Promise<unknown>,
): () => void {
  const internals = (
    window as unknown as {
      __TAURI_INTERNALS__: {
        invoke: (command: string, args: Record<string, unknown>) => Promise<unknown>;
      };
    }
  ).__TAURI_INTERNALS__;
  const original = internals.invoke;
  internals.invoke = (calledCommand: string, args: Record<string, unknown>) =>
    calledCommand === command ? respond(args) : original(calledCommand, args);
  return () => {
    internals.invoke = original;
  };
}

describe("the password contract on an edit", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("sends password: null when the box is never touched", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();

    // Clicking Save races the effect that loads GITHUB's own fields and
    // notes. `toMatchObject` only checks `password` here, so which one wins
    // does not change the outcome — but it would, for an item that actually
    // carried fields, which is exactly why GITHUB rather than STRIPE is the
    // fixture for this one.
    render(<NewItemDialog editing={GITHUB} onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /save changes/i }));

    const [sent] = askedTo(invoke, "update_item");
    expect(sent.edit).toMatchObject({ password: null });
  });

  it("sends the typed password when the box is touched", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();

    render(<NewItemDialog editing={GITHUB} onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(passwordBox(), "a new one entirely");
    await user.click(screen.getByRole("button", { name: /save changes/i }));

    const [sent] = askedTo(invoke, "update_item");
    expect(sent.edit).toMatchObject({ password: "a new one entirely" });
  });

  it("sends an empty string, not null, when the box is typed into and then cleared", async () => {
    // `null` here would silently keep a password the user deliberately
    // erased — the one failure this whole file exists to catch.
    const user = userEvent.setup();
    const invoke = watchIpc();

    render(<NewItemDialog editing={GITHUB} onClose={vi.fn()} onCreated={vi.fn()} />);
    const password = passwordBox();
    await user.type(password, "briefly");
    await user.clear(password);
    await user.click(screen.getByRole("button", { name: /save changes/i }));

    const [sent] = askedTo(invoke, "update_item");
    expect(sent.edit).toMatchObject({ password: "" });
  });

  it("shows the empty-box hint while untouched, and hides it once typed into", async () => {
    const user = userEvent.setup();

    render(<NewItemDialog editing={GITHUB} onClose={vi.fn()} onCreated={vi.fn()} />);

    expect(
      screen.getByText(/left empty, the stored password stays as it is/i),
    ).toBeTruthy();

    await user.type(passwordBox(), "x");

    expect(screen.queryByText(/left empty, the stored password stays as it is/i)).toBeNull();
  });
});

describe("creating an item", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("trims the name before sending it", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();

    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(screen.getByLabelText("Name"), "  Padded Name  ");
    await user.click(screen.getByRole("button", { name: /save item/i }));

    const [sent] = askedTo(invoke, "add_item");
    expect((sent.item as { name: string }).name).toBe("Padded Name");
  });

  it("sends every untouched optional field as null, not an empty string", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();

    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(screen.getByLabelText("Name"), "Bare Minimum");
    await user.click(screen.getByRole("button", { name: /save item/i }));

    const [sent] = askedTo(invoke, "add_item");
    expect(sent.item).toMatchObject({
      username: null,
      password: null,
      url: null,
      notes: null,
    });
  });

  it("disables Save while the name is blank", () => {
    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);

    const save = screen.getByRole("button", { name: /save item/i }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
  });

  it("disables Save while a save is already in flight", async () => {
    const user = userEvent.setup();
    // Never settles — busy has to stay true for as long as this test looks.
    const restore = interceptCommand("add_item", () => new Promise(() => {}));

    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(screen.getByLabelText("Name"), "Something");
    await user.click(screen.getByRole("button", { name: /save item/i }));

    const stillSaving = (await screen.findByRole("button", {
      name: /saving/i,
    })) as HTMLButtonElement;
    expect(stillSaving.disabled).toBe(true);

    restore();
  });
});

describe("custom fields", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("drops a field left with a blank label, keeping the ones beside it", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();

    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.type(screen.getByLabelText("Name"), "Fielded");

    await user.click(screen.getByRole("button", { name: /add a field/i }));
    await user.type(screen.getByLabelText("Field 1 name"), "Kept");
    await user.type(screen.getByLabelText("Field 1 value"), "kept-value");

    // Left blank on purpose.
    await user.click(screen.getByRole("button", { name: /add a field/i }));
    await user.type(screen.getByLabelText("Field 2 value"), "orphaned-value");

    await user.click(screen.getByRole("button", { name: /save item/i }));

    const [sent] = askedTo(invoke, "add_item");
    expect((sent.item as { fields: unknown[] }).fields).toEqual([
      { label: "Kept", value: "kept-value", secret: true },
    ]);
  });

  it("toggles a field's input type and the button's aria-pressed together", async () => {
    const user = userEvent.setup();

    render(<NewItemDialog onClose={vi.fn()} onCreated={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: /add a field/i }));

    const value = screen.getByLabelText("Field 1 value") as HTMLInputElement;
    const toggle = screen.getByRole("button", { name: "Stop hiding this field" });

    // New fields default to secret.
    expect(value.type).toBe("password");
    expect(toggle.getAttribute("aria-pressed")).toBe("true");

    await user.click(toggle);

    expect(value.type).toBe("text");
    expect(screen.getByRole("button", { name: "Hide this field" })).toBe(toggle);
    expect(toggle.getAttribute("aria-pressed")).toBe("false");
  });
});

describe("dismissing the dialog", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("clears the scanned TOTP and closes on Escape", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();
    const onClose = vi.fn();

    render(<NewItemDialog onClose={onClose} onCreated={vi.fn()} />);
    await user.keyboard("{Escape}");

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(askedTo(invoke, "clear_scanned_totp")).toHaveLength(1);
  });

  it("clears the scanned TOTP and closes on the close button", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();
    const onClose = vi.fn();

    render(<NewItemDialog onClose={onClose} onCreated={vi.fn()} />);
    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(askedTo(invoke, "clear_scanned_totp")).toHaveLength(1);
  });

  it("clears the scanned TOTP and closes when the overlay itself is clicked", async () => {
    const user = userEvent.setup();
    const invoke = watchIpc();
    const onClose = vi.fn();

    const { container } = render(<NewItemDialog onClose={onClose} onCreated={vi.fn()} />);
    const overlay = container.querySelector(".overlay");
    if (!overlay) throw new Error("the overlay element is missing");
    await user.click(overlay);

    expect(onClose).toHaveBeenCalledTimes(1);
    expect(askedTo(invoke, "clear_scanned_totp")).toHaveLength(1);
  });

  it("does not close when a click lands inside the dialog", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();

    render(<NewItemDialog onClose={onClose} onCreated={vi.fn()} />);
    await user.click(screen.getByRole("heading", { name: "New item" }));

    expect(onClose).not.toHaveBeenCalled();
  });
});

describe("loading an item to edit", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("reveals each secret custom field exactly once, and fills every field's input", async () => {
    const invoke = watchIpc();

    render(<NewItemDialog editing={STRIPE} onClose={vi.fn()} onCreated={vi.fn()} />);

    const secretValue = (await screen.findByLabelText("Field 2 value")) as HTMLInputElement;
    expect(secretValue.value).toBe("rk_live_51M2n3O4p5Q6r7S");

    const plainValue = screen.getByLabelText("Field 1 value") as HTMLInputElement;
    expect(plainValue.value).toBe("acct_1M2n3O4p5Q");

    // Once, for the one field that is actually secret — the plain one arrives
    // with `item_extras` and never needs its own request.
    expect(askedTo(invoke, "reveal_field")).toEqual([{ id: "5", label: "Restricted key" }]);
  });

  it("shows the error instead of a form that looks complete but silently is not", async () => {
    const restore = interceptCommand("item_extras", () =>
      Promise.reject(new Error("vault is locked")),
    );

    render(<NewItemDialog editing={GITHUB} onClose={vi.fn()} onCreated={vi.fn()} />);

    expect(await screen.findByText("vault is locked")).toBeTruthy();

    restore();
  });
});
