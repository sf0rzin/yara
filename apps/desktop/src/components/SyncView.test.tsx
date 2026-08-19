import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { unlockVault } from "../api";
import { installDevMock } from "../lib/devMock";
import { SyncView } from "./SyncView";

/**
 * Changing the master password, from the settings screen.
 *
 * The command behind this verifies the current password before it re-wraps the
 * key, and the form in front of it has one job the command cannot do: make sure
 * the new password is the one the user meant. Nobody sees what they typed, and
 * a mistyped new password is a vault nobody can open again.
 */
const PASSWORD = "the one that opens it";
const NEW_PASSWORD = "correct horse battery 7!";

/** The IPC, wrapped, so a test can assert about a call that must not happen. */
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

describe("changing the master password", () => {
  beforeEach(async () => {
    installDevMock();
    // The mock adopts whatever password opens it, so each test starts from a
    // known one rather than from whatever the test before it left behind.
    await unlockVault(PASSWORD, false);
  });

  it("refuses a mismatch without asking the vault to re-key anything", async () => {
    const invoke = watchIpc();
    await openTheForm();

    await type("Current master password", PASSWORD);
    await type("New master password", NEW_PASSWORD);
    await type("New master password again", "correct horse battery 8!");
    await userEvent.click(screen.getByRole("button", { name: "Change master password" }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/do not match/i);
    // Not a message with the call going out behind it: a re-key on a password
    // the user cannot see and mistyped is a vault nobody opens again.
    expect(askedTo(invoke, "change_master_password")).toEqual([]);
  });

  it("repeats the vault's own answer when the current password is wrong", async () => {
    await openTheForm();

    await type("Current master password", "not the one");
    await type("New master password", NEW_PASSWORD);
    await type("New master password again", NEW_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Change master password" }));

    // Verbatim. The vault says "wrong password or corrupted data" and means
    // either; narrowing it here would be the interface claiming to know which.
    expect((await screen.findByRole("alert")).textContent).toMatch(
      /could not decrypt: wrong password or corrupted data/,
    );
  });

  it("sends both passwords once the two new ones agree", async () => {
    const invoke = watchIpc();
    await openTheForm();

    await type("Current master password", PASSWORD);
    await type("New master password", NEW_PASSWORD);
    await type("New master password again", NEW_PASSWORD);
    await userEvent.click(screen.getByRole("button", { name: "Change master password" }));

    expect((await screen.findByRole("status")).textContent).toMatch(
      /master password changed/i,
    );
    // Both halves, under the names the command declares: the binding is the
    // one place a rename on the Rust side would go unnoticed.
    expect(askedTo(invoke, "change_master_password")).toEqual([
      { currentPassword: PASSWORD, newPassword: NEW_PASSWORD },
    ]);
    // The form is put away, so the vault's password is not left sitting in
    // three fields on a screen anybody walking past can read.
    expect(screen.queryByLabelText("Current master password")).toBeNull();
  });
});

async function openTheForm(): Promise<void> {
  render(<SyncView />);
  await userEvent.click(
    await screen.findByRole("button", { name: /change master password…/i }),
  );
}

async function type(label: string, value: string): Promise<void> {
  await userEvent.type(screen.getByLabelText(label), value);
}
