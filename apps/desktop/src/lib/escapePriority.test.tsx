import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ApprovalPrompt } from "../api";
import { ApprovalDialog } from "../components/ApprovalDialog";
import { ImportDialog } from "../components/ImportPanel";
import { NewItemDialog } from "../components/NewItemDialog";
import { installDevMock } from "./devMock";

/**
 * `ApprovalDialog`, `NewItemDialog` and `ImportDialog` each bind their own
 * `window` listener for Escape, and `Vault.tsx` can have any one of the
 * latter two mounted alongside the first — an agent's request can arrive
 * while someone is filling in a new item, or partway through an import.
 * Before `isTopmostDialog`, one Escape ran both listeners: the request was
 * denied and whatever was behind it closed in the same keystroke — for
 * `NewItemDialog`, `dismiss` also clears any TOTP secret scanned into it, so
 * that half was not recoverable either. This is the IPC boundary rather than
 * which components unmounted, for the same reason `ApprovalDialog.test.tsx`
 * tests it there: "it looked like it closed" is not a claim worth testing on
 * the dialog that decides whether an agent gets a credential.
 */
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

const calledWith = (invoke: ReturnType<typeof watchIpc>, command: string) =>
  invoke.mock.calls.some(([called]) => called === command);

const PROMPT: ApprovalPrompt = {
  id: "p-1",
  program: "claude.exe",
  programPath: null,
  pid: 1,
  item: "GitHub",
  field: "password",
  mode: "reveal",
  command: null,
  envVar: null,
  reason: "read the token",
  discloses: false,
};

beforeEach(() => {
  installDevMock();
});

describe("Escape with more than one dialog open", () => {
  it("denies the approval prompt without also discarding the form behind it", async () => {
    const onClose = vi.fn();
    const invoke = watchIpc();

    render(
      <>
        <NewItemDialog onClose={onClose} onCreated={vi.fn()} />
        <ApprovalDialog prompt={PROMPT} onSettled={vi.fn()} />
      </>,
    );

    await userEvent.keyboard("{Escape}");

    expect(calledWith(invoke, "resolve_approval")).toBe(true);
    expect(calledWith(invoke, "clear_scanned_totp")).toBe(false);
    expect(onClose).not.toHaveBeenCalled();
  });

  it("denies the approval prompt without also closing the import dialog behind it", async () => {
    const onClose = vi.fn();
    const invoke = watchIpc();

    render(
      <>
        <ImportDialog onClose={onClose} onImported={vi.fn()} />
        <ApprovalDialog prompt={PROMPT} onSettled={vi.fn()} />
      </>,
    );

    await userEvent.keyboard("{Escape}");

    expect(calledWith(invoke, "resolve_approval")).toBe(true);
    expect(onClose).not.toHaveBeenCalled();
  });
});
