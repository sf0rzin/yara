import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ApprovalPrompt } from "../api";
import { ApprovalDialog } from "./ApprovalDialog";

/*
 * The IPC boundary, so the assertion is about what actually reaches the broker
 * rather than about which button turned grey. This dialog is the only thing
 * standing between an agent and a credential, and "it looked like it denied"
 * is not a claim worth testing.
 */
const invoke = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("@tauri-apps/api/core", () => ({ invoke }));

const RUN: ApprovalPrompt = {
  id: "p-run-1",
  program: "claude.exe",
  programPath: "C:\\Users\\anthony\\AppData\\Local\\Programs\\claude\\claude.exe",
  pid: 21804,
  item: "AWS Console",
  field: "password",
  mode: "run",
  command: "terraform apply -auto-approve",
  envVar: "AWS_SECRET_ACCESS_KEY",
  reason: "apply the staging plan",
  discloses: false,
};

/**
 * A run that is a reveal in disguise: the command would print the value, so
 * the answer is "may it see this?" whatever the request called itself.
 */
const SHELL: ApprovalPrompt = {
  ...RUN,
  id: "p-shell-1",
  command: "cmd /C echo %AWS_SECRET_ACCESS_KEY%",
  discloses: true,
};

describe("ApprovalDialog", () => {
  beforeEach(() => {
    invoke.mockClear();
  });

  it("denies when the prompt is dismissed with Escape", async () => {
    const onSettled = vi.fn();
    render(<ApprovalDialog prompt={RUN} onSettled={onSettled} />);

    await userEvent.keyboard("{Escape}");

    await waitFor(() => expect(onSettled).toHaveBeenCalledTimes(1));
    expect(invoke).toHaveBeenCalledWith("resolve_approval", {
      id: RUN.id,
      choice: "deny",
      minutes: null,
    });
  });

  it("offers no timed grant for a request that discloses the secret", async () => {
    render(<ApprovalDialog prompt={SHELL} onSettled={vi.fn()} />);

    // Both halves of the timed path: the disclosure has to close the door on
    // the drawer as well as on the button inside it, or "More options…" opens
    // an "Allow for 15 min" that nothing else prevents.
    expect(screen.queryByRole("button", { name: /more options/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /allow for/i })).toBeNull();
    expect(screen.getAllByRole("button").map((button) => button.textContent)).toEqual([
      "Deny",
      "Allow once",
    ]);

    await userEvent.click(screen.getByRole("button", { name: "Allow once" }));

    await waitFor(() => expect(invoke).toHaveBeenCalledTimes(1));
    // A window grant is a standing permission to hand this value over again
    // without asking. Nothing on this prompt may create one.
    expect(invoke).toHaveBeenCalledWith("resolve_approval", {
      id: SHELL.id,
      choice: "once",
      minutes: null,
    });
  });
});
