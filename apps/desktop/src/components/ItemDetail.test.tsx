import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Cleared, ItemSummary } from "../api";
import { installDevMock } from "../lib/devMock";
import { ItemDetail } from "./ItemDetail";

/**
 * What the detail pane says about a copy.
 *
 * This is the screen that used to answer every copy with "Password copied.
 * Clipboard clears shortly." — one sentence for three different futures, two of
 * which it was not entitled to promise. The assertions here are about which of
 * the three the user is actually told about.
 *
 * Against the dev mock, because the mock is already the description of what the
 * backend answers, and the three outcomes cannot be produced on demand anywhere
 * else: they need Windows to refuse something.
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
  missingSecondFactor: false,
  updatedAt: 1_753_000_000,
  createdAt: 1_700_000_000,
};

describe("password health", () => {
  it("shows reuse and a missing second factor as quiet lines beside the password", () => {
    render(<ItemDetail item={{ ...GITHUB, reused: true, missingSecondFactor: true }} />);

    expect(screen.getByText("This password is reused.")).toBeTruthy();
    expect(screen.getByText("No second factor is stored.")).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });
});

describe("copying a password", () => {
  beforeEach(() => {
    installDevMock();
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("says when it clears, and claims nothing about history it was not told", async () => {
    const said = await copyThePassword();

    expect(said.textContent).toMatch(/comes off the clipboard in 20 seconds/i);
    expect(said.textContent).toMatch(/keep it out of clipboard history/i);
    expect(said.className).not.toContain("notice--loud");
  });

  it("warns when Windows would not keep the copy out of clipboard history", async () => {
    window.history.replaceState({}, "", "/?clipboard=history");
    const said = await copyThePassword();

    // The exclusion formats were refused, so the password is in Win+V and
    // possibly on the user's other machines. Clearing the clipboard in twenty
    // seconds removes neither, and the pane must not imply that it does.
    expect(said.textContent).toMatch(/Win\+V/);
    expect(said.className).toContain("notice--loud");
  });

  it("reports a clear that happened, quietly", async () => {
    await copyThePassword();
    const said = await clearReports("wiped");

    expect(said.textContent).toMatch(/off the clipboard/i);
    expect(said.className).not.toContain("notice--loud");
    expect(screen.queryByRole("button", { name: /take it off now/i })).toBeNull();
  });

  it("does not dress up a clipboard somebody else took as a failure", async () => {
    await copyThePassword();
    const said = await clearReports("alreadyGone");

    // Nothing went wrong: the user copied something else, and taking that off
    // the clipboard to remove a password that is no longer there would be the
    // app destroying their work. It must not read as an error.
    expect(said.textContent).toMatch(/something else was on the clipboard/i);
    expect(said.className).not.toContain("notice--loud");
    expect(screen.queryByRole("button", { name: /take it off now/i })).toBeNull();
  });

  it("says the password is still there when the clear failed, and offers to retry", async () => {
    await copyThePassword();
    const said = await clearReports("failed");

    expect(said.textContent).toMatch(/still on the clipboard/i);
    expect(said.textContent).toMatch(/Access is denied/);
    expect(said.className).toContain("notice--loud");

    // The retry is the only thing standing between a refused clear and a
    // password sitting on the clipboard until the machine is locked.
    await userEvent.click(screen.getByRole("button", { name: /take it off now/i }));
    const after = await screen.findByRole("status");
    expect(after.textContent).toMatch(/off the clipboard/i);
    expect(after.className).not.toContain("notice--loud");
  });
});

/** A second item, for what happens when the pane moves on. */
const STRIPE: ItemSummary = {
  ...GITHUB,
  id: "5",
  name: "Stripe",
  url: "https://dashboard.stripe.com",
};

describe("moving to another item", () => {
  beforeEach(() => {
    installDevMock();
    // A username is not a secret and still goes through the webview clipboard,
    // which jsdom does not have. Only the write is needed: nothing reads it
    // back any more, which was half the reason the old implementation could not
    // keep its promises.
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: async () => undefined },
      configurable: true,
    });
  });

  it("keeps a warning that is about the clipboard rather than the item", async () => {
    const view = render(<ItemDetail item={GITHUB} />);
    await userEvent.click(screen.getByRole("button", { name: "Copy password" }));
    await screen.findByRole("status");
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    await clearReports("failed");

    view.rerender(<ItemDetail item={STRIPE} />);

    // The password does not come off the clipboard because you clicked another
    // row, and this is the only place anybody is told it is still there.
    const said = await screen.findByRole("status");
    expect(said.textContent).toMatch(/still on the clipboard/i);
  });

  it("drops a line that belonged to the item being left", async () => {
    const view = render(<ItemDetail item={GITHUB} />);
    await userEvent.click(screen.getByRole("button", { name: "Copy username" }));
    expect((await screen.findByRole("status")).textContent).toMatch(/username copied/i);

    view.rerender(<ItemDetail item={STRIPE} />);
    expect(screen.queryByRole("status")).toBeNull();
  });
});

/** Renders the pane, presses copy, and hands back the line it printed. */
async function copyThePassword(): Promise<HTMLElement> {
  render(<ItemDetail item={GITHUB} />);
  await userEvent.click(screen.getByRole("button", { name: "Copy password" }));

  const said = await screen.findByRole("status");
  // The pane subscribes to the clear in an effect, a couple of promises deep.
  // Firing before that lands would test nothing at all.
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  return said;
}

/** Brings the clear forward, with the outcome this test is about. */
async function clearReports(outcome: Cleared["outcome"]): Promise<HTMLElement> {
  await act(async () => {
    (window as unknown as { __yaraClipboard: (o: Cleared["outcome"]) => void })
      .__yaraClipboard(outcome);
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
  return await screen.findByRole("status");
}
