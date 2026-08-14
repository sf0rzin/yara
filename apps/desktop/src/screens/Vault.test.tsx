import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { installDevMock } from "../lib/devMock";
import { Vault } from "./Vault";

const selectionOf = (options: HTMLElement[]) =>
  options.map((option) => option.getAttribute("aria-selected"));

/**
 * The vault, against the dev mock rather than a hand-built stub.
 *
 * The mock is already the description of what the backend answers, and a second
 * one written here would be a second thing to keep in step with Rust.
 */
describe("Vault item list", () => {
  beforeEach(() => {
    installDevMock();
  });

  it("moves the selection an assistive technology can see with ArrowDown", async () => {
    render(<Vault onLock={vi.fn()} />);

    await screen.findAllByRole("option");
    const options = screen.getAllByRole("option");
    expect(options.length).toBeGreaterThan(1);

    // The list opens on its first row, which is what keeps the three-column
    // geometry stable.
    await waitFor(() => expect(selectionOf(options)[0]).toBe("true"));
    expect(selectionOf(options)[1]).toBe("false");

    await userEvent.keyboard("{ArrowDown}");

    // aria-selected, not the data-selected styling hook this used to move on
    // its own: the highlight was visible to sighted users and to nobody else.
    await waitFor(() => expect(selectionOf(options)[1]).toBe("true"));
    expect(selectionOf(options)[0]).toBe("false");
    // And it is the row you are now on, so a screen reader is told where the
    // arrow key left you rather than being told nothing at all.
    expect(document.activeElement).toBe(options[1]);
  });
});
