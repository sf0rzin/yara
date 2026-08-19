import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { VaultProfile } from "../api";
import { VaultChooser } from "./VaultChooser";

const VAULTS: VaultProfile[] = [
  {
    id: "default",
    name: "Personal",
    selected: false,
    rememberedUntil: null,
  },
  {
    id: "work",
    name: "Work",
    selected: false,
    rememberedUntil: null,
  },
];

describe("VaultChooser", () => {
  it("requires an explicit confirmation before removing a Vault", async () => {
    const select = vi.fn(async () => undefined);
    const remove = vi.fn(async () => undefined);
    render(
      <VaultChooser
        vaults={VAULTS}
        onSelect={select}
        onRemove={remove}
        onCreate={vi.fn()}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Remove Personal Vault" }),
    );

    const dialog = screen.getByRole("alertdialog", {
      name: "Remove “Personal”?",
    });
    expect(dialog.textContent).toContain("This cannot be undone");
    expect(remove).not.toHaveBeenCalled();
    expect(select).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(remove).not.toHaveBeenCalled();

    await userEvent.click(
      screen.getByRole("button", { name: "Remove Personal Vault" }),
    );
    const confirm = screen.getByRole("button", { name: "Remove Vault" });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await userEvent.type(screen.getByRole("textbox", { name: "Vault name" }), "Personal");
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    await userEvent.click(confirm);

    await waitFor(() => expect(remove).toHaveBeenCalledWith("default", "Personal"));
  });
});
