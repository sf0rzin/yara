import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { AutoLockMenu } from "./AutoLockMenu";

it("offers creating another vault and logging out as separate actions", async () => {
  const createVault = vi.fn();
  const logout = vi.fn();
  render(
    <AutoLockMenu
      current={900}
      triggerRef={{ current: document.createElement("button") }}
      onChoose={vi.fn()}
      onLockNow={vi.fn()}
      onCreateVault={createVault}
      onLogout={logout}
      onDismiss={vi.fn()}
    />,
  );

  await userEvent.click(
    screen.getByRole("menuitem", { name: "Create another Vault" }),
  );
  await userEvent.click(screen.getByRole("menuitem", { name: "Log out" }));

  expect(createVault).toHaveBeenCalledOnce();
  expect(logout).toHaveBeenCalledOnce();
});
