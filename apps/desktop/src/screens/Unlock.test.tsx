import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { listVaults } from "../api";
import { installDevMock } from "../lib/devMock";
import { Unlock } from "./Unlock";

describe("Unlock", () => {
  beforeEach(() => {
    installDevMock();
    Object.defineProperty(window, "matchMedia", {
      value: () => ({ matches: true }),
      configurable: true,
    });
  });

  it("asks Windows to remember the vault for two weeks", async () => {
    const authenticated = vi.fn();
    render(
      <Unlock
        mode="unlock"
        vaultName="Personal"
        onAuthenticated={authenticated}
      />,
    );

    await userEvent.type(screen.getByLabelText("Master password"), "hunter2");
    await userEvent.click(
      screen.getByRole("checkbox", { name: "Remember for 2 weeks" }),
    );
    await userEvent.click(screen.getByRole("button", { name: "Unlock vault" }));

    await waitFor(() => expect(authenticated).toHaveBeenCalledOnce());
    const [profile] = await listVaults();
    expect(profile.rememberedUntil).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });
});
