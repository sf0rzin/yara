import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { installDevMock } from "../lib/devMock";
import { ImportDialog } from "./ImportPanel";

beforeEach(() => {
  installDevMock();
});

describe("Proton Pass import", () => {
  it("edits names and folders before writing the imported items", async () => {
    const onImported = vi.fn();
    const writeImport = vi.fn((_args?: Record<string, unknown>) => Promise.resolve(2));
    const internals = (
      window as unknown as {
        __TAURI_INTERNALS__: {
          invoke: (command: string, args?: Record<string, unknown>) => Promise<unknown>;
        };
      }
    ).__TAURI_INTERNALS__;
    const invoke = vi.fn(internals.invoke);
    internals.invoke = (command, args) => {
      if (command === "preview_import") {
        return Promise.resolve({
          source: "protonPass",
          fileToken: "fixture-token",
          ready: [
            { index: 0, name: "Synthetic login", folder: null },
            { index: 1, name: "Synthetic card", folder: "Cards" },
          ],
          duplicates: ["Already here"],
          skipped: [],
          warnings: [
            {
              name: "Synthetic login",
              reason: "the original modification time could not be read",
            },
          ],
        });
      }
      if (command === "run_import") return writeImport(args);
      return invoke(command, args);
    };

    render(<ImportDialog onClose={vi.fn()} onImported={onImported} />);
    await userEvent.click(screen.getByRole("button", { name: "Choose an export file" }));

    expect(await screen.findByDisplayValue("Synthetic card")).toBeTruthy();
    expect(screen.getByText("Proton Pass").closest("p")?.textContent).toContain(
      "2 items to add",
    );
    expect(screen.getByText("Already here")).toBeTruthy();
    expect(screen.getByText("Needs attention")).toBeTruthy();
    expect(screen.getByText(/only names and folders can be edited here/i)).toBeTruthy();

    const names = screen.getAllByLabelText("Name");
    const folders = screen.getAllByLabelText("Folder");
    await userEvent.clear(names[0]);
    expect(
      screen.getByRole("button", { name: "Import 2 items" }).hasAttribute("disabled"),
    ).toBe(true);
    await userEvent.type(names[0], "Renamed login");
    await userEvent.type(folders[0], "Personal");

    await userEvent.click(screen.getByRole("button", { name: "Import 2 items" }));

    expect(await screen.findByText("Imported 2 items.")).toBeTruthy();
    expect(writeImport).toHaveBeenCalledWith({
      path: "C:\\Users\\anthony\\Downloads\\proton-authenticator-export.txt",
      expectedFileToken: "fixture-token",
      edits: [
        { index: 0, name: "Renamed login", folder: "Personal" },
        { index: 1, name: "Synthetic card", folder: "Cards" },
      ],
    });
    await waitFor(() => expect(onImported).toHaveBeenCalledOnce());
  });
});
