import { render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ErrorBoundary } from "./ErrorBoundary";

/*
 * What happens when the tree above this boundary throws.
 *
 * `useAutoLock` is a hook, so an uncaught render error takes its idle timer
 * down with the rest of the component tree — nothing is left counting
 * against the key still sitting in the backend. These tests are about the
 * thing that has to replace that timer: the boundary locking the vault the
 * moment it catches something, and being honest about whether that worked.
 */
const { lockVault } = vi.hoisted(() => ({ lockVault: vi.fn() }));

// `errorMessage` is left as the real implementation — only `lockVault` needs
// to be steered per test, and reimplementing `errorMessage` here would be a
// second copy of a rule this suite has no business owning.
vi.mock("../api", async () => {
  const actual = await vi.importActual<typeof import("../api")>("../api");
  return { ...actual, lockVault };
});

function Bomb({ message }: { message: string }): never {
  throw new Error(message);
}

function Fine() {
  return <p>steady</p>;
}

describe("ErrorBoundary", () => {
  beforeEach(() => {
    lockVault.mockReset();
  });

  it("renders the fallback instead of letting the error propagate", async () => {
    lockVault.mockResolvedValue(undefined);

    render(
      <ErrorBoundary>
        <Bomb message="boom" />
      </ErrorBoundary>,
    );

    expect((await screen.findByRole("alert")).textContent).toContain(
      "Yara hit an error and stopped",
    );
  });

  it("locks the vault exactly once when a child throws", async () => {
    lockVault.mockResolvedValue(undefined);

    // Rendered bare, not inside `React.StrictMode` the way `main.tsx` mounts
    // the real boundary. The Strict Mode case is covered separately below,
    // rather than assumed to behave the same because this one passes.
    render(
      <ErrorBoundary>
        <Bomb message="boom" />
      </ErrorBoundary>,
    );

    await screen.findByText("The vault has been locked.");
    expect(lockVault).toHaveBeenCalledTimes(1);
  });

  it("still locks exactly once inside React.StrictMode, the way main.tsx mounts it", async () => {
    lockVault.mockResolvedValue(undefined);

    // Strict Mode double-invokes render for both function and class
    // components, which is why this gets its own test rather than a comment
    // on the one above: `componentDidCatch` sits in the commit phase, not the
    // render phase Strict Mode is re-running, so it should still fire once —
    // but "should" is exactly the kind of claim this suite exists to check
    // rather than take on faith.
    render(
      <StrictMode>
        <ErrorBoundary>
          <Bomb message="boom" />
        </ErrorBoundary>
      </StrictMode>,
    );

    await screen.findByText("The vault has been locked.");
    expect(lockVault).toHaveBeenCalledTimes(1);
  });

  it("renders children untouched and never calls lockVault when nothing throws", () => {
    render(
      <ErrorBoundary>
        <Fine />
      </ErrorBoundary>,
    );

    expect(screen.getByText("steady").textContent).toBe("steady");
    expect(lockVault).not.toHaveBeenCalled();
  });

  it("says the vault could not be locked when the lock call itself fails", async () => {
    lockVault.mockRejectedValue(new Error("the pipe is gone"));

    render(
      <ErrorBoundary>
        <Bomb message="boom" />
      </ErrorBoundary>,
    );

    // Not a throw from the handler: the rejection turns into the message
    // the user reads, rather than replacing it with a less useful one.
    expect(await screen.findByText(/could not be locked/i)).toBeTruthy();
  });

  it("shows the thrown error's own message", async () => {
    lockVault.mockResolvedValue(undefined);

    render(
      <ErrorBoundary>
        <Bomb message="the vault file could not be parsed" />
      </ErrorBoundary>,
    );

    expect(await screen.findByText("the vault file could not be parsed")).toBeTruthy();
  });
});
