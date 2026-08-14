import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAutoLock } from "./useAutoLock";

const MINUTE = 60_000;

describe("useAutoLock", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("locks once and then stops, however long it is left running", async () => {
    const onLock = vi.fn();
    renderHook(() => useAutoLock(MINUTE, onLock));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(MINUTE);
    });
    expect(onLock).toHaveBeenCalledTimes(1);

    // The countdown keeps ticking after zero, and the callback drops the vault
    // in the Rust process. Firing it again every second would be a locked
    // vault trying to lock itself for as long as the window stays open.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10 * MINUTE);
    });
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("never locks when the interval is Infinity", async () => {
    const onLock = vi.fn();
    // What "Only when I say so" passes in. Somebody working in a locked room
    // chose this deliberately, and a timer that fires anyway is the app
    // overruling a decision it offered them.
    const { result } = renderHook(() => useAutoLock(Number.POSITIVE_INFINITY, onLock));

    await act(async () => {
      await vi.advanceTimersByTimeAsync(24 * 60 * MINUTE);
    });

    expect(onLock).not.toHaveBeenCalled();
    expect(result.current).toBe(Number.POSITIVE_INFINITY);
  });
});
