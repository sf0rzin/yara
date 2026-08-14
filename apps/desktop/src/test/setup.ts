import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

/*
 * Unmount whatever the last test left behind.
 *
 * Testing Library registers this for itself only when vitest runs with globals,
 * which this suite deliberately does not — imports say where a name comes from.
 * Without the hook a component left mounted by one test keeps its window
 * keydown listeners registered through the next one, and half this app's
 * behaviour is window keydown listeners.
 */
afterEach(cleanup);
