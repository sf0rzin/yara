import React from "react";
import ReactDOM from "react-dom/client";

// Bundled locally rather than fetched: the app must work offline and its CSP
// forbids loading anything from a remote origin.
import "@fontsource-variable/inter";
import "@fontsource-variable/jetbrains-mono";

import "./styles/tokens.css";
import "./styles/global.css";
import "./styles/yara.css";

import App from "./App";
import { ErrorBoundary } from "./components/ErrorBoundary";

// Lets the interface run in a plain browser during development. Stripped from
// production builds, and skipped entirely when the real Tauri IPC is present.
if (import.meta.env.DEV && !("__TAURI_INTERNALS__" in window)) {
  const { installDevMock } = await import("./lib/devMock");
  installDevMock();
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    {/* Outside App, not inside: a boundary App renders cannot catch an error
        App itself throws. */}
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);
