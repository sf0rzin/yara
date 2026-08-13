import { useEffect, useState, type JSX } from "react";
import { vaultExists } from "./api";
import { TitleBar } from "./components/TitleBar";
import { YaraLogo } from "./components/YaraLogo";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";

type Screen = "loading" | "setup" | "locked" | "unlocked";

export default function App(): JSX.Element {
  const [screen, setScreen] = useState<Screen>("loading");
  const [showLoading, setShowLoading] = useState(false);

  useEffect(() => {
    vaultExists()
      .then((exists) => setScreen(exists ? "locked" : "setup"))
      .catch(() => setScreen("setup"));
  }, []);

  useEffect(() => {
    if (screen !== "loading") {
      setShowLoading(false);
      return;
    }
    const timer = setTimeout(() => setShowLoading(true), 120);
    return () => clearTimeout(timer);
  }, [screen]);

  return (
    <>
      <TitleBar />
      <div className="yara-stage" data-screen={screen}>
        {screen === "unlocked" && (
          <Vault onLock={() => setScreen("locked")} />
        )}

        {(screen === "locked" || screen === "setup") && (
          <Unlock
            mode={screen === "setup" ? "setup" : "unlock"}
            onAuthenticated={() => setScreen("unlocked")}
          />
        )}

        {screen === "loading" && (
          <main className="loading-gate">
            {showLoading && (
              <div
                className="loading-gate__brand"
                role="status"
                aria-label="Opening Yara"
              >
                <YaraLogo className="loading-gate__logo" decorative />
                <span>yara</span>
              </div>
            )}
          </main>
        )}
      </div>
    </>
  );
}
