import { useEffect, useState, type JSX } from "react";
import { vaultStartup } from "./api";
import { TitleBar } from "./components/TitleBar";
import { YaraLogo } from "./components/YaraLogo";
import { Recover } from "./screens/Recover";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";

type Screen = "loading" | "setup" | "locked" | "recover" | "unlocked";

export default function App(): JSX.Element {
  const [screen, setScreen] = useState<Screen>("loading");
  const [showLoading, setShowLoading] = useState(false);

  // Three answers, not two. This used to ask `vaultExists`, and a vault file
  // missing because a save was interrupted is not the same thing as a machine
  // that has never had one — telling them apart is the difference between
  // offering to recover the last copy and offering to overwrite it.
  useEffect(() => {
    vaultStartup()
      .then(setScreen)
      // Nothing but the IPC itself can fail here: the command reads three paths
      // and always answers with one of the three. So this is the case where
      // there is no backend at all, and setup is the state that at least shows
      // something. It is no longer the dangerous guess it was — creating a
      // vault where a copy is waiting is refused on the Rust side now.
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

        {/* The vault is a file again, so what follows is an ordinary unlock. */}
        {screen === "recover" && (
          <Recover onRecovered={() => setScreen("locked")} />
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
