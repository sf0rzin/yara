import { useEffect, useState, type JSX } from "react";
import { vaultExists } from "./api";
import { TitleBar } from "./components/TitleBar";
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

  // The title bar is outside the switch: the frame is off, so without it a
  // vault stuck on the loading frame would be a window nobody can move or
  // close.
  return (
    <>
      <TitleBar />
      {content(screen, setScreen, showLoading)}
    </>
  );
}

function content(
  screen: Screen,
  setScreen: (screen: Screen) => void,
  showLoading: boolean,
): JSX.Element {
  switch (screen) {
    case "loading":
      return (
        <main className="gate">
          {showLoading && (
            <div className="gate__card gate__card--loading" role="status">
              <span className="gate__mark" aria-hidden="true" />
              <p className="gate__sub">Opening local vault…</p>
            </div>
          )}
        </main>
      );

    case "unlocked":
      return <Vault onLock={() => setScreen("locked")} />;

    default:
      return (
        <Unlock
          mode={screen === "setup" ? "setup" : "unlock"}
          onOpen={() => setScreen("unlocked")}
        />
      );
  }
}
