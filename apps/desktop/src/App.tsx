import { useEffect, useState, type JSX } from "react";
import { vaultExists } from "./api";
import { TitleBar } from "./components/TitleBar";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";

type Screen = "loading" | "setup" | "locked" | "unlocked";

export default function App(): JSX.Element {
  const [screen, setScreen] = useState<Screen>("loading");

  useEffect(() => {
    vaultExists()
      .then((exists) => setScreen(exists ? "locked" : "setup"))
      .catch(() => setScreen("setup"));
  }, []);

  // The title bar is outside the switch: the frame is off, so without it a
  // vault stuck on the loading frame would be a window nobody can move or
  // close.
  return (
    <>
      <TitleBar />
      {content(screen, setScreen)}
    </>
  );
}

function content(
  screen: Screen,
  setScreen: (screen: Screen) => void,
): JSX.Element {
  switch (screen) {
    case "loading":
      // Deliberately blank: the check is a filesystem stat, so a spinner would
      // flash for a frame and read as jank.
      return <main className="gate" />;

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
