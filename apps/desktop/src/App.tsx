import { useCallback, useEffect, useState, type JSX } from "react";
import {
  chooseAnotherVault,
  listVaults,
  removeVault,
  selectVault,
  vaultStartup,
  type Startup,
  type VaultProfile,
} from "./api";
import { TitleBar } from "./components/TitleBar";
import { YaraLogo } from "./components/YaraLogo";
import { Recover } from "./screens/Recover";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { VaultChooser } from "./screens/VaultChooser";

type Screen = "loading" | Startup;

export default function App(): JSX.Element {
  const [screen, setScreen] = useState<Screen>("loading");
  const [showLoading, setShowLoading] = useState(false);
  const [vaults, setVaults] = useState<VaultProfile[]>([]);

  const loadState = useCallback(async () => {
    setScreen("loading");
    const next = await vaultStartup();
    const profiles = await listVaults();
    setVaults(profiles);
    setScreen(next);
  }, []);

  // Three answers, not two. This used to ask `vaultExists`, and a vault file
  // missing because a save was interrupted is not the same thing as a machine
  // that has never had one — telling them apart is the difference between
  // offering to recover the last copy and offering to overwrite it.
  useEffect(() => {
    void loadState()
      // Nothing but the IPC itself can fail here: the command reads three paths
      // and always answers with one of the three. So this is the case where
      // there is no backend at all, and setup is the state that at least shows
      // something. It is no longer the dangerous guess it was — creating a
      // vault where a copy is waiting is refused on the Rust side now.
      .catch(() => setScreen("setup"));
  }, [loadState]);

  useEffect(() => {
    if (screen !== "loading") {
      setShowLoading(false);
      return;
    }
    const timer = setTimeout(() => setShowLoading(true), 120);
    return () => clearTimeout(timer);
  }, [screen]);

  const selected = vaults.find((vault) => vault.selected) ?? null;

  async function showPicker() {
    await chooseAnotherVault();
    setVaults(await listVaults());
    setScreen("select");
  }

  function authenticated() {
    setScreen("unlocked");
    void listVaults().then(setVaults);
  }

  async function removeProfile(id: string, confirmation: string) {
    try {
      await removeVault(id, confirmation);
    } finally {
      // The backend may have committed the registry before a final filesystem
      // cleanup reported an error. Always refresh so the picker reflects what
      // is actually registered rather than showing a ghost Vault.
      const profiles = await listVaults();
      setVaults(profiles);
      setScreen(profiles.length === 0 ? "setup" : "select");
    }
  }

  return (
    <>
      <TitleBar />
      <div className="yara-stage" data-screen={screen}>
        {screen === "unlocked" && (
          <Vault
            vaultName={selected?.name ?? "Personal"}
            onLock={() => setScreen("locked")}
            onLogout={() => {
              setScreen("select");
              void listVaults().then(setVaults);
            }}
            onCreateVault={() => setScreen("setup")}
          />
        )}

        {(screen === "locked" || screen === "setup") && (
          <Unlock
            key={`${screen}-${selected?.id ?? "new"}`}
            mode={screen === "setup" ? "setup" : "unlock"}
            vaultName={selected?.name}
            hasOtherVaults={vaults.length > 0}
            onAuthenticated={authenticated}
            onUseAnother={vaults.length > 0 ? () => void showPicker() : undefined}
          />
        )}

        {screen === "select" && (
          <VaultChooser
            vaults={vaults}
            onSelect={async (id) => {
              await selectVault(id);
              await loadState();
            }}
            onRemove={removeProfile}
            onCreate={() => setScreen("setup")}
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
