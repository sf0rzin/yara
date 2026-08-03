import { useEffect, useState, type JSX } from "react";
import { checkForUpdate, type AvailableUpdate } from "../lib/updates";
import { Icon } from "./Icon";

/**
 * Offers an update, once one is known to exist.
 *
 * Renders nothing until then, which is almost always. An update is not urgent
 * and this is not a modal: it sits in the flow, it can be dismissed, and it
 * never interrupts what the user came here to do.
 *
 * Installing restarts the app and therefore locks the vault. That is said in
 * the button's own copy rather than discovered afterwards — with no colour
 * available to mark consequence, the wording has to carry it.
 */
export function UpdateNotice(): JSX.Element | null {
  const [update, setUpdate] = useState<AvailableUpdate | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let live = true;
    void checkForUpdate().then((found) => {
      if (live) setUpdate(found);
    });
    return () => {
      live = false;
    };
  }, []);

  if (!update || dismissed) return null;

  const install = async () => {
    setInstalling(true);
    setFailed(false);
    try {
      await update.install();
      // Not reached: a successful install relaunches the process.
    } catch {
      // Here the user pressed a button, so silence would be a lie.
      setFailed(true);
      setInstalling(false);
    }
  };

  return (
    <div className="update" role="status">
      <Icon name="download" size={14} />

      <div className="update__text">
        <p className="update__title">Version {update.version} is available</p>
        {failed ? (
          <p className="update__notes">
            That did not install. Check your connection and try again.
          </p>
        ) : (
          update.notes && <p className="update__notes">{update.notes}</p>
        )}
      </div>

      <button
        type="button"
        className="button button--quiet"
        onClick={() => setDismissed(true)}
        disabled={installing}
      >
        Later
      </button>

      {/* Not button--primary: "New item" already holds this screen's single
          inverted slot, and a transient strip does not get to take it. */}
      <button
        type="button"
        className="button button--outline"
        onClick={() => void install()}
        disabled={installing}
      >
        {installing ? "Installing…" : "Install and restart"}
      </button>
    </div>
  );
}
