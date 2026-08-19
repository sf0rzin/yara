import { useEffect, useState, type JSX } from "react";
import { errorMessage, type VaultProfile } from "../api";
import { Icon } from "../components/Icon";
import { YaraLogo } from "../components/YaraLogo";
import { isTopmostDialog, useModalDialog } from "../lib/useModalDialog";

interface VaultChooserProps {
  vaults: VaultProfile[];
  onSelect: (id: string) => Promise<void>;
  onRemove: (id: string, confirmation: string) => Promise<void>;
  onCreate: () => void;
}

interface RemoveVaultDialogProps {
  vault: VaultProfile;
  busy: boolean;
  error: string | null;
  confirmation: string;
  onConfirmationChange: (value: string) => void;
  onCancel: () => void;
  onConfirm: () => void;
}

function RemoveVaultDialog({
  vault,
  busy,
  error,
  confirmation,
  onConfirmationChange,
  onCancel,
  onConfirm,
}: RemoveVaultDialogProps): JSX.Element {
  const dialogRef = useModalDialog<HTMLDivElement>();

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (
        event.key === "Escape" &&
        !busy &&
        isTopmostDialog(dialogRef.current)
      ) {
        onCancel();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, dialogRef, onCancel]);

  return (
    <div className="overlay" role="presentation">
      <div
        className="dialog vault-remove"
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="vault-remove-title"
        aria-describedby="vault-remove-copy"
      >
        <header className="dialog__head">
          <h2 className="dialog__title" id="vault-remove-title">
            Remove “{vault.name}”?
          </h2>
        </header>
        <p className="vault-remove__copy" id="vault-remove-copy">
          This permanently deletes this Vault, its local backup copies, and
          its remembered master password. This cannot be undone. Type
          <strong> {vault.name}</strong> to confirm.
        </p>
        <label className="vault-remove__label">
          Vault name
          <input
            className="input vault-remove__input"
            value={confirmation}
            disabled={busy}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => onConfirmationChange(event.target.value)}
          />
        </label>
        {error && (
          <p className="notice notice--loud" role="alert">
            <Icon name="alert" size={13} />
            {error}
          </p>
        )}
        <footer className="dialog__foot">
          <button
            type="button"
            className="button button--primary"
            disabled={busy}
            autoFocus
            onClick={onCancel}
          >
            Cancel
          </button>
          <button
            type="button"
            className="button button--outline"
            disabled={busy || confirmation !== vault.name}
            onClick={onConfirm}
          >
            {busy ? "Removing…" : "Remove Vault"}
          </button>
        </footer>
      </div>
    </div>
  );
}

/** The signed-out home for a device that carries more than one local vault. */
export function VaultChooser({
  vaults,
  onSelect,
  onRemove,
  onCreate,
}: VaultChooserProps): JSX.Element {
  const [opening, setOpening] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const [candidate, setCandidate] = useState<VaultProfile | null>(null);
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const busy = opening !== null || removing !== null;

  async function open(id: string) {
    if (busy) return;
    setOpening(id);
    setError(null);
    try {
      await onSelect(id);
    } catch (caught) {
      setError(errorMessage(caught));
      setOpening(null);
    }
  }

  async function remove() {
    if (!candidate || busy) return;
    setRemoving(candidate.id);
    setRemoveError(null);
    try {
      await onRemove(candidate.id, confirmation);
      setCandidate(null);
      setConfirmation("");
    } catch (caught) {
      setRemoveError(errorMessage(caught));
    } finally {
      setRemoving(null);
    }
  }

  return (
    <main
      className="unlock-layer"
      role="dialog"
      aria-modal="true"
      aria-labelledby="vault-picker-title"
      aria-busy={busy || undefined}
    >
      <section className="vault-picker">
        <header className="vault-picker__header">
          <YaraLogo className="vault-picker__logo" decorative />
          <div>
            <h1 id="vault-picker-title">Choose a Vault</h1>
            <p>Your Vaults stay separate on this device.</p>
          </div>
        </header>

        <div className="vault-picker__list">
          {vaults.map((vault) => {
            const remembered =
              vault.rememberedUntil !== null &&
              vault.rememberedUntil * 1000 > Date.now();
            return (
              <div className="vault-picker__row" key={vault.id}>
                <button
                  type="button"
                  className="vault-picker__item"
                  disabled={busy}
                  onClick={() => void open(vault.id)}
                >
                  <span className="vault-picker__tile" aria-hidden="true">
                    <Icon name="lock" size={15} />
                  </span>
                  <span className="vault-picker__copy">
                    <strong>{vault.name}</strong>
                    <small>
                      {remembered
                        ? "Remembered on this device"
                        : "Master password required"}
                    </small>
                  </span>
                  <Icon name="chevronRight" size={14} />
                </button>
                <button
                  type="button"
                  className="vault-picker__remove"
                  aria-label={`Remove ${vault.name} Vault`}
                  title={`Remove ${vault.name}`}
                  disabled={busy}
                  onClick={() => {
                    setRemoveError(null);
                    setConfirmation("");
                    setCandidate(vault);
                  }}
                >
                  <Icon name="trash" size={14} />
                </button>
              </div>
            );
          })}
        </div>

        <button
          type="button"
          className="vault-picker__create"
          disabled={busy}
          onClick={onCreate}
        >
          <Icon name="plus" size={14} />
          Create another Vault
        </button>

        {error && (
          <p className="unlock-error" role="alert">
            {error}
          </p>
        )}
      </section>

      {candidate && (
        <RemoveVaultDialog
          vault={candidate}
          busy={removing === candidate.id}
          error={removeError}
          confirmation={confirmation}
          onConfirmationChange={setConfirmation}
          onCancel={() => {
            setCandidate(null);
            setConfirmation("");
          }}
          onConfirm={() => void remove()}
        />
      )}
    </main>
  );
}
