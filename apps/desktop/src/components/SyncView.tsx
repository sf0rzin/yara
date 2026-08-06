import { useCallback, useEffect, useState, type JSX } from "react";
import {
  errorMessage,
  iconsEnabled,
  setIconsEnabled,
  syncEnrol,
  syncForget,
  syncNow,
  syncStatus,
  type RecoveryKit,
  type SyncReport,
  type SyncStatus,
} from "../api";
import { Icon } from "./Icon";

/**
 * Enrolling a machine, and syncing it.
 *
 * The recovery kit is the load-bearing screen here. It appears once, it is not
 * stored, and losing it means losing the account — so it cannot be dismissed
 * by clicking away, and the button that dismisses it says what it is
 * confirming rather than "OK".
 */
export function SyncView(): JSX.Element {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [kit, setKit] = useState<RecoveryKit | null>(null);
  const [report, setReport] = useState<SyncReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      setStatus(await syncStatus());
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const run = async (work: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await work();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  };

  if (kit) {
    return <KitOnce kit={kit} onAcknowledged={() => void refresh().then(() => setKit(null))} />;
  }

  return (
    <section className="sync">
      {error && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {error}
        </p>
      )}

      <IconSetting />

      {status?.enrolled ? (
        <Enrolled
          status={status}
          report={report}
          busy={busy}
          onSync={() =>
            void run(async () => {
              setReport(await syncNow());
              await refresh();
            })
          }
          onForget={() =>
            void run(async () => {
              await syncForget();
              setReport(null);
              await refresh();
            })
          }
        />
      ) : (
        <Enrol
          busy={busy}
          onEnrol={(baseUrl, invite, password, label) =>
            void run(async () => {
              setKit(await syncEnrol(baseUrl, invite, password, label));
            })
          }
        />
      )}
    </section>
  );
}

function Enrol({
  busy,
  onEnrol,
}: {
  busy: boolean;
  onEnrol: (baseUrl: string, invite: string, password: string, label?: string) => void;
}): JSX.Element {
  const [baseUrl, setBaseUrl] = useState("https://yara.rindexx.cc");
  const [invite, setInvite] = useState("");
  const [password, setPassword] = useState("");
  const [label, setLabel] = useState("");

  const ready = baseUrl.trim() && invite.trim() && password.length > 0;

  return (
    <form
      className="sync__form"
      onSubmit={(event) => {
        event.preventDefault();
        if (ready && !busy) onEnrol(baseUrl.trim(), invite.trim(), password, label.trim() || undefined);
      }}
    >
      <p className="sync__lead">
        Sync keeps this vault on more than one machine. The server stores what
        it cannot read: your items are encrypted before they leave, and it
        never receives your password or anything derived from it.
      </p>

      <label className="input-label">
        Server
        <input
          className="input"
          value={baseUrl}
          onChange={(event) => setBaseUrl(event.target.value)}
          autoComplete="off"
          spellCheck={false}
        />
      </label>

      <label className="input-label">
        Invite code
        <input
          className="input"
          value={invite}
          onChange={(event) => setInvite(event.target.value)}
          placeholder="abcde-fghij-klmno"
          autoComplete="off"
          spellCheck={false}
        />
      </label>

      <label className="input-label">
        Master password
        <input
          className="input"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
        />
      </label>
      <p className="input-hint">
        Confirms it is you, and derives the key that wraps this vault for the
        server. It is not sent.
      </p>

      <label className="input-label">
        This machine
        <input
          className="input"
          value={label}
          onChange={(event) => setLabel(event.target.value)}
          placeholder="Optional — desktop, laptop"
          autoComplete="off"
        />
      </label>

      <button type="submit" className="button button--primary" disabled={!ready || busy}>
        {busy ? "Enrolling…" : "Enrol this machine"}
      </button>
    </form>
  );
}

/**
 * The recovery kit, once.
 *
 * No close button in the corner and no click-outside: the only way past this
 * is the acknowledgement, because everything else reads as "dismiss" and this
 * is not a thing to dismiss.
 */
function KitOnce({
  kit,
  onAcknowledged,
}: {
  kit: RecoveryKit;
  onAcknowledged: () => void;
}): JSX.Element {
  const [confirmed, setConfirmed] = useState(false);

  return (
    <section className="sync">
      <h2 className="sync__title">Write this down before you continue</h2>

      <p className="sync__lead">
        This is your recovery kit. It is the second half of what protects the
        account, together with your master password — and it is shown once. It
        is not stored on this machine and cannot be shown again.
      </p>

      <p className="kit">{kit.kit}</p>

      <dl className="approval__facts">
        <div>
          <dt>Account</dt>
          <dd className="selectable">{kit.accountId}</dd>
        </div>
      </dl>

      <p className="notice notice--loud">
        <Icon name="alert" size={13} />
        Without it, a new machine cannot join and a lost password cannot be
        recovered. Nobody can reissue it.
      </p>

      {/* A checkbox rather than a switch: this acknowledges something once, it
          does not hold a setting. */}
      <label className="sync__confirm">
        <input
          type="checkbox"
          className="checkbox"
          checked={confirmed}
          onChange={(event) => setConfirmed(event.target.checked)}
        />
        <span>I have written down the recovery kit and stored it somewhere safe.</span>
      </label>

      <button
        type="button"
        className="button button--primary"
        disabled={!confirmed}
        onClick={onAcknowledged}
      >
        Continue
      </button>
    </section>
  );
}

function Enrolled({
  status,
  report,
  busy,
  onSync,
  onForget,
}: {
  status: SyncStatus;
  report: SyncReport | null;
  busy: boolean;
  onSync: () => void;
  onForget: () => void;
}): JSX.Element {
  const [confirmingForget, setConfirmingForget] = useState(false);

  return (
    <>
      <dl className="approval__facts">
        <div>
          <dt>Server</dt>
          <dd className="selectable">{status.baseUrl}</dd>
        </div>
        <div>
          <dt>Account</dt>
          <dd className="selectable">{status.accountId}</dd>
        </div>
        <div>
          <dt>This machine</dt>
          <dd className="selectable">{status.deviceId}</dd>
        </div>
        <div>
          <dt>Last synced</dt>
          <dd>{status.lastSyncedAt ? whenever(status.lastSyncedAt) : "Never"}</dd>
        </div>
      </dl>

      {report && (
        <p className="notice">
          <Icon name="check" size={13} />
          {describe(report)}
        </p>
      )}

      <div className="sync__actions">
        <button type="button" className="button button--primary" disabled={busy} onClick={onSync}>
          {busy ? "Syncing…" : "Sync now"}
        </button>

        {/* Two clicks, because there is no colour to mark this and the
            wording has to carry the consequence on its own. */}
        {confirmingForget ? (
          <button type="button" className="button button--outline" disabled={busy} onClick={onForget}>
            Stop syncing and forget this device
          </button>
        ) : (
          <button
            type="button"
            className="button button--quiet"
            disabled={busy}
            onClick={() => setConfirmingForget(true)}
          >
            Stop syncing
          </button>
        )}
      </div>

      {confirmingForget && (
        <p className="notice">
          Your items stay on this machine. The server keeps its copy until this
          device is revoked there.
        </p>
      )}
    </>
  );
}

function describe(report: SyncReport): string {
  const parts: string[] = [];
  if (report.pulled) parts.push(`${report.pulled} in`);
  if (report.pushed) parts.push(`${report.pushed} out`);
  if (report.conflicts) {
    parts.push(
      `${report.conflicts} ${report.conflicts === 1 ? "conflict" : "conflicts"}, both copies kept`,
    );
  }

  return parts.length === 0 ? "Already up to date." : `Synced: ${parts.join(", ")}.`;
}

function whenever(at: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - at);
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} h ago`;
  return new Date(at * 1000).toLocaleDateString();
}

/**
 * Site icons, and the honest sentence about what fetching them costs.
 *
 * It lives on this screen because this is where the app already accounts for
 * what leaves the machine. A control about network fetching hidden anywhere
 * else would be a control nobody finds until after they wanted it.
 */
function IconSetting(): JSX.Element {
  const [on, setOn] = useState<boolean | null>(null);

  useEffect(() => {
    void iconsEnabled().then(setOn).catch(() => setOn(null));
  }, []);

  if (on === null) return <></>;

  return (
    <section>
      <div className="group">
        <label className="setting__row">
          <span className="setting__label">Site icons</span>
          <input
            type="checkbox"
            className="switch"
            checked={on}
            onChange={(event) => {
              setOn(event.target.checked);
              void setIconsEnabled(event.target.checked);
            }}
          />
        </label>
      </div>

      <p className="setting__caption">
        Fetched through {"yara.rindexx.cc"} rather than from each site, so no
        site learns you hold an account with it. That server sees which domains
        are asked about. Turning this off deletes what was cached.
      </p>
    </section>
  );
}
