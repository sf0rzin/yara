import { useCallback, useEffect, useState, type JSX } from "react";
import {
  changeMasterPassword,
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
import { StrengthMeter, useStrength } from "./StrengthMeter";
import {
  checkForUpdate,
  lastUpdateCheck,
  runningVersion,
  type CheckRecord,
} from "../lib/updates";

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

      {/*
        Sync first, and not because it is bigger. This screen exists because a
        vault has to follow you between machines; site icons is a preference
        about pictures. Putting the preference above it made the reason for
        the screen the second thing on it.
      */}
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

      <MasterPassword />
      <IconSetting />
      <UpdateSetting />
    </section>
  );
}

/**
 * Changing the master password.
 *
 * There was no way to do this at all — the command existed and nothing in the
 * interface could reach it, so the only answer to "someone watched me type it"
 * was to export and start again.
 *
 * The current password is asked for because the command demands it, and the
 * command demands it because it used to re-key on the word of whoever called
 * it. The interface says what the change is worth: a new wrapping of the same
 * key, which is the honest description and a smaller claim than people expect.
 */
function MasterPassword(): JSX.Element {
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const [changed, setChanged] = useState(false);
  const strength = useStrength(next);

  // Nothing typed here outlives the form. The fields hold the password to the
  // whole vault, and a cancelled attempt should not leave it in React state
  // for as long as the settings screen stays open.
  const close = () => {
    setOpen(false);
    setCurrent("");
    setNext("");
    setAgain("");
    setProblem(null);
  };

  const ready = current.length > 0 && next.length > 0 && again.length > 0;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    setProblem(null);

    // Twice, and compared here, because the backend only ever sees one of them.
    // Getting this wrong locks you out of your own vault with a password you
    // mistyped and never saw.
    if (next !== again) {
      setProblem("The two new passwords do not match.");
      return;
    }
    if (strength === "weak") {
      setProblem("Choose a longer master password.");
      return;
    }

    setBusy(true);
    try {
      await changeMasterPassword(current, next);
      setChanged(true);
      close();
    } catch (caught) {
      // Shown as the vault worded it. A wrong current password comes back as
      // "could not decrypt: wrong password or corrupted data", which is
      // deliberately both — rewriting it as "wrong password" would have the
      // interface tell you which, and it does not know.
      setProblem(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="master">
      <p className="section-label">Master password</p>

      <p className="sync__lead">
        Changing it re-wraps the 32-byte key this vault is encrypted under. Your
        items are not re-encrypted and what is stored for each of them does not
        change — this is a new lock on the same box, not a new box. Sync
        enrolment is left as it is, and a grant an agent is already holding
        keeps working until it expires or you revoke it.
      </p>

      {changed && (
        <p className="notice" role="status">
          <Icon name="check" size={13} />
          Master password changed. The old one no longer opens this vault.
        </p>
      )}

      {open ? (
        <form className="sync__form" onSubmit={(event) => void submit(event)}>
          <label className="input-label">
            Current master password
            <input
              className="input"
              type="password"
              value={current}
              autoComplete="current-password"
              onChange={(event) => setCurrent(event.target.value)}
            />
          </label>
          <p className="input-hint">
            Checked against the vault on disk before anything is written.
            Without it, anything running inside this window could re-key your
            vault while it sat unlocked in front of you.
          </p>

          <label className="input-label">
            New master password
            <input
              className="input"
              type="password"
              value={next}
              autoComplete="new-password"
              onChange={(event) => setNext(event.target.value)}
            />
          </label>
          <StrengthMeter strength={strength} />

          <label className="input-label">
            New master password again
            <input
              className="input"
              type="password"
              value={again}
              autoComplete="new-password"
              onChange={(event) => setAgain(event.target.value)}
            />
          </label>

          {problem && (
            <p className="notice notice--loud" role="alert">
              <Icon name="alert" size={13} />
              {problem}
            </p>
          )}

          <div className="sync__actions">
            <button
              type="submit"
              className="button button--primary"
              disabled={!ready || busy}
            >
              {busy ? "Changing…" : "Change master password"}
            </button>
            <button
              type="button"
              className="button button--quiet"
              disabled={busy}
              onClick={close}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="sync__actions">
          <button
            type="button"
            className="button button--outline"
            onClick={() => {
              setChanged(false);
              setOpen(true);
            }}
          >
            Change master password…
          </button>
        </div>
      )}
    </section>
  );
}

/**
 * What version this is, and what the last update check actually did.
 *
 * Here because this screen already accounts for what the app does over the
 * network, and because the alternative was a check whose only failure mode was
 * looking exactly like success. "Check now" is a button somebody pressed, so
 * unlike the one at launch it says what happened — that distinction is the
 * rule this file already follows for a failed install.
 */
function UpdateSetting(): JSX.Element {
  const [version, setVersion] = useState<string | null>(null);
  const [record, setRecord] = useState<CheckRecord | null>(lastUpdateCheck());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void runningVersion().then(setVersion);
  }, []);

  const recheck = async () => {
    setBusy(true);
    await checkForUpdate();
    setRecord(lastUpdateCheck());
    setBusy(false);
  };

  return (
    <section>
      <p className="section-label">Updates</p>
      <div className="group">
        <div className="detail__row">
          <span className="detail__label">This build</span>
          <span className="detail__value selectable">{version ?? "Unknown"}</span>
        </div>
        <div className="detail__row">
          <span className="detail__label">Last checked</span>
          <span className="detail__value">{describeCheck(record)}</span>
        </div>
      </div>

      <div className="sync__actions">
        <button
          type="button"
          className="button button--outline"
          disabled={busy}
          onClick={() => void recheck()}
        >
          {busy ? "Checking…" : "Check now"}
        </button>
      </div>
    </section>
  );
}

function describeCheck(record: CheckRecord | null): string {
  if (record === null) return "Not yet";

  const when = whenever(record.at);
  switch (record.result.state) {
    case "current":
      return `${when} — up to date`;
    case "available":
      return `${when} — ${record.result.update.version} is available`;
    case "unavailable":
      return `${when} — no updater in this build`;
    // The case this whole section exists for. Reads as a sentence rather than
    // a code, because the person reading it is the one who has to act on it.
    case "failed":
      return `${when} — the check failed: ${record.result.reason}`;
  }
}

function Enrol({
  busy,
  onEnrol,
}: {
  busy: boolean;
  onEnrol: (baseUrl: string, invite: string, password: string, label?: string) => void;
}): JSX.Element {
  const [baseUrl, setBaseUrl] = useState("https://yara.lat");
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

      <div className="group">
        <Fact label="Account" value={kit.accountId} />
      </div>

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
      {/*
        An inset group, which is what this app uses for a list of facts about
        one thing — see the detail pane. It used to borrow `approval__facts`
        from the agent dialog, so the same "label, value" idea had two
        different shapes depending on which screen you were on.
      */}
      <section>
        <p className="section-label">Sync</p>
        <div className="group">
          <Fact label="Server" value={status.baseUrl} />
          <Fact label="Account" value={status.accountId} />
          <Fact label="This machine" value={status.deviceId} />
          <Fact
            label="Last synced"
            value={status.lastSyncedAt ? whenever(status.lastSyncedAt) : "Never"}
          />
        </div>
      </section>

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

/** One row of an inset group. Absent values say so rather than showing blank. */
function Fact({ label, value }: { label: string; value: string | null }): JSX.Element {
  return (
    <div className="detail__row">
      <span className="detail__label">{label}</span>
      <span className="detail__value selectable">{value ?? "Not recorded"}</span>
    </div>
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
      <p className="section-label">Settings</p>
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
        Fetched through {"yara.lat"} rather than from each site, so no
        site learns you hold an account with it. That server sees which domains
        are asked about. Turning this off deletes what was cached.
      </p>
    </section>
  );
}
