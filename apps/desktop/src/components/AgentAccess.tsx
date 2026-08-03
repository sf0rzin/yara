import { useCallback, useEffect, useState, type JSX } from "react";
import {
  auditEntries,
  listGrants,
  revokeGrant,
  type AuditEntry,
  type Grant,
} from "../api";
import { Icon } from "./Icon";

/** Refresh cadence, so grant countdowns stay honest. */
const POLL_MS = 5_000;

export function AgentAccess(): JSX.Element {
  const [grants, setGrants] = useState<Grant[]>([]);
  const [entries, setEntries] = useState<AuditEntry[]>([]);

  const refresh = useCallback(async () => {
    const [nextGrants, nextEntries] = await Promise.all([
      listGrants().catch(() => []),
      auditEntries(50).catch(() => []),
    ]);
    setGrants(nextGrants);
    setEntries(nextEntries);
  }, []);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  return (
    <div className="security">
      <section className="finding">
        <header className="finding__head">
          <h3 className="finding__title">Active permissions</h3>
          <span className="finding__count">{grants.length}</span>
        </header>
        <p className="finding__desc">
          {grants.length === 0
            ? "No program currently holds permission to use anything."
            : "Each of these expires on its own. Locking the vault cancels them all."}
        </p>

        {grants.length > 0 && (
          <div className="finding__group">
            {grants.map((grant) => (
              <div key={grant.id} className="grant">
                <span className="grant__text">
                  <span className="grant__title">
                    {grant.program} · {grant.item}
                  </span>
                  {/* The command, not just "can use": a grant authorises one
                      command and reading it back is the only way to tell what
                      was actually agreed to. */}
                  <span className="grant__sub">
                    Can {grant.permits} with the {grant.field} ·{" "}
                    {formatRemaining(grant.secondsRemaining)} left ·{" "}
                    {grant.remainingUses} use{grant.remainingUses === 1 ? "" : "s"}
                  </span>
                </span>
                <button
                  type="button"
                  className="button button--quiet"
                  onClick={() => void revokeGrant(grant.id).then(refresh)}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="finding">
        <header className="finding__head">
          <h3 className="finding__title">History</h3>
          <span className="finding__count">{entries.length}</span>
        </header>
        <p className="finding__desc">
          Every request, including the ones that were turned down.
        </p>

        {entries.length === 0 ? (
          <p className="empty">Nothing has asked for anything yet.</p>
        ) : (
          <div className="finding__group">
            {entries.map((entry) => (
              <div key={entry.id} className="audit" data-notable={entry.notable || undefined}>
                <Icon name={entry.allowed ? "check" : "close"} size={13} />
                <span className="audit__text">
                  <span className="audit__line">
                    {entry.program} {entry.summary} · {entry.item}
                  </span>
                  <span className="audit__sub">
                    {entry.allowed ? "Allowed" : "Refused"} · {formatWhen(entry.at)}
                  </span>
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <p className="security__note">
        yara can only vouch for what it was asked. A program that already runs
        as you can read this app's memory while the vault is unlocked, and no
        password manager running in your own session can prevent that.
      </p>
    </div>
  );
}

function formatRemaining(seconds: number): string {
  if (seconds >= 60) return `${Math.ceil(seconds / 60)} min`;
  return `${seconds}s`;
}

function formatWhen(unixSeconds: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`;
  return new Date(unixSeconds * 1000).toLocaleDateString();
}
