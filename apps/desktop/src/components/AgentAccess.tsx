import { useCallback, useEffect, useState, type JSX } from "react";
import {
  auditEntries,
  errorMessage,
  listGrants,
  revokeGrant,
  type AuditEntry,
  type Grant,
} from "../api";
import { Icon } from "./Icon";

/** Refresh cadence, so grant countdowns stay honest. */
const POLL_MS = 5_000;

/**
 * What currently holds permission, and what has asked for it.
 *
 * This is the screen somebody opens because they suspect something is wrong, so
 * it is the last place that may answer an error with reassurance. Both lists
 * start as `null` — "not read yet", which is a different thing from "read, and
 * empty". They used to be caught to `[]`, which meant a failed IPC call
 * rendered "No program currently holds permission to use anything": a positive
 * security claim manufactured out of a failure.
 */
export function AgentAccess({ historyOnly = false }: { historyOnly?: boolean } = {}): JSX.Element {
  const [grants, setGrants] = useState<Grant[] | null>(null);
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [readError, setReadError] = useState<string | null>(null);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      // Only the list this screen is showing. Fetching both meant a failure in
      // the half that is not rendered had nowhere to be reported, and the poll
      // would have kept raising it every five seconds about nothing visible.
      if (historyOnly) setEntries(await auditEntries(50));
      else setGrants(await listGrants());
      setReadError(null);
    } catch (caught) {
      setReadError(errorMessage(caught));
    }
  }, [historyOnly]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  /**
   * Revokes a grant, and says so when it did not.
   *
   * The command answers with whether it removed anything, and that answer used
   * to be thrown away with no `.catch` behind it — so a revoke that never
   * happened was indistinguishable from one that did, on the one control here
   * whose whole purpose is to take permission away.
   */
  const revoke = async (grant: Grant) => {
    setRevokeError(null);
    try {
      const revoked = await revokeGrant(grant.id);
      // Refreshed first so the message lands next to the list it describes,
      // and so a successful read does not then clear the message.
      await refresh();
      if (!revoked) {
        setRevokeError(
          `Nothing was revoked. The broker no longer held that permission for ${grant.program} — most likely it expired first. What it does hold is below.`,
        );
      }
    } catch (caught) {
      setRevokeError(
        `That did not go through, so ${grant.program} may still hold this permission: ${errorMessage(caught)}`,
      );
    }
  };

  return (
    <div className="panel">
      {readError && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {readError}
        </p>
      )}

      {revokeError && (
        <p className="notice notice--loud">
          <Icon name="alert" size={13} />
          {revokeError}
        </p>
      )}

      {!historyOnly && <section className="panel__section">
        <header className="panel__head">
          <h3 className="panel__title">Active permissions</h3>
          {/* A dash rather than 0 while the count is unknown. A zero here reads
              as a finding, and an unread list has not found anything. */}
          <span className="panel__count">{grants === null ? "—" : grants.length}</span>
        </header>
        <p className="panel__desc">
          {grants === null
            ? readError === null
              ? "Reading what currently holds permission…"
              : "This could not be read. Treat what holds permission as unknown, not as none."
            : grants.length === 0
              ? "No program currently holds permission to use anything."
              : "Each of these expires on its own. Locking the vault cancels them all."}
        </p>

        {grants !== null && grants.length > 0 && (
          <div className="panel__group">
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
                  onClick={() => void revoke(grant)}
                >
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </section>}

      {historyOnly && <section className="panel__section">
        <header className="panel__head">
          <h3 className="panel__title">History</h3>
          <span className="panel__count">{entries === null ? "—" : entries.length}</span>
        </header>
        <p className="panel__desc">
          Every request, including the ones that were turned down.
        </p>

        {entries === null ? (
          <p className="empty">
            {readError === null
              ? "Reading the log…"
              : "The log could not be read. This is not a record of nothing having happened."}
          </p>
        ) : entries.length === 0 ? (
          <p className="empty">Nothing has asked for anything yet.</p>
        ) : (
          <div className="panel__group">
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
      </section>}
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
