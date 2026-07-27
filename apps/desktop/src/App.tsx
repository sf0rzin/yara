import { useCallback, useEffect, useState } from "react";
import {
  addItem,
  createVault,
  deleteItem,
  errorMessage,
  ItemSummary,
  listItems,
  lockVault,
  revealPassword,
  totpCode,
  TotpCode,
  unlockVault,
  vaultExists,
} from "./api";
import "./App.css";

type Screen = "loading" | "setup" | "locked" | "unlocked";

export default function App() {
  const [screen, setScreen] = useState<Screen>("loading");

  useEffect(() => {
    vaultExists()
      .then((exists) => setScreen(exists ? "locked" : "setup"))
      .catch(() => setScreen("setup"));
  }, []);

  if (screen === "loading") {
    return <main className="shell" />;
  }

  if (screen === "unlocked") {
    return (
      <Vault
        onLock={() => {
          void lockVault();
          setScreen("locked");
        }}
      />
    );
  }

  return (
    <Gate
      mode={screen === "setup" ? "setup" : "unlock"}
      onOpen={() => setScreen("unlocked")}
    />
  );
}

function Gate({
  mode,
  onOpen,
}: {
  mode: "setup" | "unlock";
  onOpen: () => void;
}) {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isSetup = mode === "setup";

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);

    if (isSetup && password !== confirmation) {
      setError("the two passwords do not match");
      return;
    }
    if (isSetup && password.length < 12) {
      setError("use at least 12 characters — this is the one you cannot recover");
      return;
    }

    setBusy(true);
    try {
      await (isSetup ? createVault(password) : unlockVault(password));
      setPassword("");
      setConfirmation("");
      onOpen();
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="shell gate">
      <form className="card" onSubmit={submit}>
        <h1>lapse</h1>
        <p className="subtitle">
          {isSetup
            ? "Choose a master password. It is never stored and cannot be reset."
            : "Enter your master password."}
        </p>

        <input
          type="password"
          value={password}
          autoFocus
          placeholder="Master password"
          onChange={(e) => setPassword(e.target.value)}
        />

        {isSetup && (
          <input
            type="password"
            value={confirmation}
            placeholder="Confirm master password"
            onChange={(e) => setConfirmation(e.target.value)}
          />
        )}

        {error && <p className="error">{error}</p>}

        <button type="submit" disabled={busy || password.length === 0}>
          {busy ? "Working…" : isSetup ? "Create vault" : "Unlock"}
        </button>
      </form>
    </main>
  );
}

function Vault({ onLock }: { onLock: () => void }) {
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [query, setQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const refresh = useCallback(async (search: string) => {
    try {
      setItems(await listItems(search));
      setError(null);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }, []);

  useEffect(() => {
    void refresh(query);
  }, [query, refresh]);

  return (
    <main className="shell">
      <header className="topbar">
        <input
          className="search"
          value={query}
          placeholder="Search"
          onChange={(e) => setQuery(e.target.value)}
        />
        <button onClick={() => setAdding(true)}>Add</button>
        <button className="ghost" onClick={onLock}>
          Lock
        </button>
      </header>

      {error && <p className="error">{error}</p>}

      {adding && (
        <AddItem
          onCancel={() => setAdding(false)}
          onSaved={() => {
            setAdding(false);
            void refresh(query);
          }}
        />
      )}

      {items.length === 0 ? (
        <p className="empty">
          {query ? "Nothing matches that." : "No items yet."}
        </p>
      ) : (
        <ul className="items">
          {items.map((item) => (
            <ItemRow
              key={item.id}
              item={item}
              onDeleted={() => void refresh(query)}
            />
          ))}
        </ul>
      )}
    </main>
  );
}

function ItemRow({
  item,
  onDeleted,
}: {
  item: ItemSummary;
  onDeleted: () => void;
}) {
  const [revealed, setRevealed] = useState<string | null>(null);

  async function reveal() {
    if (revealed) {
      setRevealed(null);
      return;
    }
    try {
      setRevealed(await revealPassword(item.id));
    } catch {
      setRevealed(null);
    }
  }

  return (
    <li className="item">
      <div className="item-main">
        <span className="item-name">{item.name}</span>
        {item.username && <span className="item-sub">{item.username}</span>}
      </div>

      {item.hasTotp && <Totp id={item.id} />}

      <div className="item-actions">
        {item.hasPassword && (
          <button className="ghost" onClick={reveal}>
            {revealed ? "Hide" : "Reveal"}
          </button>
        )}
        <button
          className="ghost danger"
          onClick={() => deleteItem(item.id).then(onDeleted)}
        >
          Delete
        </button>
      </div>

      {revealed && <code className="revealed">{revealed}</code>}
    </li>
  );
}

function Totp({ id }: { id: string }) {
  const [code, setCode] = useState<TotpCode | null>(null);

  useEffect(() => {
    let active = true;

    const tick = () => {
      totpCode(id)
        .then((next) => {
          if (active) setCode(next);
        })
        .catch(() => {
          if (active) setCode(null);
        });
    };

    tick();
    const timer = setInterval(tick, 1000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [id]);

  if (!code) return null;

  return (
    <div className="totp" title={`${code.seconds_remaining}s remaining`}>
      <span className="totp-code">{code.code}</span>
      <span className="totp-countdown">{code.seconds_remaining}</span>
    </div>
  );
}

function AddItem({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpUri, setTotpUri] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      await addItem({
        name,
        username: username || null,
        password: password || null,
        totp_uri: totpUri || null,
      });
      onSaved();
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  return (
    <form className="card add" onSubmit={submit}>
      <input
        value={name}
        autoFocus
        placeholder="Name"
        onChange={(e) => setName(e.target.value)}
      />
      <input
        value={username}
        placeholder="Username"
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="password"
        value={password}
        placeholder="Password"
        onChange={(e) => setPassword(e.target.value)}
      />
      <input
        value={totpUri}
        placeholder="otpauth:// URI (optional)"
        onChange={(e) => setTotpUri(e.target.value)}
      />

      {error && <p className="error">{error}</p>}

      <div className="row">
        <button type="submit" disabled={!name}>
          Save
        </button>
        <button type="button" className="ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
