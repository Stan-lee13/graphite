// Where the Core lives and which key unlocks it, and where the browser keeps
// them. No imports and no Vite env, so it runs under Node for its tests
// (connection.test.ts, `tsx --test`); api.ts binds it to the real storages.
//
// Round 29 (audit 2026-10-20, D6): the key used to live in localStorage
// unconditionally — on disk, for every later visitor to this browser profile
// and for any script that ever runs on this origin. It now lives in
// sessionStorage (this tab, gone when the tab closes) unless the operator
// ticks "Remember on this device", which is the only path to localStorage.
// The Core address is not a secret and stays in localStorage.
//
// Round 29 (D5): every storage access is wrapped. A blocked or absent storage
// (private mode, sandboxed iframe, a SecurityError thrown by the property
// getter itself) degrades to "this page only", never to a blank console.

/** The parts of `Storage` the console uses; injectable for tests. */
export interface KeyValueStore {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

/** A getter, because merely reading `window.localStorage` can throw. */
export type StoreRef = () => KeyValueStore | undefined | null;

export interface Connection {
  /** Origin of the Core, e.g. `http://127.0.0.1:7331`. Empty means same
   *  origin (the dev proxy, or a Core serving the built console itself). */
  base: string;
  /** The operator key (`GRAPHITE_API_KEY`). Empty for a dev-mode Core. */
  key: string;
  /** Keep the key across browser restarts (localStorage) rather than for
   *  this tab only (sessionStorage). Off unless the operator chooses it. */
  remember: boolean;
}

export const BASE_STORAGE = "graphite.core";
export const KEY_STORAGE = "graphite.key";

export function storageGet(store: StoreRef, k: string): string | null {
  try {
    return store()?.getItem(k) ?? null;
  } catch {
    return null;
  }
}

/** Write `v`, or remove the entry when `v` is empty. Never throws. */
export function storageSet(store: StoreRef, k: string, v: string): void {
  try {
    const s = store();
    if (!s) return;
    if (v) s.setItem(k, v);
    else s.removeItem(k);
  } catch {
    /* private mode or blocked storage: the setting lives for this page only */
  }
}

/** Trim, drop a trailing slash and a trailing `/api` so either form works. */
export function normaliseBase(raw: string): string {
  let b = raw.trim().replace(/\/+$/, "");
  if (b.endsWith("/api")) b = b.slice(0, -4);
  return b;
}

export interface ConnectionStore {
  get(): Connection;
  set(next: Connection): void;
  /**
   * Drop the key and nothing else. Round 29 (D9): "Forget key" used to save
   * whatever was in the address field at the time, so an unsaved, half-typed
   * edit to the address was persisted by a button that said it only forgot
   * the key.
   */
  forgetKey(): void;
  onChange(l: () => void): () => void;
}

export function createConnectionStore(opts: {
  local: StoreRef;
  session: StoreRef;
  buildDefault: string;
}): ConnectionStore {
  const { local, session } = opts;
  const sessionKey = storageGet(session, KEY_STORAGE);
  const localKey = storageGet(local, KEY_STORAGE);
  // A key already in localStorage was put there by an earlier console, which
  // always remembered: keep honouring that until the operator says otherwise.
  let connection: Connection = {
    base: normaliseBase(storageGet(local, BASE_STORAGE) ?? opts.buildDefault),
    key: sessionKey ?? localKey ?? "",
    remember: sessionKey === null && localKey !== null,
  };
  const listeners = new Set<() => void>();

  const persist = () => {
    storageSet(local, BASE_STORAGE, connection.base);
    if (connection.remember) {
      storageSet(local, KEY_STORAGE, connection.key);
      storageSet(session, KEY_STORAGE, "");
    } else {
      storageSet(session, KEY_STORAGE, connection.key);
      // Choosing "this session only" must also take the key off the disk.
      storageSet(local, KEY_STORAGE, "");
    }
  };
  const publish = (next: Connection) => {
    connection = next;
    persist();
    for (const l of listeners) l();
  };

  return {
    get: () => connection,
    set: (next) => publish({ base: normaliseBase(next.base), key: next.key.trim(), remember: next.remember }),
    forgetKey: () => publish({ ...connection, key: "" }),
    onChange: (l) => {
      listeners.add(l);
      return () => listeners.delete(l);
    },
  };
}
