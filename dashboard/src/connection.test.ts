// Round 29 (audit 2026-10-20, D5/D6/D9): where the console keeps the key,
// and that storage failures never take the console down. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  BASE_STORAGE,
  KEY_STORAGE,
  createConnectionStore,
  storageGet,
  storageSet,
  type KeyValueStore,
} from "./connection.ts";

class Mem implements KeyValueStore {
  m = new Map<string, string>();
  getItem(k: string) {
    return this.m.get(k) ?? null;
  }
  setItem(k: string, v: string) {
    this.m.set(k, v);
  }
  removeItem(k: string) {
    this.m.delete(k);
  }
}

const KEY = "k".repeat(64);

test("by default the key lives in this session only, never on disk", () => {
  const local = new Mem();
  const session = new Mem();
  const store = createConnectionStore({ local: () => local, session: () => session, buildDefault: "" });
  assert.equal(store.get().remember, false);
  store.set({ base: "http://127.0.0.1:7331/", key: ` ${KEY} `, remember: false });
  assert.equal(session.getItem(KEY_STORAGE), KEY);
  assert.equal(local.getItem(KEY_STORAGE), null);
  // The address is not a secret; it is remembered either way.
  assert.equal(local.getItem(BASE_STORAGE), "http://127.0.0.1:7331");
});

test("remembering is an explicit choice, and un-choosing it wipes the disk copy", () => {
  const local = new Mem();
  const session = new Mem();
  const store = createConnectionStore({ local: () => local, session: () => session, buildDefault: "" });
  store.set({ base: "", key: KEY, remember: true });
  assert.equal(local.getItem(KEY_STORAGE), KEY);
  assert.equal(session.getItem(KEY_STORAGE), null);

  // A new page load picks the remembered key and the choice back up.
  const reloaded = createConnectionStore({ local: () => local, session: () => new Mem(), buildDefault: "" });
  assert.deepEqual(reloaded.get(), { base: "", key: KEY, remember: true });

  reloaded.set({ ...reloaded.get(), remember: false });
  assert.equal(local.getItem(KEY_STORAGE), null);
});

test("Forget key forgets the key and persists nothing else", () => {
  const local = new Mem();
  const session = new Mem();
  const store = createConnectionStore({ local: () => local, session: () => session, buildDefault: "" });
  store.set({ base: "https://core.example", key: KEY, remember: true });
  // The operator has typed a new address into the form but not saved it;
  // the store never sees it, and forgetting the key must not save it.
  store.forgetKey();
  assert.deepEqual(store.get(), { base: "https://core.example", key: "", remember: true });
  assert.equal(local.getItem(BASE_STORAGE), "https://core.example");
  assert.equal(local.getItem(KEY_STORAGE), null);
  assert.equal(session.getItem(KEY_STORAGE), null);
});

test("a storage that throws, or is missing, degrades to this page only", () => {
  const throwing: KeyValueStore = {
    getItem() {
      throw new Error("SecurityError");
    },
    setItem() {
      throw new Error("QuotaExceededError");
    },
    removeItem() {
      throw new Error("SecurityError");
    },
  };
  const getterThrows = () => {
    throw new Error("SecurityError: the property getter itself");
  };
  assert.equal(storageGet(() => throwing, "x"), null);
  assert.equal(storageGet(getterThrows, "x"), null);
  assert.doesNotThrow(() => storageSet(() => throwing, "x", "y"));
  assert.doesNotThrow(() => storageSet(getterThrows, "x", ""));
  assert.doesNotThrow(() => storageSet(() => undefined, "x", "y"));

  const store = createConnectionStore({ local: getterThrows, session: () => throwing, buildDefault: "https://built.example/api" });
  assert.deepEqual(store.get(), { base: "https://built.example", key: "", remember: false });
  store.set({ base: "https://core.example", key: KEY, remember: false });
  assert.equal(store.get().key, KEY, "the setting still holds for this page");
});
