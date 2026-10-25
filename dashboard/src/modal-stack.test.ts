// Round 39 (R39-DASH-2): only the modal surface opened last answers a key.
// Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createModalStack } from "./modal-stack.ts";

test("R39-DASH-2: the palette over a detail pane owns Escape and Tab; the pane gets them back when it closes", () => {
  const modals = createModalStack();
  const pane = Symbol("detail");
  const palette = Symbol("palette");
  const closePane = modals.open(pane);
  assert.equal(modals.isTop(pane), true);
  const closePalette = modals.open(palette);
  assert.equal(modals.isTop(palette), true);
  assert.equal(modals.isTop(pane), false, "a key in the palette must not also close the pane");
  closePalette();
  assert.equal(modals.isTop(pane), true);
  closePane();
  assert.equal(modals.isTop(pane), false);
});

test("closing a surface that is not on top leaves the top one in charge", () => {
  const modals = createModalStack();
  const a = Symbol("a");
  const b = Symbol("b");
  const closeA = modals.open(a);
  modals.open(b);
  closeA();
  assert.equal(modals.isTop(b), true);
  closeA(); // twice is harmless
  assert.equal(modals.isTop(b), true);
});
