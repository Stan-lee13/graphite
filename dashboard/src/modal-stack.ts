// Which modal surface owns the keyboard. No imports, so it runs under Node
// for its tests (modal-stack.test.ts).
//
// Round 39 (R39-DASH-2): every modal surface (the detail pane, the phone's
// More sheet, the command palette) put its own keydown listener on window.
// With the palette opened over a detail pane (Ctrl+K works anywhere), one
// Escape ran both listeners and closed both, and Tab ran both focus traps —
// the pane's pulled focus out of the palette before the palette's pulled it
// back. Only the surface opened last handles a key now.

export interface ModalStack {
  /** Register a surface as opened; returns the function that closes it. */
  open(id: symbol): () => void;
  /** Whether `id` is the surface opened last and still open. */
  isTop(id: symbol): boolean;
}

export function createModalStack(): ModalStack {
  const stack: symbol[] = [];
  return {
    open(id) {
      stack.push(id);
      return () => {
        const i = stack.lastIndexOf(id);
        if (i >= 0) stack.splice(i, 1);
      };
    },
    isTop: (id) => stack.length > 0 && stack[stack.length - 1] === id,
  };
}
