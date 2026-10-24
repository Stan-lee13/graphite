// The state one poll keeps, as a pure reducer so it runs under Node for its
// tests (poll-state.test.ts). usePolling.ts drives it.
//
// Round 30: when the operator pointed the console at another Core (or
// changed the key), the poll restarted but kept the previous Core's payload
// and its "Updated 4s ago" until the new Core answered — and kept it
// indefinitely if the new Core never did, under the new Core's name in the
// sidebar. That is one Core's numbers presented as another's. A change of
// connection now clears the payload, the error and the timestamp: the view
// shows "loading" for the new Core, not stale data from the old one.
//
// A result is also tagged with the connection epoch it was fetched under,
// so a response from the old Core that lands after the switch is dropped
// rather than shown as the new Core's.

/**
 * How often `/manifests` is polled, wherever it is. It is every manifest in
 * full (about 4.6 MB for the shipped set) and changes only on a registry
 * update or a restart. Round 30 slowed the Programs view's poll to this;
 * Round 36: the Call graph view still fetched it every 30 s.
 */
export const MANIFESTS_POLL_MS = 300_000;

export interface PollState<T, E> {
  data: T | null;
  error: E | null;
  loading: boolean;
  updatedAt: number | null;
  /** The connection epoch `data`/`error` belong to. */
  epoch: number;
}

export type PollEvent<T, E> =
  | { type: "connection-changed"; epoch: number }
  | { type: "ok"; epoch: number; value: T; at: number }
  | { type: "fail"; epoch: number; error: E };

export function initialPoll<T, E>(epoch = 0): PollState<T, E> {
  return { data: null, error: null, loading: true, updatedAt: null, epoch };
}

export function pollReducer<T, E>(s: PollState<T, E>, ev: PollEvent<T, E>): PollState<T, E> {
  switch (ev.type) {
    case "connection-changed":
      return ev.epoch === s.epoch ? s : initialPoll<T, E>(ev.epoch);
    case "ok":
      // A result fetched under an earlier connection is not this Core's.
      if (ev.epoch !== s.epoch) return s;
      return { data: ev.value, error: null, loading: false, updatedAt: ev.at, epoch: s.epoch };
    case "fail":
      if (ev.epoch !== s.epoch) return s;
      // The last good payload stays on screen, under <Freshness>'s banner
      // (Round 29, D3) — but only if it is this Core's.
      return { ...s, error: ev.error, loading: false };
  }
}
