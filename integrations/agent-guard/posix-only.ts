/**
 * Round 40 (assurance): the one way a guard test skips on Windows.
 *
 * A test that depends on POSIX file modes or owners (chmod, uids, mode bits
 * the guard compares) cannot hold on Windows, which has neither: there the
 * guard checks the kinds of its lock directory and state file, not their
 * owner or access (G2-6, R39-CLIENTS-6; `guard-round40.test.ts` holds what
 * Windows does check). Such a test passes `{ skip: posixOnly("why") }`, so
 * the reason is in the TAP output on Windows — never a bare `skip: true` —
 * and CI's Windows job allows exactly as many skips as there are uses of
 * this function (`.github/workflows/ci.yml`, agent-guard-windows). On every
 * other platform it is `false`: nothing skips, and the Linux job's zero-skip
 * rule still holds.
 */
export function posixOnly(why: string): string | false {
  return process.platform === "win32" ? `POSIX only: ${why}` : false;
}
