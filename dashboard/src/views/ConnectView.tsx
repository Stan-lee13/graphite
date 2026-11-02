// Where the console gets its Core, and the key that unlocks it.
//
// A Graphite Core's keys are chosen by whoever starts it. There is no sign-up
// and no key service: the operator generates secrets, starts the Core with
// them, and hands each tool the key it needs. The console's is the read-only
// key (GRAPHITE_READ_API_KEY, Round 30, K-11; Audit A061): it opens the
// console's routes and nothing that writes. This screen is where the console
// receives it, and it proves the key works before anything depends on it.

import { useRef, useState, type FormEvent } from "react";
import { Check, Eye, EyeOff, X } from "lucide-react";
import {
  MIN_KEY_CHARS,
  baseProblem,
  forgetKey,
  getConnection,
  normaliseBase,
  setConnection,
  testConnection,
  type ConnectionReport,
} from "../api";
import { reachProblem } from "../status";
import { PageHead, Section } from "../ui";

/** `keyNotNeeded`: a key-guarded route answered this browser with no key. */
export function ConnectView({ keyNotNeeded }: { keyNotNeeded: boolean }) {
  const current = getConnection();
  const [base, setBase] = useState(current.base);
  const [key, setKey] = useState(current.key);
  const [remember, setRemember] = useState(current.remember);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [report, setReport] = useState<(ConnectionReport & { tested: { base: string; key: string } }) | null>(null);
  const [saved, setSaved] = useState(false);
  // Round 39 (R39-DASH-7): why the last "Save and use" was refused, for the
  // address it was refused for.
  const [refused, setRefused] = useState<{ base: string; why: string } | null>(null);

  const keyTooShort = key.trim().length > 0 && key.trim().length < MIN_KEY_CHARS;
  const dirty =
    normaliseBase(base) !== current.base || key.trim() !== current.key || remember !== current.remember;

  // Round 36: a report is about the address and key it tested. It stayed on
  // screen after either field was edited — "Core reached, key accepted"
  // beside an address nobody had tested — and a slow test that an edit had
  // overtaken landed later under the new address. A report is now shown
  // only while the fields still hold what it tested, and only the latest
  // test may report at all.
  const run = useRef(0);
  const runTest = async () => {
    const id = ++run.current;
    const tested = { base: normaliseBase(base), key: key.trim() };
    setTesting(true);
    setReport(null);
    try {
      const r = await testConnection({ base, key, remember });
      if (run.current === id) setReport({ ...r, tested });
    } finally {
      if (run.current === id) setTesting(false);
    }
  };
  const shownReport =
    report && report.tested.base === normaliseBase(base) && report.tested.key === key.trim() ? report : null;

  const save = (e: FormEvent) => {
    e.preventDefault();
    // Round 39 (R39-DASH-7): an address the console will never send to is
    // not saved. It went to localStorage as typed — a key pasted one field
    // too high was kept on disk, whatever "Remember" said, and drawn in the
    // sidebar and in every view's fault text.
    const why = baseProblem(base);
    if (why !== null) {
      setRefused({ base, why });
      return;
    }
    setRefused(null);
    setConnection({ base, key, remember });
    setSaved(true);
    setTimeout(() => setSaved(false), 1600);
  };

  return (
    <>
      <PageHead
        title="Connection"
        desc="Which Core this console reads from, and the key it presents. Both stay in this browser; the key, for this tab only unless you choose otherwise."
      />

      <div className="connect">
        <form className="connect-form" onSubmit={save} noValidate>
          <Section title="Core">
            <div className="field">
              <label htmlFor="core-base">Address</label>
              <input
                id="core-base"
                name="core"
                type="url"
                inputMode="url"
                value={base}
                placeholder="http://127.0.0.1:7331"
                autoComplete="off"
                spellCheck={false}
                aria-invalid={refused?.base === base || undefined}
                aria-describedby="core-base-help"
                onChange={(e) => setBase(e.target.value)}
              />
              <p className="field-help" id="core-base-help">
                {refused?.base === base ? (
                  <span className="field-error" role="alert">
                    Not saved. {refused.why}
                  </span>
                ) : (
                  <>
                    The origin the Core listens on. Leave it empty to use the origin this console was served
                    from, which is what the development proxy expects.
                  </>
                )}
              </p>
            </div>

            <div className="field">
              <label htmlFor="core-key">API key</label>
              <div className="field-row">
                <input
                  id="core-key"
                  name="graphite-api-key"
                  type={show ? "text" : "password"}
                  value={key}
                  placeholder={keyNotNeeded ? "Not needed: this Core answered without a key" : "Paste the operator key…"}
                  autoComplete="off"
                  spellCheck={false}
                  aria-invalid={keyTooShort || undefined}
                  aria-describedby="core-key-help"
                  onChange={(e) => setKey(e.target.value)}
                />
                <button
                  type="button"
                  className="icon-btn"
                  aria-label={show ? "Hide key" : "Show key"}
                  aria-pressed={show}
                  onClick={() => setShow((s) => !s)}
                >
                  {show ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                </button>
              </div>
              <p className="field-help" id="core-key-help">
                {keyTooShort ? (
                  <span className="field-error">
                    A Core refuses to start with a key under {MIN_KEY_CHARS} characters, so this one cannot be the
                    Core's key.
                  </span>
                ) : (
                  <>
                    The value of <code translate="no">GRAPHITE_READ_API_KEY</code> on the Core: the read-only
                    key, which opens only what this console reads. Sent only as a bearer header, never written
                    to a URL.
                  </>
                )}
              </p>
            </div>

            {/* Round 29 (audit 2026-10-20, D6): session-only by default; the
                disk copy is an explicit choice, and un-ticking it removes it. */}
            <label className="field-check">
              <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
              <span>
                Remember the key on this device
                <span className="field-help">
                  {remember
                    ? "Kept in this browser's localStorage until you forget it. Anyone who can use this browser profile, and any script that runs on this origin, can read it."
                    : "Kept for this browser session only (sessionStorage). A browser may restore it with a reopened tab or a restored session, so on a shared machine use Forget key before you leave."}
                </span>
              </span>
            </label>

            <div className="btn-row">
              <button type="button" className="btn" onClick={runTest} disabled={testing}>
                {testing ? "Testing…" : "Test connection"}
              </button>
              <button type="submit" className="btn primary" disabled={!dirty && !saved}>
                {saved ? "Saved" : "Save and use"}
              </button>
              {current.key && (
                <button
                  type="button"
                  className="btn quiet"
                  onClick={() => {
                    // Round 29 (D9): forget the key only. This used to save
                    // the address field too, unsaved edit and all.
                    setKey("");
                    forgetKey();
                  }}
                >
                  Forget key
                </button>
              )}
            </div>

            {/* Round 39: one live region that is always in the page. The
                report used to mount with its own aria-live, and a region
                that arrives with its content is often not announced. */}
            <div aria-live="polite" className="report-live">
              {testing ? (
                <p className="field-help">Testing…</p>
              ) : (
                shownReport && <Report report={shownReport} hasKey={key.trim().length > 0} />
              )}
            </div>
          </Section>
        </form>

        <aside className="connect-aside">
          <Section title="Where the key comes from">
            <ol className="steps">
              <li>
                <strong>The operator makes it.</strong> Whoever starts the Core generates one secret of at
                least {MIN_KEY_CHARS} characters:
                <pre translate="no">openssl rand -hex 32</pre>
              </li>
              <li>
                <strong>The Core starts with it.</strong> The Core refuses to start without a key unless it
                is told, by name, to run keyless on loopback:
                <pre translate="no">{`GRAPHITE_API_KEY=<the verify secret>\nGRAPHITE_READ_API_KEY=<a second secret>\nGRAPHITE_CORS_ORIGINS=https://console.example`}</pre>
              </li>
              <li>
                <strong>Each caller gets the key it needs.</strong> This console and Prometheus get the
                read key: it opens <code translate="no">/metrics</code>, <code translate="no">/manifests</code>{" "}
                and <code translate="no">/api/*</code>, and nothing that writes. The agent kit and the CLI get
                the verify key, which also submits verifications and records lifecycle events on the audit
                trail. Give this console the verify key only for a Core started without a read key. Both are
                sent as <code translate="no">Authorization: Bearer</code>; every route except{" "}
                <code translate="no">/health</code> requires one.
              </li>
            </ol>
          </Section>
          <Section title="For development">
            <p className="prose">
              A Core started with <code translate="no">GRAPHITE_DEV_MODE=1</code> on{" "}
              <code translate="no">127.0.0.1</code> has no key. Leave the field empty. The Core will not run
              keyless on any other address.
            </p>
            <p className="prose">
              Browsers reach a Core only from the origins listed in{" "}
              <code translate="no">GRAPHITE_CORS_ORIGINS</code>. If the connection test says the Core did not
              answer but you can open <code translate="no">/health</code> in a new tab, that list is the
              reason.
            </p>
          </Section>
        </aside>
      </div>
    </>
  );
}

function Report({ report, hasKey }: { report: ConnectionReport; hasKey: boolean }) {
  return (
    <ul className="report">
      <li className={report.reachable ? "ok" : "bad"}>
        {report.reachable ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
        <span>
          {report.reachable ? (
            <>
              Core reached, version <span translate="no">{report.version}</span>
              {report.degraded ? ", reporting itself degraded" : ""}
            </>
          ) : (
            // Round 19 (F-19-C6): refused before sending, not unreachable.
            // Round 30: something answered, but it was not a Core. Round 39
            // (R39-DASH-6): a 500 or 429 is an answer too; only no answer at
            // all gets the CORS advice (status.ts reachProblem).
            <>{reachProblem(report.reachError?.kind, report.reachError?.message).text}</>
          )}
        </span>
      </li>
      {report.reachable && (
        <li className={report.authorized ? "ok" : "bad"}>
          {report.authorized ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
          <span>
            {report.authorized
              ? hasKey
                ? "Key accepted: a key-guarded route (/api/protocols/top) answered with it."
                : "No key needed. This Core runs in dev mode."
              : report.authError?.kind === "unauthorized"
                ? hasKey
                  ? "Key rejected. It is not the key this Core was started with."
                  : "This Core requires a key, and none was given."
                : (report.authError?.message ?? "The key could not be checked.")}
          </span>
        </li>
      )}
    </ul>
  );
}
