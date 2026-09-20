// Where the console gets its Core, and the key that unlocks it.
//
// A Graphite Core has exactly one key, chosen by whoever starts it. There is
// no sign-up and no key service: the operator generates a secret, starts the
// Core with it, and hands it to each tool that will call the Core — this
// console, the agent kit, the CLI. This screen is where the console receives
// its copy, and it proves the copy works before anything depends on it.

import { useState, type FormEvent } from "react";
import { Check, Eye, EyeOff, X } from "lucide-react";
import {
  MIN_KEY_CHARS,
  getConnection,
  normaliseBase,
  setConnection,
  testConnection,
  type ConnectionReport,
} from "../api";
import type { CoreState } from "../App";
import { PageHead, Section } from "../ui";

export function ConnectView({ core }: { core: CoreState }) {
  const current = getConnection();
  const [base, setBase] = useState(current.base);
  const [key, setKey] = useState(current.key);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [report, setReport] = useState<ConnectionReport | null>(null);
  const [saved, setSaved] = useState(false);

  const keyTooShort = key.trim().length > 0 && key.trim().length < MIN_KEY_CHARS;
  const dirty = normaliseBase(base) !== current.base || key.trim() !== current.key;

  const runTest = async () => {
    setTesting(true);
    setReport(null);
    try {
      setReport(await testConnection({ base, key }));
    } finally {
      setTesting(false);
    }
  };

  const save = (e: FormEvent) => {
    e.preventDefault();
    setConnection({ base, key });
    setSaved(true);
    setTimeout(() => setSaved(false), 1600);
  };

  return (
    <>
      <PageHead
        title="Connection"
        desc="Which Core this console reads from, and the key it presents. Both stay in this browser."
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
                onChange={(e) => setBase(e.target.value)}
              />
              <p className="field-help">
                The origin the Core listens on. Leave it empty to use the origin this console was served
                from, which is what the development proxy expects.
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
                  placeholder={core === "ok" && !current.key ? "Not needed: this Core runs in dev mode" : "Paste the operator key…"}
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
                    The value of <code translate="no">GRAPHITE_API_KEY</code> on the Core. Stored only in this
                    browser, sent only as a bearer header, never written to a URL.
                  </>
                )}
              </p>
            </div>

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
                    setKey("");
                    setConnection({ base, key: "" });
                  }}
                >
                  Forget key
                </button>
              )}
            </div>

            {report && <Report report={report} hasKey={key.trim().length > 0} />}
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
                <pre translate="no">{`GRAPHITE_API_KEY=<the secret>\nGRAPHITE_CORS_ORIGINS=https://console.example`}</pre>
              </li>
              <li>
                <strong>Every caller gets a copy.</strong> This console, the agent kit and the CLI all send
                the same key as <code translate="no">Authorization: Bearer</code>. Every route except{" "}
                <code translate="no">/health</code> requires it.
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
    <ul className="report" aria-live="polite">
      <li className={report.reachable ? "ok" : "bad"}>
        {report.reachable ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
        <span>
          {report.reachable ? (
            <>
              Core reached, version <span translate="no">{report.version}</span>
              {report.degraded ? ", reporting itself degraded" : ""}
            </>
          ) : (
            <>
              No answer from <code translate="no">/health</code>. Check the address; if the Core is up, add
              this console's origin to <code translate="no">GRAPHITE_CORS_ORIGINS</code>.
            </>
          )}
        </span>
      </li>
      {report.reachable && (
        <li className={report.authorized ? "ok" : "bad"}>
          {report.authorized ? <Check aria-hidden="true" /> : <X aria-hidden="true" />}
          <span>
            {report.authorized
              ? hasKey
                ? "Key accepted. Every console route answered with it."
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
