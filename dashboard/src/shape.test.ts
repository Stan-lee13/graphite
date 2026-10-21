// Round 30: a payload without the fields the views read is refused with the
// field named, before a view draws "NaN" or crashes. Run: npm test.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ShapeError,
  checkGraph,
  checkHealth,
  checkHistory,
  checkManifests,
  checkRegistry,
  checkTop,
  checkViolations,
} from "./shape.ts";

const node = {
  program_id: "11111111111111111111111111111111",
  name: "System Program",
  manifest_version: "1.0.0",
  trust_tier: "OfficialManifest",
  instruction_count: 13,
  baseline_samples: null,
  battle_tested_tx_count: 0,
  community_verified_count: 0,
  quarantined: false,
  quarantine_reason: null,
  cpi_targets: [],
};
const point = {
  timestamp: "2026-10-21T00:00:00Z",
  confidence: 0.74,
  approved: true,
  program_id: node.program_id,
  audit_trail_id: "a1",
  transaction_sha256: null,
  manifest_version: "1.0.0",
};

function refused(fn: () => void, mentions: RegExp) {
  assert.throws(fn, (e: unknown) => e instanceof ShapeError && mentions.test(e.message));
}

test("what a Core sends today passes", () => {
  checkGraph({ nodes: [node], edges: [{ from: "a", to: "b" }] });
  checkHistory({ series: [point, { ...point, decision: "analysis_only", executable: false }], count: 2 });
  checkViolations({
    violations: [{ ...point, protocol_name: "P", instruction_name: "i", policy_verdict: "Rejected", risk_status: "Clear" }],
    error_violations: [{ timestamp: point.timestamp, program_id: "", instruction_name: "", error: "bad", error_type: "BadRequest", status: 422 }],
    violation_count: 1,
    error_count: 1,
    count: 2,
  });
  checkTop({ program_count: 1, top: [{ program_id: node.program_id, observed_verifications: 0 }] });
  checkRegistry({ record_count: 0, records: [], reviewers: [] });
  checkManifests([{ protocol: { program_id: node.program_id }, instructions: [] }]);
  checkHealth({ status: "ok", service: "graphite-core", version: "0.3.0-beta", degraded: false, degraded_reasons: [] });
});

test("the shapes a broken Core or a proxy sends are refused, naming the field", () => {
  refused(() => checkGraph({ nodes: null }), /`nodes`/);
  refused(() => checkGraph({ nodes: [{ ...node, instruction_count: "13" }], edges: [] }), /instruction_count/);
  refused(() => checkHistory({ series: "nope" }), /`count`|`series`/);
  refused(() => checkHistory({ series: [], count: -1 }), /`count`/);
  refused(() => checkHistory({ series: [{ ...point, confidence: Number.NaN }], count: 1 }), /confidence/);
  refused(() => checkHistory({ series: [{ ...point, executable: "yes" }], count: 1 }), /executable/);
  refused(() => checkViolations({ violations: [{ timestamp: 3 }], count: "many" }), /`count`/);
  refused(() => checkTop({}), /`top`/);
  refused(() => checkRegistry("<html>proxy login</html>"), /not an object/);
  refused(() => checkManifests({ not: "a list" }), /not a list/);
  refused(() => checkHealth({ status: "ok" }), /`version`/);
});

test("fields the console does not read pass through", () => {
  checkHistory({ series: [{ ...point, some_future_field: { x: 1 } }], count: 1, cursor: "abc" });
});
