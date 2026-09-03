# Flow designer canvas — implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An xyflow canvas tab beside the YAML tab of the Flows screen that edits a flow visually, round-trips through the daemon's normalizer, marks validation errors on the offending node, auto-lays out with ELK, and animates a running flow.

**Architecture:** The daemon gains one GUI-only op, `admin.flows.normalize`, that accepts YAML text or a raw flow JSON and answers with canonical YAML + resolved flow JSON + the first validation error (path, message). The frontend keeps one lifted `{ yaml, flow, error, dirty }` state per selected flow shared by the canvas and the textarea; a pure `graph.ts` module derives nodes/edges from the resolved flow and applies edits (connect with order repair, cycle refusal, add/remove/move/update steps). Positions live in localStorage; ELK fills the gaps and "Tidy" relays everything. Run animation parses the daemon's progress notes (`"<step>: running (i/n)"` and the new `"<step>: <status>"`).

**Tech Stack:** Rust (pam_flow, pam_daemon, pam_gui bridge), React 19 + TypeScript, `@xyflow/react` 12, `elkjs` (bundled build, literal dynamic import), Tailwind v4 tokens, CVA, vitest + testing-library, lucide-react.

Spec: `docs/specs/2026-09-02-flow-designer-design.md` (approved 2026-09-02).

## Global constraints

- Branch first, PR + squash merge, no AI attribution in commits or PRs. Never commit to `main`.
- Rust tests live in sibling `*_test.rs` files wired with `#[cfg(test)] mod x_test;` — never `mod tests` inside a source file.
- New npm deps: exactly `@xyflow/react` (^12) and `elkjs` (latest 0.x). No other dependency, Rust or npm.
- ESLint bans Tailwind arbitrary values (`w-[347px]`) in `className`, `cn()`, `cva()` strings — including strings passed to xyflow props. No inline `style` except the ones xyflow requires for node positions (xyflow sets those itself).
- All colors via `@theme` tokens; xyflow themed only through `--xy-*` variables bound with `var()`; no hardcoded hex.
- `--xy-*` bindings live in `frontend/src/styles/tokens.css`; `design.test.ts` must keep passing.
- Every `Flow` JSON field name is the Rust serde name (`read_only`, `needs_succeeded`, `duration` strings like `5m`, `500ms`).
- Step id rule `[a-z0-9-]{1,64}`; `needs` and `when` reference earlier steps only; steps execute in file order.
- Local gate before every PR: `tools/check.sh` (fmt, clippy -D warnings, cargo test, eslint, tsc + vite build, vitest).
- Copy voice: refusals as cause + fix; notes in the existing "pam speaks in first person" voice used by FlowEditor.

## File structure

Rust:
- Modify `crates/pam_flow/src/validate.rs` — add `parse_value(serde_json::Value)`; `crates/pam_flow/src/lib.rs` re-export; tests in `crates/pam_flow/src/validate_test.rs`.
- Modify `crates/pam_daemon/src/admin_flows.rs` — `OP_FLOWS_NORMALIZE`, handler, `FLOW_ADMIN_OPS`; tests in `crates/pam_daemon/src/admin_flows_test.rs` (whitelist count 7 → 8).
- Modify `crates/pam_gui/src/bridge_test.rs` only if it hardcodes the flow op count (it sums `FLOW_ADMIN_OPS.len()`, so likely untouched).
- Modify `crates/pam_daemon/src/flow_service.rs` — settle note after each step; test in `crates/pam_daemon/src/flow_service_test.rs`.

Frontend:
- Modify `frontend/package.json`, `frontend/package-lock.json` (two deps).
- Modify `frontend/vitest.setup.ts` — ResizeObserver + DOMMatrixReadOnly stubs xyflow needs in jsdom.
- Modify `frontend/src/lib/ipc.ts` — `FlowSpec` family, `RawFlow` family, `FlowNormalizeReply`, `flowsNormalize`, `AdminOp` union.
- Modify `frontend/src/styles/tokens.css` — `--xy-*` block; `frontend/src/styles/design.test.ts` — assertion.
- Create `frontend/src/screens/flow-canvas/graph.ts` + `graph.test.ts` — pure model.
- Create `frontend/src/screens/flow-canvas/notes.ts` + `notes.test.ts` — progress-note parser.
- Create `frontend/src/screens/flow-canvas/layout.ts` + `layout.test.ts` — positions store + ELK.
- Create `frontend/src/screens/flow-canvas/StepNode.tsx`, `FrameNode.tsx`, `FlowEdge.tsx`, `FlowCanvas.tsx`, `Inspector.tsx`, `FlowCanvas.test.tsx`, `Inspector.test.tsx`.
- Modify `frontend/src/screens/Flows.tsx` (tabs, lifted state, normalize debounce, run state), `FlowEditor.tsx` (controlled yaml, save gating), `FlowRunCard.tsx` (callbacks), `Flows.test.tsx`.

Docs: `docs/specs/2026-09-02-flow-designer-design.md` gets a "Landed deviations" section at the end if anything deviates.

---

### Task 1: `pam_flow::parse_value` — a flow from raw JSON

**Files:**
- Modify: `crates/pam_flow/src/validate.rs` (next to `parse`, line ~324)
- Modify: `crates/pam_flow/src/lib.rs` (re-export)
- Test: `crates/pam_flow/src/validate_test.rs`

**Interfaces:**
- Produces: `pub fn parse_value(raw: serde_json::Value) -> Result<Flow, FlowError>` — same rules and paths as `parse`; a serde error becomes `FlowError::Invalid { path, message }` through the same `from_*_error` shaping (`steps[1].when: …`), unknown keys refused (`RawFlow` is `deny_unknown_fields`).

- [ ] **Step 1: Write the failing tests** (append to `validate_test.rs`)

```rust
#[test]
fn parse_value_accepts_the_raw_json_shape() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [
            { "id": "status", "run": ["git", "status", "--short"], "role": "verify" },
            { "id": "log", "run": ["git", "log", "--oneline"], "needs": ["status"],
              "when": { "succeeded": "status" }, "timeout": "10m",
              "retry": { "attempts": 2, "backoff": "1s" } }
        ]
    });
    let flow = pam_flow::parse_value(raw).expect("parses");
    assert_eq!(flow.steps.len(), 2);
    assert_eq!(flow.steps[1].needs, vec!["status"]);
    assert_eq!(flow.steps[1].when, pam_flow::When::Succeeded("status".into()));
    assert_eq!(pam_flow::format_duration(flow.steps[1].timeout), "10m");
    assert_eq!(flow.steps[1].retry.attempts, 2);
}

#[test]
fn parse_value_reports_the_same_paths_as_parse() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [ { "id": "later", "run": ["git", "status"], "needs": ["missing"] } ]
    });
    let err = pam_flow::parse_value(raw).unwrap_err();
    let yaml_err = pam_flow::parse(
        "schema: 1\nid: demo\nname: Demo\nsteps:\n  - id: later\n    run: [git, status]\n    needs: [missing]\n",
    )
    .unwrap_err();
    assert_eq!(err.to_string(), yaml_err.to_string());
    assert!(err.to_string().starts_with("steps[0].needs[0]"), "{err}");
}

#[test]
fn parse_value_refuses_an_unknown_key_by_path() {
    let raw = serde_json::json!({
        "schema": 1, "id": "demo", "name": "Demo",
        "steps": [ { "id": "s", "run": ["git", "status"], "ui": { "x": 1 } } ]
    });
    let err = pam_flow::parse_value(raw).unwrap_err();
    match err {
        pam_flow::FlowError::Invalid { path, message } => {
            assert!(path.starts_with("steps[0]") || path == "yaml", "{path}: {message}");
            assert!(message.contains("unknown field `ui`"), "{message}");
        }
        other => panic!("{other:?}"),
    }
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `cargo test -p pam_flow parse_value`
Expected: compile error — `parse_value` not found.

- [ ] **Step 3: Implement**

In `validate.rs`, after `parse`:

```rust
/// [`parse`] for a flow already in memory as JSON in the file's own shape
/// (`run` / `connector` / `call` / `with`, …) — what the designer canvas
/// sends back. Same rules, same paths, no disk.
///
/// # Errors
///
/// As [`parse`]; a serde error keeps the path serde worked out.
pub fn parse_value(raw: serde_json::Value) -> Result<Flow, FlowError> {
    let raw: RawFlow = serde_json::from_value(raw).map_err(|error| from_json_error(&error))?;
    validate(raw)
}

/// Turns a serde_json error into an `Invalid` error. serde_json does not
/// track a path, so the message carries the field and the path is
/// `yaml` unless the message names a step-level field we can place.
fn from_json_error(error: &serde_json::Error) -> FlowError {
    FlowError::invalid("yaml", error.to_string())
}
```

If `serde_json` is not yet a dependency of `pam_flow`, it is (the spec lists it; confirm with `grep serde_json crates/pam_flow/Cargo.toml`). Note: serde_json errors carry no path; the unknown-key test above accepts `path == "yaml"`. To do better cheaply, route through YAML: `let text = serde_yaml_ng::to_string(&raw_value)?; parse(&text)` — this gives paths for free and reuses `from_yaml_error`. **Use the YAML route** (`serde_yaml_ng::to_string(&raw)` on the `Value`, then `parse`), because identical paths for both entry points is what the canvas markers rely on. Keep the size check: the rendered YAML goes through `parse`, which enforces `MAX_FILE_BYTES`.

Final implementation:

```rust
pub fn parse_value(raw: serde_json::Value) -> Result<Flow, FlowError> {
    let text = serde_yaml_ng::to_string(&raw)
        .map_err(|error| FlowError::invalid("yaml", error.to_string()))?;
    parse(&text)
}
```

Then tighten the unknown-key test to `assert_eq!(path, "steps[0]")` if that is what `from_yaml_error` yields (run and read the actual path; assert the literal you observe, it must start with `steps[0]`).

Re-export in `lib.rs`: add `parse_value` to the `pub use validate::{…}` list.

- [ ] **Step 4: Run tests**

Run: `cargo test -p pam_flow`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_flow
git commit -m "feat(flow): parse_value — a Flow from raw JSON, same paths as parse"
```

---

### Task 2: `admin.flows.normalize`

**Files:**
- Modify: `crates/pam_daemon/src/admin_flows.rs`
- Test: `crates/pam_daemon/src/admin_flows_test.rs`

**Interfaces:**
- Produces: `pub const OP_FLOWS_NORMALIZE: &str = "admin.flows.normalize"` in `FLOW_ADMIN_OPS` (length 8). Args: exactly one of `yaml: string` | `flow: object`. Reply body valid: `{ "valid": true, "yaml": String, "flow": Flow JSON, "digest": String }`; invalid: `{ "valid": false, "error": { "path": String, "message": String } }`. Outcome `Verified` in both cases. Refusal `CAUSE_INVALID_ADMIN_ARGS` when both or neither arg is present.

- [ ] **Step 1: Failing tests** (append to `admin_flows_test.rs`; update the whitelist test's `assert_eq!(FLOW_ADMIN_OPS.len(), 7)` to `8`)

```rust
#[tokio::test]
async fn normalize_renders_yaml_canonically_and_carries_the_parsed_flow() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let messy = "name: Local flow\nschema: 1\nid: local\nsteps:\n  - run: [git, status]\n    id: look\n    timeout: 5m\n";
    let body = body_of(
        admin
            .handle(&admin_envelope("req_n1", OP_FLOWS_NORMALIZE, json!({ "yaml": messy })))
            .await,
        Outcome::Verified,
    );
    assert_eq!(body["valid"], json!(true));
    let yaml = body["yaml"].as_str().unwrap();
    assert!(yaml.starts_with("schema: 1\nid: local\nname: Local flow\n"), "{yaml}");
    assert!(!yaml.contains("timeout"), "default timeout is omitted: {yaml}");
    assert_eq!(body["flow"]["steps"][0]["id"], json!("look"));
    assert_eq!(body["flow"]["steps"][0]["action"]["kind"], json!("command"));
    assert_eq!(body["digest"].as_str().unwrap().len(), 64);
}

#[tokio::test]
async fn normalize_accepts_the_raw_flow_json_and_yields_the_same_digest() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let raw = json!({ "schema": 1, "id": "local", "name": "Local flow",
        "steps": [{ "id": "look", "run": ["git", "status"] }] });
    let from_flow = body_of(
        admin.handle(&admin_envelope("req_n2", OP_FLOWS_NORMALIZE, json!({ "flow": raw }))).await,
        Outcome::Verified,
    );
    let from_yaml = body_of(
        admin.handle(&admin_envelope("req_n3", OP_FLOWS_NORMALIZE,
            json!({ "yaml": from_flow["yaml"] }))).await,
        Outcome::Verified,
    );
    assert_eq!(from_flow["digest"], from_yaml["digest"]);
    assert_eq!(from_flow["yaml"], from_yaml["yaml"]);
}

#[tokio::test]
async fn normalize_answers_invalid_flows_with_the_path_not_a_refusal() {
    let (_tmp, _store, admin, _ingress) = service().await;
    let raw = json!({ "schema": 1, "id": "local", "name": "Local flow",
        "steps": [{ "id": "look", "run": ["bash", "-c", "ls"] }] });
    let body = body_of(
        admin.handle(&admin_envelope("req_n4", OP_FLOWS_NORMALIZE, json!({ "flow": raw }))).await,
        Outcome::Verified,
    );
    assert_eq!(body["valid"], json!(false));
    assert_eq!(body["error"]["path"], json!("steps[0].run[0]"));
    assert!(body["error"]["message"].as_str().unwrap().contains("shell"));
    assert!(body.get("yaml").is_none());
}

#[tokio::test]
async fn normalize_needs_exactly_one_of_yaml_or_flow() {
    let (_tmp, _store, admin, _ingress) = service().await;
    for args in [json!({}), json!({ "yaml": "schema: 1\n", "flow": {} })] {
        let cause = cause_of(admin.handle(&admin_envelope("req_n5", OP_FLOWS_NORMALIZE, args)).await);
        assert_eq!(cause, CAUSE_INVALID_ADMIN_ARGS);
    }
}
```

Add `OP_FLOWS_NORMALIZE` to the `use crate::admin_flows::{…}` import and `use serde_json::json;` if not already imported.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p pam_daemon admin_flows_test`
Expected: compile error on `OP_FLOWS_NORMALIZE`.

- [ ] **Step 3: Implement**

In `admin_flows.rs`:

```rust
/// Canonical rendering + validation of a flow that lives only in the
/// GUI: the canvas sends its model here after every edit and shows the
/// YAML it gets back. Never touches disk; never a capability.
pub const OP_FLOWS_NORMALIZE: &str = "admin.flows.normalize";
```

Add it to `FLOW_ADMIN_OPS` (after `OP_FLOWS_SAVE`), to `dispatch_flows` (`OP_FLOWS_NORMALIZE => self.flows_normalize(args).map_err(OwnedRefusal::from)`), and:

```rust
/// Renders one flow canonically, or names the first rule it breaks.
fn flows_normalize(&self, args: &Value) -> Result<AdminOk, AdminRefusal> {
    let yaml = args.get("yaml").and_then(Value::as_str);
    let flow = args.get("flow").filter(|value| value.is_object());
    let parsed = match (yaml, flow) {
        (Some(text), None) => pam_flow::parse(text),
        (None, Some(raw)) => pam_flow::parse_value(raw.clone()),
        _ => {
            return Err(AdminRefusal {
                cause: CAUSE_INVALID_ADMIN_ARGS,
                detail: format!("{OP_FLOWS_NORMALIZE} takes exactly one of `yaml` (text) or `flow` (object)"),
                recovery: RECOVERY_FLOW_EDIT,
            });
        }
    };
    let bytes = yaml.map_or(0, str::len);
    let body = match parsed {
        Ok(flow) => json!({
            "valid": true,
            "yaml": pam_flow::to_normalized_yaml(&flow),
            "flow": flow,
            "digest": pam_flow::digest(&flow),
        }),
        Err(error) => {
            let (path, message) = match &error {
                FlowError::Invalid { path, message } => (path.clone(), message.clone()),
                other => ("yaml".to_owned(), other.to_string()),
            };
            json!({ "valid": false, "error": { "path": path, "message": message } })
        }
    };
    Ok(AdminOk {
        outcome: Outcome::Verified,
        body,
        audit: json!({ "op": OP_FLOWS_NORMALIZE, "valid": parsed_is_valid, "bytes": bytes }),
    })
}
```

(Compute `parsed_is_valid` before `parsed` is consumed: `let valid = parsed.is_ok();`.) Look at how `CAUSE_INVALID_ADMIN_ARGS` and `RECOVERY_FLOW_EDIT` are imported/declared at the top of the file and reuse them. Update the module doc comment's op list.

- [ ] **Step 4: Run tests**

Run: `cargo test -p pam_daemon admin_flows && cargo test -p pam_gui`
Expected: pass (the bridge whitelist test sums `FLOW_ADMIN_OPS.len()`, so it follows).

- [ ] **Step 5: Commit**

```bash
git add crates/pam_daemon
git commit -m "feat(daemon): admin.flows.normalize — canonical YAML + first error for the designer"
```

---

### Task 3: Per-step settle note

**Files:**
- Modify: `crates/pam_daemon/src/flow_service.rs` (`RunState::execute`, `publish_progress`)
- Test: `crates/pam_daemon/src/flow_service_test.rs`

**Interfaces:**
- Produces: after each executed step, a `Progress { pct, note: "<step>: <status>" }` event where `<status>` is `StepStatus::as_str()`. Skipped steps also publish `"<step>: skipped"`. The running note is unchanged.

- [ ] **Step 1: Failing test** — find how `flow_service_test.rs` runs a flow with a captured `EventPublisher::for_tests()` receiver (grep `for_tests` and `Event::Progress` there); write:

```rust
#[tokio::test]
async fn every_step_publishes_a_running_note_then_its_settle_note() {
    // arrange exactly like the existing progress/run test in this file:
    // a flow with two command steps (`true`-like allowlisted programs used
    // elsewhere in this file), run it, drain the events receiver.
    let notes: Vec<String> = /* collect Event::Progress { note, .. } in order */;
    assert_eq!(
        notes,
        vec![
            "first: running (1/2)".to_owned(),
            "first: succeeded".to_owned(),
            "second: running (2/2)".to_owned(),
            "second: succeeded".to_owned(),
        ]
    );
}
```

Copy the arrangement from the nearest existing test verbatim (same programs, same `flows_for_tests` helper).

- [ ] **Step 2: Run to verify failure** — `cargo test -p pam_daemon every_step_publishes` — expected: the vector has two entries.

- [ ] **Step 3: Implement** — in `execute`:

```rust
if !self.should_run(step) {
    self.reports.push(StepReport::new(&step.id, step.kind(), StepStatus::Skipped));
    self.publish_settled(index, total, &step.id, StepStatus::Skipped).await;
    continue;
}
self.publish_progress(index, total, &step.id).await;
let report = self.run_step(step).await?;
let blocked = report.status == StepStatus::Blocked;
self.publish_settled(index, total, &step.id, report.status).await;
self.reports.push(report);
```

with

```rust
/// Tells subscribers how a step ended, so a canvas can paint its rim
/// before the verdict lands.
async fn publish_settled(&self, index: usize, total: usize, step: &str, status: StepStatus) {
    let note = format!("{step}: {}", status.as_str());
    self.publish_note(index + 1, total, note).await;
}
```

Refactor `publish_progress` so both share one `publish_note(done: usize, total, note)` computing `pct` (running uses `index`, settled uses `index + 1`).

- [ ] **Step 4: Run** — `cargo test -p pam_daemon` and `cargo test -p pam --test live_subscribe` if it asserts note text (grep `running (` under `crates/pam/tests`; adjust only if an assertion counts progress events).

- [ ] **Step 5: Commit** — `git commit -am "feat(daemon): publish a settle note per flow step"`

---

### Task 4: Frontend foundation — deps, ipc types, tokens, jsdom stubs

**Files:**
- Modify: `frontend/package.json`, `frontend/package-lock.json`
- Modify: `frontend/src/lib/ipc.ts`
- Modify: `frontend/src/styles/tokens.css`, `frontend/src/styles/design.test.ts`
- Modify: `frontend/vitest.setup.ts`
- Test: `frontend/src/lib/ipc.test.ts` (exists? grep; otherwise the `flowsNormalize` wrapper is covered by FlowCanvas tests)

**Interfaces (produces, all exported from `ipc.ts`):**

```ts
export type FlowWhen = "needs_succeeded" | "always" | { succeeded: string } | { failed: string };
export type FlowEffect = "read_only" | "stateful";
export type FlowRole = "observe" | "verify" | "change";
export type FlowOutput = "compact" | "summarize" | "discard";
export type FlowApproval = "none" | "required";
export type FlowConnectorId = "github" | "jenkins" | "sonarqube" | "jira" | "confluence" | "sharepoint" | "aws";
export const FLOW_CONNECTORS: readonly FlowConnectorId[] = ["github","jenkins","sonarqube","jira","confluence","sharepoint","aws"];
export type FlowArgValue = string | number;
export type FlowAction =
  | { kind: "command"; argv: string[] }
  | { kind: "connector"; connector: FlowConnectorId; call: string; with: Record<string, FlowArgValue> };
export interface FlowStep {
  id: string; action: FlowAction; timeout: string; effect: FlowEffect; role: FlowRole;
  output: FlowOutput; needs: string[]; when: FlowWhen;
  retry: { attempts: number; backoff: string }; approval: FlowApproval; env: Record<string, string>;
}
export interface FlowSpecInput { description: string; default: string | null }
export interface FlowSpec { id: string; name: string; description: string; inputs: Record<string, FlowSpecInput>; steps: FlowStep[] }
/** The file's own shape, what `admin.flows.normalize { flow }` takes. */
export interface RawFlowStep {
  id: string; run?: string[]; connector?: FlowConnectorId; call?: string; with?: Record<string, FlowArgValue>;
  timeout?: string; effect?: FlowEffect; role?: FlowRole; output?: FlowOutput; needs?: string[];
  when?: FlowWhen; retry?: { attempts: number; backoff?: string }; approval?: FlowApproval; env?: Record<string, string>;
}
export interface RawFlow { schema: 1; id: string; name: string; description?: string; inputs?: Record<string, { description?: string; default?: string | null }>; steps: RawFlowStep[] }
export type FlowNormalizeReply =
  | { valid: true; yaml: string; flow: FlowSpec; digest: string }
  | { valid: false; error: { path: string; message: string } };
export function flowsNormalize(input: { yaml: string } | { flow: RawFlow }): Promise<FlowNormalizeReply>;
/** Connector call table mirrored from pam_flow::validate::connector_calls, for the inspector's call picker. */
export const FLOW_CONNECTOR_CALLS: Record<FlowConnectorId, { name: string; args: { name: string; required: boolean }[] }[]>;
```

`FlowDetail.flow` becomes `flow?: FlowSpec | null`. Copy `FLOW_CONNECTOR_CALLS` exactly from `crates/pam_flow/src/validate.rs` lines 107–230 (`connector_calls`), argument names and required flags verbatim.

- [ ] **Step 1: Install deps**

```bash
cd frontend && npm install @xyflow/react@^12 elkjs@^0.11
```

(Use the latest 0.x elkjs npm shows; pin the caret to what installs.) Confirm `npm ls elkjs @xyflow/react`.

- [ ] **Step 2: ipc.ts** — add the types and wrapper above, extend `AdminOp` with `"admin.flows.normalize"`, narrow `FlowDetail.flow`.

- [ ] **Step 3: vitest.setup.ts** — xyflow in jsdom needs:

```ts
if (typeof window !== "undefined") {
  if (!("ResizeObserver" in window)) {
    class ResizeObserverStub { observe() {} unobserve() {} disconnect() {} }
    Object.defineProperty(window, "ResizeObserver", { value: ResizeObserverStub, configurable: true });
  }
  if (!("DOMMatrixReadOnly" in window)) {
    class DOMMatrixReadOnlyStub { m22 = 1; constructor(_t?: string) {} }
    Object.defineProperty(window, "DOMMatrixReadOnly", { value: DOMMatrixReadOnlyStub, configurable: true });
  }
}
```

(These are the two globals @xyflow/react touches on mount; add `Element.prototype.getBoundingClientRect` stubs only if a test needs measured nodes.)

- [ ] **Step 4: tokens.css** — after the `@theme inline` block, add a scoped binding block (not inside `@theme`, and not inside a `@layer`):

```css
/* ------------------------------------------------------------------ *
 * xyflow — its stylesheet is unlayered, so the canvas is themed only
 * through the variables it reads. Every value is a semantic token.
 * ------------------------------------------------------------------ */
.flow-canvas .react-flow {
  --xy-background-color: var(--color-chrome);
  --xy-background-pattern-color: var(--color-separator);
  --xy-edge-stroke: var(--color-line);
  --xy-edge-stroke-selected: var(--color-accent);
  --xy-edge-stroke-width: 1.5;
  --xy-edge-label-background-color: var(--color-surface-raised);
  --xy-edge-label-color: var(--color-ink-muted);
  --xy-handle-background-color: var(--color-line);
  --xy-handle-border-color: var(--color-surface-raised);
  --xy-selection-background-color: var(--color-accent-soft);
  --xy-selection-border: 1px solid var(--color-accent);
  --xy-minimap-background-color: var(--color-surface);
  --xy-minimap-mask-background-color: var(--color-overlay);
  --xy-minimap-node-background-color: var(--color-accent-soft);
  --xy-minimap-node-stroke-color: var(--color-edge);
  --xy-node-background-color: var(--color-surface-raised);
  --xy-node-border: 1px solid var(--color-edge);
  --xy-node-boxshadow-selected: var(--shadow-raise);
  --xy-attribution-background-color: transparent;
}
```

Check the exact variable names against `node_modules/@xyflow/react/dist/style.css` (grep `--xy-`) and keep only names that exist there; drop any that do not.

- [ ] **Step 5: design.test.ts** — add:

```ts
describe("xyflow bindings", () => {
  it("binds every --xy-* variable to a semantic token, never a raw value", () => {
    const block = blockOf(stripComments(tokensCss), ".flow-canvas .react-flow");
    const declarations = declarationsOf(block);
    const names = Object.keys(declarations).filter((name) => name.startsWith("--xy-"));
    expect(names.length).toBeGreaterThan(8);
    for (const name of names) {
      const value = declarations[name];
      const ok = /var\(--(color|shadow)-[a-z-]+\)/.test(value) || value === "transparent" || /^[0-9.]+$/.test(value) || /^1px solid var\(--color-[a-z-]+\)$/.test(value);
      expect(ok, `${name}: ${value}`).toBe(true);
    }
  });
});
```

Adapt to the file's existing `blockOf`/`declarationsOf` helpers (read lines 83–117 first; `blockOf` may expect a `:root`-style selector string — pass the selector exactly as written).

- [ ] **Step 6: Gate**

```bash
npm --prefix frontend run lint && npm --prefix frontend run build && npm --prefix frontend run test
```

- [ ] **Step 7: Commit**

```bash
git add frontend/package.json frontend/package-lock.json frontend/src/lib/ipc.ts frontend/src/styles frontend/vitest.setup.ts
git commit -m "feat(gui): designer foundation — xyflow + elk deps, flow types, normalize op, --xy tokens"
```

---

### Task 5: `graph.ts` — the pure canvas model

**Files:**
- Create: `frontend/src/screens/flow-canvas/graph.ts`
- Test: `frontend/src/screens/flow-canvas/graph.test.ts`

**Interfaces (produces):**

```ts
import type { Edge, Node } from "@xyflow/react";
export type RunStatus = "running" | FlowStepStatus;
export interface Marker { path: string; message: string; field: string }
export interface StepNodeData extends Record<string, unknown> { step: FlowStep; index: number; status: RunStatus | null; marker: Marker | null; selected?: boolean }
export interface InputsNodeData extends Record<string, unknown> { inputs: FlowSpec["inputs"]; marker: Marker | null }
export interface VerdictNodeData extends Record<string, unknown> { outcome: OutcomeName | null }
export type StepNode = Node<StepNodeData, "step">;
export type InputsNode = Node<InputsNodeData, "inputs">;
export type VerdictNode = Node<VerdictNodeData, "verdict">;
export type CanvasNode = StepNode | InputsNode | VerdictNode;
export type EdgeKind = "needs" | "succeeded" | "failed" | "terminal";
export interface FlowEdgeData extends Record<string, unknown> { kind: EdgeKind; running: boolean }
export type CanvasEdge = Edge<FlowEdgeData, "flow">;
export const INPUTS_NODE = "inputs"; export const VERDICT_NODE = "verdict";
export function edgeId(kind: Exclude<EdgeKind,"terminal">, source: string, target: string): string; // `${kind}:${source}->${target}`
export function toGraph(spec: FlowSpec, statuses?: Record<string, RunStatus>, marker?: Marker | null): { nodes: CanvasNode[]; edges: CanvasEdge[] }; // positions {x:0,y:0}; selected false
export type Refused = { cause: string; fix: string };
export type Edit = { ok: true; spec: FlowSpec } | { ok: false; refused: Refused };
export function connect(spec: FlowSpec, source: string, target: string): Edit;      // adds `needs`, order repair, cycle refusal, no-op if present, refuses self/inputs/verdict
export function disconnect(spec: FlowSpec, id: string): FlowSpec;                   // removes needs entry or resets when
export function setEdgeKind(spec: FlowSpec, id: string, kind: Exclude<EdgeKind,"terminal">): Edit; // needs<->when flip (a when edge replaces any existing when)
export function addStep(spec: FlowSpec, kind: "command" | "connector"): { spec: FlowSpec; id: string }; // id `step-N` first free N; command argv ["git","status"]; connector github/runs with {}
export function removeStep(spec: FlowSpec, id: string): FlowSpec;                   // drops references in other steps' needs/when
export function updateStep(spec: FlowSpec, id: string, patch: Partial<FlowStep>): FlowSpec; // renaming id rewrites references
export function moveStep(spec: FlowSpec, id: string, direction: -1 | 1): Edit;      // refuses when it would put a reference forward
export function updateInputs(spec: FlowSpec, inputs: FlowSpec["inputs"]): FlowSpec;
export function defaultStep(id: string, kind: "command" | "connector"): FlowStep;   // timeout "5m", effect read_only, role observe (change when stateful), output compact, needs [], when "needs_succeeded", retry {attempts:1, backoff:"500ms"}, approval none, env {}
export function toRaw(spec: FlowSpec): RawFlow;                                     // action → run|connector/call/with; every other field copied as-is
export function markerFor(error: { path: string; message: string } | null, spec: FlowSpec): { node: string | null; marker: Marker | null }; // node = step id for steps[N], INPUTS_NODE for inputs., null otherwise; field = path after the node prefix
export function splitArgv(line: string): string[]; export function joinArgv(argv: string[]): string; // double-quoted tokens kept whole; quotes re-added on tokens with spaces
export function isStepId(id: string): boolean; // /^[a-z0-9-]{1,64}$/
```

Order repair (in `connect`, when `index(target) < index(source)`): `dependents(target)` = target plus every step that references any member through `needs` or `when`, transitively, in current order. If `source ∈ dependents` → refused `{ cause: "\`${target}\` already runs before \`${source}\`", fix: "remove the edge that makes \`${source}\` wait on \`${target}\` first" }`. Otherwise remove the dependents from the array and splice them right after `source`.

- [ ] **Step 1: Failing tests** (`graph.test.ts`, vitest, no DOM). Write these `it` blocks with a `spec()` fixture builder (three command steps `a`, `b`, `c`; `b.needs = ["a"]`):

```ts
it("derives one step node per step in file order plus the two frames", …)        // 5 nodes; ids ["inputs","a","b","c","verdict"]; index 0..2
it("derives needs edges, when edges with their kind, and terminal edges", …)      // needs:a->b; c has when {failed:"b"} → failed:b->c; terminal from c only
it("connect adds a needs edge forward without reordering", …)                     // connect(a→c): c.needs = ["a"]; order unchanged
it("connect backward moves the target and its dependents after the source", …)   // spec a,b,c with c.needs=[b]; connect(c→a): order [b? no] → compute: dependents(a) = a,b(needs a),c(needs b) includes c=source → refused. Use: steps a,b,c independent; connect(c→a) → order [b,c,a]; a.needs=["c"]
it("connect refuses a cycle with cause and fix", …)                               // b.needs=[a]; connect(b→a) → ok:false, cause names both ids
it("connect refuses frames and self", …)                                          // inputs/verdict/self → ok:false
it("disconnect removes a needs entry or resets when", …)
it("setEdgeKind flips needs to succeeded and back, replacing an existing when", …)
it("addStep picks the first free step-N id and defaults every field", …)         // step-1, then step-2; defaultStep shape asserted field by field
it("removeStep drops references in later steps", …)                               // remove a → b.needs [], c.when needs_succeeded
it("updateStep renaming an id rewrites references", …)
it("moveStep refuses to move a step before one it needs", …)                       // b (needs a) up → refused; c up → ok
it("toRaw emits run for commands and connector/call/with for connectors", …)     // no `action` key; `needs`/`when` copied
it("markerFor maps steps[N] to the step id and inputs. to the frame", …)          // steps[1].run[0] → {node:"b", field:"run[0]"}; inputs.repo.default → inputs; id → null
it("splitArgv keeps double-quoted tokens whole and joinArgv re-quotes spaces", …) // `cargo clippy -- -D warnings "two words"` ↔ 6 tokens
```

- [ ] **Step 2: Run** — `npm --prefix frontend run test -- graph` — expected: module not found.

- [ ] **Step 3: Implement** `graph.ts` exactly to the interfaces. Pure functions, never mutate the input spec (spread/map). `toGraph` nodes: `{ id, type: "step", position: {x:0,y:0}, data }`; edges `{ id, type: "flow", source, target, data: { kind, running: statuses?.[target] === "running" } }`; terminal edges `{ id: "terminal:"+id, source: id, target: VERDICT_NODE, selectable: false, data: { kind: "terminal", running: false } }` for steps that are not a source of any needs/when edge. The Inputs frame connects to nothing.

- [ ] **Step 4: Run tests until green**, then `npm --prefix frontend run lint`.

- [ ] **Step 5: Commit** — `git add frontend/src/screens/flow-canvas && git commit -m "feat(gui): flow canvas graph model — nodes, edges, order repair, raw round-trip"`

---

### Task 6: `notes.ts` and `layout.ts`

**Files:**
- Create: `frontend/src/screens/flow-canvas/notes.ts`, `notes.test.ts`
- Create: `frontend/src/screens/flow-canvas/layout.ts`, `layout.test.ts`

**Interfaces (produces):**

```ts
// notes.ts
export function parseNote(note: string): { step: string; status: RunStatus } | null;
export function statusesFrom(notes: readonly string[]): Record<string, RunStatus>; // later notes win
// layout.ts
export type Positions = Record<string, { x: number; y: number }>;
export function loadPositions(flowId: string): Positions;           // try/catch, {} on anything
export function savePositions(flowId: string, positions: Positions): void;
export function clearPositions(flowId: string): void;
export const LAYOUT_KEY = (flowId: string) => `pam.flow.layout.${flowId}`;
export async function autoLayout(nodes: readonly CanvasNode[], edges: readonly CanvasEdge[], sizes: Record<string, { width: number; height: number }>): Promise<Positions>;
export function applyPositions(nodes: CanvasNode[], positions: Positions): CanvasNode[];
export const NODE_SIZE = { step: { width: 220, height: 112 }, inputs: { width: 200, height: 96 }, verdict: { width: 200, height: 96 } } as const;
```

`autoLayout` does `const { default: ELK } = await import("elkjs/lib/elk.bundled.js");` (literal specifier — never a variable) and runs `elk.layout({ id: "root", layoutOptions: { "elk.algorithm": "layered", "elk.direction": "RIGHT", "elk.spacing.nodeNode": "48", "elk.layered.spacing.nodeNodeBetweenLayers": "96", "elk.portConstraints": "FIXED_SIDE" }, children: nodes.map(n => ({ id: n.id, width, height })), edges: edges.map(e => ({ id: e.id, sources: [e.source], targets: [e.target] })) })` and maps children `x,y` back. Type the import with a minimal local `declare module "elkjs/lib/elk.bundled.js"` in `frontend/src/screens/flow-canvas/elk.d.ts` only if the package's own types do not resolve for that path (check `node_modules/elkjs/lib/elk.bundled.d.ts` first — it exists in recent versions).

- [ ] **Step 1: Failing tests**

`notes.test.ts`:
```ts
it("parses the running note", () => expect(parseNote("clippy: running (3/6)")).toEqual({ step: "clippy", status: "running" }));
it("parses every settle word", () => for each of succeeded/failed/skipped/blocked/cancelled …);
it("ignores anything else", () => expect(parseNote("queued · waiting")).toBeNull());
it("later notes win", () => expect(statusesFrom(["a: running (1/2)", "a: succeeded", "b: running (2/2)"])).toEqual({ a: "succeeded", b: "running" }));
```

`layout.test.ts` (mock elk: `vi.mock("elkjs/lib/elk.bundled.js", () => ({ default: class { layout = vi.fn(async (g) => ({ ...g, children: g.children.map((c, i) => ({ ...c, x: i * 100, y: 10 })) })) } }))`):
```ts
it("round-trips positions through localStorage under the flow key", …);
it("returns {} when the store throws or holds junk", …);   // Object.defineProperty(window,"localStorage",{get(){throw new Error("nope")}}) then restore; and setItem("pam.flow.layout.x","not json")
it("autoLayout asks ELK for a layered RIGHT graph and maps x/y back", …);
it("applyPositions keeps nodes without a stored position at their current place", …);
```

- [ ] **Step 2: Run, verify failure. Step 3: Implement. Step 4: Run green + lint.**

- [ ] **Step 5: Commit** — `git commit -m "feat(gui): flow canvas notes parser and layout store with ELK"`

---

### Task 7: Nodes, edges, canvas host

**Files:**
- Create: `frontend/src/screens/flow-canvas/StepNode.tsx`, `FrameNode.tsx`, `FlowEdge.tsx`, `FlowCanvas.tsx`
- Test: `frontend/src/screens/flow-canvas/FlowCanvas.test.tsx`

**Interfaces:**
- Consumes: Task 5/6 exports; `Panel`, `Badge`, `Button`, `ConfirmButton`, `FailureNote`; lucide `Terminal`, `Plug`, `Hand`, `Sparkles`, `Clock`, `RotateCw`, `KeyboardIcon`/`SlidersHorizontal`, `Flag`.
- Produces:

```tsx
export interface FlowCanvasProps {
  flowId: string;
  spec: FlowSpec;
  statuses: Record<string, RunStatus>;
  outcome: OutcomeName | null;
  error: { path: string; message: string } | null;
  onChange: (spec: FlowSpec) => void;       // every accepted edit
  selection: Selection; onSelect: (s: Selection) => void;
}
export type Selection = { kind: "none" } | { kind: "step"; id: string } | { kind: "edge"; id: string } | { kind: "inputs" };
export function FlowCanvas(props: FlowCanvasProps): JSX.Element;  // wraps ReactFlowProvider
```

Visuals (frontend-design skill governs; measurable bar in the spec): StepNode = `Panel ground="raised"` recipe via `cva` `stepNodeVariants` with `rim: none | selected | running | succeeded | failed | skipped | blocked | cancelled | invalid | approval` mapping to `ring-2 ring-accent`, `ring-2 ring-accent animate-breathe`, `ring-2 ring-success`, `ring-2 ring-danger`, `ring-2 ring-ink-faint`, `ring-2 ring-warning`, `ring-2 ring-danger` (invalid, plus marker chip), `ring-2 ring-warning` (approval), all token-backed. Width `w-56`. Header: glyph + `font-display text-sm font-semibold` id + order `Badge tone="neutral"`; body `font-data text-xs text-ink-muted line-clamp-2`; footer chips per the spec table; `Handle type="target" position={Position.Left}` and `type="source" position={Position.Right}` with class `size-2.5 rounded-pill bg-line hover:bg-accent`. Marker chip `Badge tone="danger"` with `title={message}` and an `aria-label="validation marker"`; the cause+fix text renders in a `FailureNote`-styled popover inside the node when selected (reuse `FailureNote` with `{ cause: message, detail: field, recovery: "fix it in the inspector" }`).

FrameNode: `Panel` (surface) `w-50`; Inputs lists `name = default` rows or "no inputs"; Verdict shows the five outcome chips via `OUTCOME_TONES` from FlowRunCard (import it), all `opacity-40` except the painted `outcome`.

FlowEdge: `getSmoothStepPath`; `BaseEdge` with `className` from `cva` `edgeVariants` `{ kind: needs|succeeded|failed|terminal, running: true|false }` → strokes `stroke-line`, `stroke-success`, `stroke-danger`, `stroke-line opacity-40`; running adds `animate-dash` — add `--animate-dash: dash 1s linear infinite` + `@keyframes dash { to { stroke-dashoffset: -12 } }` to the `@theme` block in tokens.css (next to `--animate-breathe`) and `stroke-dasharray` via the class `[stroke-dasharray:6]`? **No** — arbitrary values are banned; add a plain CSS rule `.flow-canvas .flow-edge-running { stroke-dasharray: 6 }` next to the `--xy-*` block. `EdgeLabelRenderer` pill `Badge` for `succeeded`/`failed`.

FlowCanvas: `<div className="flow-canvas h-130 min-h-130 w-full rounded-card border border-edge overflow-hidden">` (check `h-130` exists in the spacing scale: Tailwind v4 numeric spacing is unbounded multiples of `--spacing`, so `h-130` = 32.5rem = 520px; fine). `ReactFlow` with `nodeTypes={{ step: StepNode, inputs: FrameNode, verdict: FrameNode }}`, `edgeTypes={{ flow: FlowEdge }}`, `snapToGrid snapGrid={[16,16]}`, `fitView`, `proOptions={{ hideAttribution: true }}`, `<Background variant={BackgroundVariant.Dots} gap={16} />`, `<MiniMap pannable zoomable />`, `onConnect` → `connect()` → `onChange` or `setRefused(refused)` (FailureNote above the canvas, label "canvas"), `onNodesChange` → applyNodeChanges to a local nodes state (needed for the minimap to see measured sizes) and on `position` change with `dragging === false` → `savePositions`, `onEdgesDelete`/`onNodesDelete` disabled (`deleteKeyCode={null}`; removal goes through the toolbar's ConfirmButton), `onSelectionChange` → `onSelect`. Toolbar row above: `Add command`, `Add connector` (ghost sm) → `addStep` + select it; spacer; `Tidy` → `clearPositions` + `autoLayout` for all; `Fit` → `fitView()`; `Remove` (ConfirmButton, disabled when selection none) → `removeStep`/`disconnect`. On `spec` change: rebuild nodes from `toGraph`, apply stored positions, and `autoLayout` only the nodes without one (keep others). Keep the `ReactFlowProvider` inside `FlowCanvas` so `useReactFlow` works for `fitView`.

- [ ] **Step 1: Failing tests** (`FlowCanvas.test.tsx`; mock `./layout` autoLayout to a resolved grid; render with `pr-readiness`-like spec of 3 steps):

```ts
it("renders one node per step with its order chip and kind glyph", …)                 // getAllByRole("button"/"group")? xyflow nodes are div[data-id]; query by aria-label `step ${id}`
it("shows the modifier chips: approval hand, summarize sparkle, retry, timeout", …)
it("paints the marker on the node named by the error path", …)                        // error {path:"steps[1].run[0]"} → node b has aria-label "validation marker"
it("paints rims from statuses and the running dash on incoming edges", …)             // statuses {a:"succeeded", b:"running"} → node classes contain ring-success / animate-breathe; edge needs:a->b has flow-edge-running
it("Add command appends a step and selects it", …)                                     // onChange called with 4 steps, onSelect {kind:"step", id:"step-1"}
it("Remove on a selected step goes through the confirm tap and calls onChange", …)
it("Tidy clears stored positions and relays every node", …)                            // localStorage key removed; autoLayout mock called with 5 nodes
it("a refused connection shows cause and fix above the canvas", …)                     // call the onConnect handler via the ReactFlow mock? Simpler: export `useConnectHandler` or test `connect` at the graph level (already) and here assert the FailureNote renders when `refused` state set through a backward connection triggered by `fireEvent` on handles is not feasible in jsdom — instead expose a `data-testid`-free prop `onConnectAttempt` for tests? No: keep it honest — render, grab the ReactFlow `onConnect` by mocking `@xyflow/react`'s `ReactFlow` with a stub that captures props and renders `nodes`/`edges` through the given `nodeTypes`/`edgeTypes`. Use that stub for every test in this file (a `vi.mock("@xyflow/react", …)` that keeps `Handle`, `Position`, `BaseEdge`, `getSmoothStepPath`, `EdgeLabelRenderer`, `ReactFlowProvider`, `useReactFlow` real where possible and replaces only `ReactFlow`, `Background`, `MiniMap`).
```

- [ ] **Step 2: Run, verify failures. Step 3: Implement the four components. Step 4: Green + lint + `npm run build`.**

- [ ] **Step 5: Commit** — `git commit -m "feat(gui): flow canvas — step cards, frames, edges, toolbar, minimap"`

---

### Task 8: Inspector

**Files:**
- Create: `frontend/src/screens/flow-canvas/Inspector.tsx`
- Test: `frontend/src/screens/flow-canvas/Inspector.test.tsx`

**Interfaces:**

```tsx
export interface InspectorProps { spec: FlowSpec; selection: Selection; onChange: (spec: FlowSpec) => void; onSelect: (s: Selection) => void; error: { path: string; message: string } | null }
export function Inspector(props: InspectorProps): JSX.Element;
```

Sections (use `Section` eyebrows, fields styled like `fieldClasses` in FlowRunCard — copy that class string into a shared `frontend/src/components/ui/field.ts` exporting `fieldClasses` and import it in both places):
- nothing selected → flow `name`, `description` (textarea rows 3).
- `inputs` → rows name / description / default, `Add input`, remove per row; writes through `updateInputs`.
- `step` → `id` (local check `isStepId` + uniqueness → inline danger text "ids are [a-z0-9-], unique"), `kind` (two `aria-pressed` buttons like the tabs), command: `argv` single input (`splitArgv` on blur/enter, `joinArgv` to display) + `env` rows; connector: connector select (`FLOW_CONNECTORS`), call select (`FLOW_CONNECTOR_CALLS[connector]`), `with` rows pre-listed from the call's args with `required` marked; `timeout` input; `effect`, `role`, `output`, `approval` selects; `retry` attempts (1–5) + backoff; `when` display (read-only summary: "runs when needs succeeded" / "always" / "when b succeeded"); step list with ▲ ▼ buttons (`moveStep`, refusal as inline text) and click-to-select.
- `edge` → radio `needs` / `succeeded` / `failed` (`setEdgeKind`), plus the edge's `source → target` line; terminal edges are never selectable so never reach here.
- The `error` for the selected thing renders as `FailureNote` with `label="flow"` at the top of the inspector (`markerFor` decides whether it belongs to this selection).

Selects with `stateful` effect force `approval` to `required` in the UI (disabled select with a note "stateful steps always need approval"), mirroring the validator.

- [ ] **Step 1: Failing tests** — one `it` per section: name edit calls onChange with the new name; input row add/remove; step id invalid shows the inline note and does not call onChange; argv line splits into argv on Enter; kind flip to connector yields `github` / first call and required `with` rows; effect `stateful` forces approval; retry attempts clamp to 1–5; move ▲ on a dependent shows the refusal; edge radio flips kind.

- [ ] **Step 2–4: Run → implement → green + lint.**

- [ ] **Step 5: Commit** — `git commit -m "feat(gui): flow canvas inspector"`

---

### Task 9: Flows screen integration

**Files:**
- Modify: `frontend/src/screens/Flows.tsx`, `FlowEditor.tsx`, `FlowRunCard.tsx`
- Test: `frontend/src/screens/Flows.test.tsx`

**Interfaces:**
- `FlowEditor` props become `{ entry, yaml, onYamlChange: (yaml: string) => void, saveDisabled: boolean, onSaved, onDeleted }` — it no longer owns the text or fetches the detail; Flows.tsx does.
- `FlowRunCard` gains optional `onRun?: (run: { ticket: string | null; notes: string[]; settled: string | null; refused: boolean }) => void`, called whenever any of those change (notes accumulate per ticket; a new ticket resets them).
- Flows.tsx: `TABS = ["canvas", "yaml", "runs"]`, default `"canvas"`; state per selected flow: `detail = useQuery(["flow", id], flowsGet)`; `draft: { yaml: string; spec: FlowSpec | null; error: {path,message} | null; dirty: boolean }` reset from `detail.data` (`yaml`, `flow`) on id change; `normalize = useMutation(flowsNormalize)`; `onCanvasChange(spec)` → set `draft.spec = spec` immediately, debounce 150 ms → `normalize.mutate({ flow: toRaw(spec) })` → on reply set `yaml`, `spec` (valid) or `error` (invalid); `onYamlChange(text)` → set `yaml`, `dirty`, debounce 400 ms → `normalize.mutate({ yaml })` → on reply set `spec`/`error` (and **not** the yaml text — the human's text stays as typed until Save). Switching to the canvas tab flushes the pending yaml debounce. `saveDisabled = draft.error !== null || normalize.isPending`. Run state: `run` from `FlowRunCard.onRun`; `statuses = statusesFrom(run.notes)`; `verdict = useFlowVerdict(run.settled)`; when `verdict.data` exists, statuses become `Object.fromEntries(steps.map(s => [s.id, s.status]))` and `outcome = verdict.data.outcome`; any `onCanvasChange`/`onYamlChange` clears `run` (`setRun(null)`). FlowEditor and FlowRunCard render under both `canvas` and `yaml`; FlowRuns under `runs`. The inspector sits right of the canvas at `lg:` (`grid lg:grid-cols-[1fr_20rem]`? — banned arbitrary value; use `lg:flex lg:flex-row` with `lg:w-80` on the inspector panel).

- [ ] **Step 1: Failing tests** (extend `Flows.test.tsx`; add `flowsNormalize` to `mocks` and a `SPEC` fixture with three steps returned from `flowsGet` as `flow`):

```ts
it("opens on the canvas tab with one node per step", …);
it("a canvas edit normalizes and rewrites the yaml tab's text", …);       // trigger onChange via the Add command toolbar button; flowsNormalize called with {flow: {...run:["git","status"]...}}; switch to yaml → textarea value equals reply.yaml
it("a yaml edit re-parses into the canvas after the debounce", …);        // fake timers; type in the textarea; advance 400ms; flowsNormalize called with {yaml}
it("an invalid reply marks the node and disables Save", …);
it("run notes paint rims and the verdict settles them", …);               // start a run from the card (existing helper), feed progress notes → node aria/status attribute; feed done → verdict rims + Verdict frame outcome chip
it("editing after a run clears the rims", …);
```

Keep every existing test green; update the ones that assumed the default tab was `yaml` (they now click the `yaml` tab first, or use the `editorFor` helper after clicking).

- [ ] **Step 2: Run → verify failures. Step 3: Implement. Step 4: `tools/check.sh` green.**

- [ ] **Step 5: Commit** — `git commit -m "feat(gui): Flows canvas tab — shared draft, normalize round-trip, live markers, run rims"`

---

### Task 10: Verification, docs, landing

- [ ] `tools/check.sh` on the settled tree.
- [ ] Production proof: `npm --prefix frontend run build && rg -c 'admin.flows.normalize' frontend/dist/assets/*.js && ls frontend/dist/assets | rg -i elk` — the ELK chunk must be a separate file (literal dynamic import). Then `cargo build --release -p pam --features gui-embed && strings target/release/pam | rg -c 'admin.flows.normalize'`.
- [ ] Fixture eyeballing (recipe: scratch `send_admin` dump binary → `frontend/public/fixture.js` shim answering `daemon_status`, `plugin:event|listen`, `admin_call` by op, `__TAURI_EVENT_PLUGIN_INTERNALS__.unregisterListener`; served through a temporary `.claude/launch.json` entry; delete both after): screenshots of the canvas for `pr-readiness` and `ci-failure-triage`, an inspector edit and the YAML it produced, a marker, run rims mid-run and the verdict, in all four `data-theme` × `data-mode` combos.
- [ ] Spec: append "Landed deviations" if any (e.g. variable names of `--xy-*` that did not exist).
- [ ] PR per landing wave; `gh pr checks <n> --watch && gh pr merge <n> --squash --delete-branch`; main run watched by id with `--exit-status`, conclusion must be the literal `success`.
- [ ] ptrack: tasks under plan #6 closed with `--summary`, commits linked (`ptrack commit add`), summary set.

## Landing waves

- Wave A (worktree 1, Rust only): Tasks 1–3 → PR `feat(daemon): admin.flows.normalize + per-step settle notes`.
- Wave B (worktree 2, frontend foundation): Tasks 4–6 → PR `feat(gui): flow designer foundation`.
  A and B touch disjoint files (B does not touch Cargo.lock) and can run in parallel.
- Wave C (after B lands, one worktree): Tasks 7–8 → PR `feat(gui): flow canvas + inspector`.
- Wave D (after A and C): Task 9 → PR `feat(gui): Flows canvas tab`.
- Task 10 closes the plan.
