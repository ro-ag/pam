/**
 * The intent table: what Pam can be asked, how a question is recognised,
 * and the sentence each answer is built from.
 *
 * Two orders come out of one table. `SPEC_ORDER` is what the Home pills
 * show (the spec's reading order); `MATCH_ORDER` is what `matchIntent`
 * walks, and it resolves the overlaps — a question about a refusal
 * "today" is about the refusal, one about starting "the daemon" at login
 * is about login, one about "tokens saved today" is about the odometer.
 */

import type { Answer, Args, AskContext, IntentId, SettingsTopic } from "./answer";
import { ago, duration, failedRead, gb, kb, localMidnight, plural, repoTail } from "./answer";
import type { Sources } from "./sources";

/**
 * An answer reads sources and returns a sentence. It also gets the raw
 * question: `where_change` needs the wording to tell "start at login"
 * from "restart the daemon" — both land on the Daemon panel, but they are
 * not the same sentence.
 */
type AnswerFn = (
  args: Args,
  sources: Sources,
  ctx: AskContext,
  question: string,
) => Promise<Answer>;

export interface Intent {
  id: IntentId;
  label: string;
  canonical: string;
  patterns: RegExp[];
  answer: AnswerFn;
}

// --- capture ---------------------------------------------------------------

/** Crockford ULID: the ticket ids the daemon hands out. */
const ULID = /\b[0-9A-HJKMNP-TV-Z]{26}\b/;
/** `repo.push`, `flow.run`, `compress.log`. */
const CAPABILITY = /\b([a-z]+(?:\.[a-z_]+)+)\b/;
const IN_REPO = /\bin\s+([\w.-]+)\b/i;
const RUN_FLOW = /\brun\s+([a-z0-9][a-z0-9-]*)/i;

/** Settings wording → panel, anchor slug, and the sentence's subject. */
const TOPICS: Array<[RegExp, SettingsTopic, string, string]> = [
  [/retention|prune|how long .*keep/i, "retention", "Retention", "Retention"],
  [/login|startup|start at|launch/i, "daemon", "Daemon", "Start at login"],
  [/daemon|stop|restart/i, "daemon", "Daemon", "The daemon"],
  [
    /profile|approval mode|relaxed|strict/i,
    "security",
    "Security",
    "The approval profile and grants",
  ],
  [/grant|capabilit/i, "security", "Security", "The approval profile and grants"],
  [
    /models? (dir|folder|directory)|weights|tier|curator/i,
    "models",
    "Models",
    "The models directory and tier defaults",
  ],
  [
    /connector|jira|github|sonar|confluence|sharepoint|aws/i,
    "connectors",
    "Connectors",
    "Connectors",
  ],
  [/allowed program|flow setting|flows? (dir|folder)/i, "flows", "Flows", "Flow programs"],
  [/theme|mode|dark|light|appearance/i, "appearance", "Appearance", "Theme and mode"],
];

/**
 * Everything a question carries, read once for whichever intent won.
 * One capture rather than one per intent: "where do I change start at
 * login" is a login question that still names a settings topic, and an
 * answer should not be blind to an argument just because another intent
 * claimed the sentence.
 */
export function captureArgs(question: string): Args {
  const args: Args = {};
  const ticket = question.match(ULID)?.[0];
  if (ticket) args.ticket = ticket;
  const capability = question.match(CAPABILITY)?.[1];
  if (capability) args.capability = capability;
  const repo = question.match(IN_REPO)?.[1];
  if (repo) args.repo = repo;
  const flow = question.match(RUN_FLOW)?.[1];
  if (flow) args.flow = flow;
  const topic = TOPICS.find(([pattern]) => pattern.test(question))?.[1];
  if (topic) args.topic = topic;
  return args;
}

// --- answers ---------------------------------------------------------------

async function approvalsWaiting(
  _args: Args,
  sources: Sources,
  ctx: AskContext,
): Promise<Answer> {
  const links = [{ label: "Open Approvals", to: "/approvals" as const }];
  try {
    const { pending } = await sources.approvalsPending();
    if (pending.length === 0) {
      return {
        intent: "approvals_waiting",
        sentence: "Nothing waits for you.",
        facts: [],
        links,
      };
    }
    const facts = pending
      .slice(0, 8)
      .map((hand): [string, string] => [
        hand.capability,
        `${hand.agent} · ${repoTail(hand.repo)} · ${ago(hand.requested_ts, ctx.now)}`,
      ]);
    return {
      intent: "approvals_waiting",
      sentence: `${plural(pending.length, "request")} wait${
        pending.length === 1 ? "s" : ""
      } for your hand.`,
      facts,
      links,
    };
  } catch (error) {
    return failedRead("approvals_waiting", "the approval queue", error);
  }
}

/** `detail` is JSON when policy wrote it, a bare string when it did not. */
function refusalDetail(detail: unknown): {
  cause?: string;
  detail?: string;
  recovery?: string;
} {
  if (typeof detail !== "object" || detail === null) return {};
  const shaped = detail as Record<string, unknown>;
  const read = (key: string) => (typeof shaped[key] === "string" ? shaped[key] : undefined);
  return { cause: read("cause"), detail: read("detail"), recovery: read("recovery") };
}

async function whyRefused(args: Args, sources: Sources, ctx: AskContext): Promise<Answer> {
  let row;
  try {
    const { requests } = await sources.activityList({
      state: "refused",
      limit: 20,
      ...(args.capability ? { capability: args.capability } : {}),
    });
    row = requests.find((candidate) => candidate.id === args.ticket) ?? requests[0];
  } catch (error) {
    return failedRead("why_refused", "the refusals", error);
  }
  if (!row) {
    return {
      intent: "why_refused",
      sentence: "I have refused nothing lately.",
      facts: [],
      links: [{ label: "Open Activity", to: "/activity", search: { state: "refused" } }],
    };
  }
  let audit: Awaited<ReturnType<Sources["auditRequest"]>>["rows"] = [];
  try {
    ({ rows: audit } = await sources.auditRequest(row.id));
  } catch {
    // The verdict is already in the request row; the audit only adds the
    // words, and a missing trail is not worth refusing the answer over.
  }
  const refusal =
    [...audit].reverse().find((entry) => entry.decision === "refuse") ??
    audit[audit.length - 1];
  const written = refusalDetail(refusal?.detail);
  const cause = written.cause ?? row.outcome ?? "refused";
  const detail = written.detail ?? "";
  const recovery = written.recovery ?? "";
  const links: Answer["links"] = [
    { label: "Open Activity", to: "/activity", search: { state: "refused" } },
  ];
  if (/grant|profile|approval/i.test(cause)) {
    links.push({ label: "Settings › Security", to: "/settings", hash: "security" });
  }
  return {
    intent: "why_refused",
    sentence:
      `I refused ${row.capability} from ${row.agent}: ${cause}` +
      `${detail ? ` — ${detail}` : ""}.${recovery ? ` ${recovery}` : ""}`,
    facts: [
      ["ticket", row.id],
      ["when", ago(refusal?.ts ?? row.created_ts, ctx.now)],
      ["cause", cause],
    ],
    links,
  };
}

/** Verdict buckets, in the order the sentence reads them. */
const VERDICTS = ["solved", "changed", "verified", "unresolved", "blocked"] as const;
const RUNNING_STATES = new Set(["queued", "running", "waiting_approval"]);

async function whatRan(args: Args, sources: Sources, ctx: AskContext): Promise<Answer> {
  const inRepo = args.repo ? ` in ${args.repo}` : "";
  const links: Answer["links"] = [
    {
      label: "Open Activity",
      to: "/activity",
      ...(args.repo ? { search: { repo: args.repo } } : {}),
    },
  ];
  let requests;
  try {
    ({ requests } = await sources.activityList({
      limit: 100,
      ...(args.repo ? { repo: args.repo } : {}),
    }));
  } catch (error) {
    return failedRead("what_ran", "today's activity", error);
  }
  const since = localMidnight(ctx.now);
  const rows = requests.filter((row) => row.created_ts * 1000 >= since);
  if (rows.length === 0) {
    return {
      intent: "what_ran",
      sentence: `Nothing has run today${inRepo}.`,
      facts: [],
      links,
    };
  }
  // Known verdicts keep their order; anything else the daemon reports
  // still gets counted, under its own name, after them — an unfamiliar
  // outcome is not a reason to under-count the day.
  const counts = new Map<string, number>();
  const bump = (key: string) => counts.set(key, (counts.get(key) ?? 0) + 1);
  for (const row of rows) {
    if (RUNNING_STATES.has(row.state)) bump("still running");
    else if (row.state === "refused") bump("refused");
    else if (row.state === "failed") bump("failed");
    else bump(row.outcome ?? row.state);
  }
  const order = [...VERDICTS, "refused", "failed", "still running"];
  const keys = [
    ...order.filter((key) => counts.has(key)),
    ...[...counts.keys()].filter((key) => !order.includes(key)),
  ];
  const parts = keys.map((key) => `${counts.get(key)} ${key}`);
  const capabilities = new Map<string, number>();
  for (const row of rows)
    capabilities.set(row.capability, (capabilities.get(row.capability) ?? 0) + 1);
  const facts: Array<[string, string]> = [...capabilities.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([capability, count]) => [capability, plural(count, "request")]);
  const agents = [...new Set(rows.map((row) => row.agent))];
  facts.push(["agents", agents.join(", ")]);
  return {
    intent: "what_ran",
    sentence: `Today ${plural(rows.length, "request")} ran${inRepo}: ${parts.join(", ")}.`,
    facts,
    links,
  };
}

async function modelStatus(_args: Args, sources: Sources, ctx: AskContext): Promise<Answer> {
  const links = [{ label: "Open Models", to: "/models" as const }];
  let status;
  try {
    status = await sources.modelsStatus();
  } catch (error) {
    return failedRead("model_status", "the model runtime", error);
  }
  const state = status.runtime.state;
  const { light, heavy } = status.defaults;
  const facts: Array<[string, string]> = [];
  if (state.quant) facts.push(["quant", state.quant]);
  if (state.device) facts.push(["device", state.device]);
  if (state.last_used_at) facts.push(["last used", ago(state.last_used_at, ctx.now)]);
  facts.push(["light default", light ?? "unset"]);
  facts.push(["heavy default", heavy ?? "unset"]);
  if (state.state === "loaded" && state.id) {
    return {
      intent: "model_status",
      sentence:
        `${state.id} is loaded on ${state.device ?? "cpu"}: ` +
        `${gb(state.weight_bytes ?? 0)} of ${gb(status.host_ram_bytes)} RAM, ` +
        `context ${state.context_length ?? 0}.`,
      facts,
      links,
    };
  }
  if (state.state === "loading" && state.id) {
    return {
      intent: "model_status",
      sentence: state.phase
        ? `${state.id} is loading (${state.phase}).`
        : `${state.id} is loading.`,
      facts,
      links,
    };
  }
  return {
    intent: "model_status",
    sentence: `No model is loaded; ${
      light ? `the light default is ${light}` : "no light default is set"
    }.`,
    facts,
    links,
  };
}

async function whereChange(
  args: Args,
  sources: Sources,
  _ctx: AskContext,
  question: string,
): Promise<Answer> {
  const matched =
    TOPICS.find(([pattern]) => pattern.test(question)) ??
    TOPICS.find(([, topic]) => topic === args.topic);
  if (!matched) {
    return {
      intent: "where_change",
      sentence:
        "Tell me which setting: retention, start at login, the approval profile, grants, " +
        "the models directory, connectors, flow programs, or the theme.",
      facts: [],
      links: [{ label: "Open Settings", to: "/settings" }],
    };
  }
  const [, topic, panel, subject] = matched;
  const facts: Array<[string, string]> = [];
  if (topic === "retention") {
    try {
      const windows = await sources.retentionGet();
      const days = (value: number | null) => (value === null ? "forever" : `${value} days`);
      facts.push(["evidence", days(windows.evidence_days)]);
      facts.push(["audit", days(windows.audit_days)]);
    } catch {
      // The panel is still where it lives; the current windows are a
      // nicety, not the answer.
    }
  }
  return {
    intent: "where_change",
    sentence: `${subject} lives in Settings › ${panel}.`,
    facts,
    links: [{ label: `Settings › ${panel}`, to: "/settings", hash: topic }],
  };
}

async function daemonStatus(_args: Args, sources: Sources): Promise<Answer> {
  const links = [{ label: "Settings › Daemon", to: "/settings" as const, hash: "daemon" }];
  let health;
  try {
    health = await sources.daemonStatus();
  } catch (error) {
    return failedRead("daemon_status", "the daemon", error);
  }
  if (!health.connected || !health.status) {
    return {
      intent: "daemon_status",
      sentence: "The daemon is not answering; the next question starts it.",
      facts: [],
      links,
    };
  }
  const status = health.status;
  const text = (key: string, fallback: string) =>
    typeof status[key] === "string" ? (status[key] as string) : fallback;
  const count = (key: string) =>
    typeof status[key] === "number" ? (status[key] as number) : 0;
  const version = text("daemon_version", "unknown");
  const uptime = count("uptime_s");
  const active = count("active_requests");
  return {
    intent: "daemon_status",
    sentence: `The daemon answers: version ${version}, up for ${duration(uptime)}, ${plural(
      active,
      "active request",
    )}.`,
    facts: [
      ["version", version],
      ["uptime", duration(uptime)],
      ["active", String(active)],
    ],
    links,
  };
}

async function loginStart(_args: Args, sources: Sources): Promise<Answer> {
  const links = [{ label: "Settings › Daemon", to: "/settings" as const, hash: "daemon" }];
  let service;
  try {
    service = await sources.serviceStatus();
  } catch (error) {
    return failedRead("login_start", "the login unit", error);
  }
  const state = service.state;
  if (state.kind === "unsupported") {
    return {
      intent: "login_start",
      sentence: `Not here: ${state.reason}.`,
      facts: [],
      links,
    };
  }
  const facts: Array<[string, string]> = [["unit", state.unit]];
  if (state.kind === "not_installed") {
    return {
      intent: "login_start",
      sentence: "No: nothing starts me at login.",
      facts,
      links,
    };
  }
  return {
    intent: "login_start",
    sentence: `Yes: the ${service.platform} unit is installed${
      state.loaded ? " and loaded" : " but not loaded"
    }.`,
    facts,
    links,
  };
}

async function flows(args: Args, sources: Sources): Promise<Answer> {
  if (args.flow) {
    return {
      intent: "flows",
      sentence: `I do not run flows from here; open ${args.flow} on the Flows screen.`,
      facts: [["flow", args.flow]],
      links: [{ label: "Open Flows", to: "/flows", search: { flow: args.flow } }],
    };
  }
  const links = [{ label: "Open Flows", to: "/flows" as const }];
  let list;
  try {
    ({ flows: list } = await sources.flowsList());
  } catch (error) {
    return failedRead("flows", "your flows", error);
  }
  if (list.length === 0) {
    return { intent: "flows", sentence: "You have no flows yet.", facts: [], links };
  }
  const named = list.map((flow) => (flow.valid ? flow.id : `${flow.id} (invalid)`));
  return {
    intent: "flows",
    sentence: `You have ${plural(list.length, "flow")}: ${named.join(", ")}.`,
    facts: list.map((flow): [string, string] => [flow.id, flow.name]),
    links,
  };
}

async function tokensSaved(_args: Args, sources: Sources, ctx: AskContext): Promise<Answer> {
  const links = [{ label: "Open Activity", to: "/activity" as const }];
  let stats;
  try {
    stats = await sources.evidenceStats(Math.floor(ctx.now / 1000) - 7 * 86_400);
  } catch (error) {
    return failedRead("tokens_saved", "the compression odometer", error);
  }
  if (stats.compressions === 0) {
    return {
      intent: "tokens_saved",
      sentence: "Nothing has been compressed this week.",
      facts: [],
      links,
    };
  }
  return {
    intent: "tokens_saved",
    sentence:
      `This week I avoided about ${stats.tokens_avoided_est.toLocaleString("en-US")} tokens ` +
      `across ${plural(stats.compressions, "compression")} ` +
      `(${kb(stats.source_bytes)} → ${kb(stats.compact_bytes)}).`,
    facts: [
      ["tokens", stats.tokens_avoided_est.toLocaleString("en-US")],
      ["compressions", String(stats.compressions)],
      ["bytes", `${kb(stats.source_bytes)} → ${kb(stats.compact_bytes)}`],
    ],
    links,
  };
}

/** The honest answer: what Pam does know, so the next question lands. */
export async function fallbackAnswer(): Promise<Answer> {
  return Promise.resolve({
    intent: "fallback",
    sentence:
      "I can answer about pam itself: approvals, refusals, today's activity, the model, " +
      "settings, the daemon, login, flows, tokens saved.",
    facts: [],
    links: [],
  });
}

// --- the table -------------------------------------------------------------

/** The spec's reading order — what the Home pills show. */
export const SPEC_ORDER: Intent[] = [
  {
    id: "approvals_waiting",
    label: "waiting for me",
    canonical: "what's waiting for my approval?",
    patterns: [/approv/i, /waiting for (me|my)/i, /pending/i, /raised hand/i],
    answer: approvalsWaiting,
  },
  {
    id: "why_refused",
    label: "why refused",
    canonical: "why was that refused?",
    patterns: [/refus/i, /denied/i, /why (did|was).*(not|n't|never)/i],
    answer: whyRefused,
  },
  {
    id: "what_ran",
    label: "what ran today",
    canonical: "what ran today?",
    patterns: [
      /what (ran|happened|did)/i,
      /today/i,
      /recent/i,
      /this (morning|afternoon|week)/i,
    ],
    answer: whatRan,
  },
  {
    id: "model_status",
    label: "the model",
    canonical: "which model is loaded?",
    patterns: [/model/i, /loaded/i, /memory/i, /\bram\b/i, /\bgpu\b/i, /metal/i],
    answer: modelStatus,
  },
  {
    id: "where_change",
    label: "where do I change",
    canonical: "where do I change log retention?",
    patterns: [
      /where (do|can|would) i/i,
      /how do i (change|set|turn|switch)/i,
      /setting/i,
      /where is/i,
    ],
    answer: whereChange,
  },
  {
    id: "daemon_status",
    label: "the daemon",
    canonical: "is the daemon running?",
    patterns: [/daemon/i, /running/i, /uptime/i, /alive/i, /status/i, /version/i],
    answer: daemonStatus,
  },
  {
    id: "login_start",
    label: "start at login",
    canonical: "does pam start at login?",
    patterns: [/login/i, /startup/i, /boot/i, /start at/i],
    answer: loginStart,
  },
  {
    id: "flows",
    label: "my flows",
    canonical: "which flows do I have?",
    patterns: [/flow/i, RUN_FLOW],
    answer: flows,
  },
  {
    id: "tokens_saved",
    label: "tokens saved",
    canonical: "how many tokens did I save?",
    patterns: [/token/i, /saved/i, /compress/i, /odometer/i],
    answer: tokensSaved,
  },
];

/**
 * Matching order. Narrow questions go first so a broad pattern cannot
 * steal them: a refusal is a refusal even when it says "today", and
 * "start at login" is about login even when it says "daemon".
 */
const MATCH_IDS: IntentId[] = [
  "why_refused",
  "tokens_saved",
  "login_start",
  "where_change",
  "what_ran",
  "approvals_waiting",
  "model_status",
  "daemon_status",
  "flows",
];

const BY_ID = new Map(SPEC_ORDER.map((intent) => [intent.id, intent]));

export const MATCH_ORDER: Intent[] = MATCH_IDS.map((id) => {
  const intent = BY_ID.get(id);
  if (!intent) throw new Error(`unknown intent in match order: ${id}`);
  return intent;
});

/** The answer function for an id; `fallback` when nothing matched. */
export function answerFor(id: IntentId): AnswerFn {
  return BY_ID.get(id)?.answer ?? fallbackAnswer;
}
