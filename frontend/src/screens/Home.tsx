import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import {
  Activity,
  ArrowUpRight,
  ChevronRight,
  Cpu,
  Hand,
  MessageSquare,
  Server,
  Workflow,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { liveSources } from "../lib/ask/live";
import { useRephrasePref } from "../lib/ask/prefs";
import { INTENTS, ask, type Answer, type AskLink } from "../lib/ask/router";
import { approvalsPending, daemonStatus, modelsStatus, toBridgeFailure } from "../lib/ipc";
import type { BridgeFailure } from "../lib/ipc";

/** Read-only answers from live daemon state, with a three-exchange session history. */
const PROMPT_LABELS: Record<string, string> = {
  approvals_waiting: "Pending approvals",
  why_refused: "Explain a refusal",
  what_ran: "Today's activity",
  model_status: "Loaded model",
  where_change: "Find a setting",
  daemon_status: "Daemon status",
  login_start: "Start at login",
  flows: "Available flows",
  tokens_saved: "Tokens saved",
};
const WORKSPACE_LINKS = [
  {
    to: "/approvals",
    label: "Review approvals",
    detail: "Decide what agents may do",
    icon: Hand,
  },
  {
    to: "/activity",
    label: "Inspect activity",
    detail: "Requests, results and evidence",
    icon: Activity,
  },
  {
    to: "/flows",
    label: "Browse flows",
    detail: "Build and run reusable workflows",
    icon: Workflow,
  },
  { to: "/models", label: "Manage models", detail: "Local weights and runtime", icon: Cpu },
] as const;

/** How many exchanges Pam keeps — the number the placeholder promises. */
export const MEMORY_DEPTH = 3;

/** Small counts read as words in Pam's voice; big ones stay numerals. */
const COUNT_WORDS = [
  "No",
  "One",
  "Two",
  "Three",
  "Four",
  "Five",
  "Six",
  "Seven",
  "Eight",
  "Nine",
] as const;

/** `One`, `Two`, … `12` — the greeting counts hands, it does not tally. */
export function countWord(n: number): string {
  return COUNT_WORDS[n] ?? String(n);
}

/** The display word over the greeting; local clock, no timezone games. */
export function partOfDay(nowMs: number): string {
  const hour = new Date(nowMs).getHours();
  if (hour < 12) return "Good morning";
  if (hour < 18) return "Good afternoon";
  return "Good evening";
}

/** One question and what came back; `answer === null` means still asking. */
interface Exchange {
  id: number;
  question: string;
  answer: Answer | null;
  failure: BridgeFailure | null;
}

export function HomeScreen() {
  const status = useQuery({
    queryKey: ["daemon", "status"],
    queryFn: daemonStatus,
    refetchInterval: 5_000,
  });
  const pending = useQuery({
    queryKey: ["approvals", "pending"],
    queryFn: approvalsPending,
    refetchInterval: 5_000,
  });
  const [rephrase] = useRephrasePref();
  // Only read when the switch is on: the model line is the only thing on
  // this screen that needs it, and an off switch should cost nothing.
  const models = useQuery({
    queryKey: ["models", "status"],
    queryFn: modelsStatus,
    enabled: rephrase,
  });

  const pathname = useRouterState({ select: (state) => state.location.pathname });
  const navigate = useNavigate();
  const sources = useMemo(liveSources, []);

  const [greetingWord] = useState(() => partOfDay(Date.now()));
  const [question, setQuestion] = useState("");
  const [exchanges, setExchanges] = useState<Exchange[]>([]);
  const [asking, setAsking] = useState(false);
  const nextId = useRef(0);

  const connected = status.data?.connected === true;
  const hands = pending.data?.pending.length ?? 0;
  const activeRequests = status.data?.status?.active_requests;
  const greeting = !connected
    ? "The daemon is not answering; the next question starts it."
    : pending.isError
      ? "I cannot see the approval queue right now."
      : hands === 0
        ? "No requests need your approval."
        : `${countWord(hands)} request${hands === 1 ? "" : "s"} awaiting your approval.`;

  const submit = (text: string) => {
    const asked = text.trim();
    if (asked === "" || asking) return;
    setAsking(true);
    setQuestion("");
    const id = nextId.current++;
    setExchanges((prev) =>
      [{ id, question: asked, answer: null, failure: null }, ...prev].slice(0, MEMORY_DEPTH),
    );
    const settle = (patch: Partial<Exchange>) =>
      setExchanges((prev) =>
        prev.map((exchange) => (exchange.id === id ? { ...exchange, ...patch } : exchange)),
      );
    void ask(asked, { screen: pathname, now: Date.now() }, sources, { rephrase })
      // `ask` answers a failed read in Pam's voice rather than throwing;
      // this catch is for the impossible one, which still gets the
      // uniform refusal shape instead of a blank card.
      .then((answer) => settle({ answer }))
      .catch((error: unknown) => settle({ failure: toBridgeFailure(error) }))
      .finally(() => setAsking(false));
  };

  const go = (link: AskLink) =>
    void navigate({
      to: link.to,
      ...(link.search === undefined ? {} : { search: link.search }),
      ...(link.hash === undefined ? {} : { hash: link.hash }),
    } as Parameters<typeof navigate>[0]);

  return (
    <div className="home-workspace flex min-h-full flex-col px-6 pb-6">
      <header className="flex flex-wrap items-end justify-between gap-3 border-b border-line py-6">
        <div className="space-y-1">
          <h1 className="font-sans text-title font-semibold text-ink">Home</h1>
          <p className="text-sm text-ink-muted">
            {greetingWord}. Your local workspace at a glance.
          </p>
        </div>
        <span className="rounded-badge border border-line px-2 py-1 text-xs text-ink-muted">
          Overview
        </span>
      </header>

      <div className="home-columns grid items-start gap-5 py-6">
        <Panel ground="command" className="min-w-0 overflow-hidden" aria-busy={asking}>
          <div className="space-y-4 p-5">
            <div className="flex items-center gap-3">
              <span className="warm-badge flex size-10 shrink-0 items-center justify-center rounded-card">
                <MessageSquare aria-hidden="true" className="size-5" />
              </span>
              <div>
                <h2 className="text-lg font-semibold">
                  <label htmlFor="ask-pam">Ask PAM</label>
                </h2>
                <p className="text-xs text-ink-muted">Answers from your machine</p>
              </div>
            </div>
            <p className="text-sm font-medium">What would you like to know?</p>
            <div className="flex items-center gap-2">
              <input
                id="ask-pam"
                aria-label="ask pam"
                aria-describedby="ask-pam-help"
                value={question}
                disabled={asking}
                placeholder="Ask about requests, models, or settings"
                onChange={(event) => setQuestion(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") submit(question);
                  if (event.key === "Escape") setQuestion("");
                }}
                className="field-control h-8 min-w-0 flex-1 rounded-control border border-control-line bg-inset px-3 font-sans text-sm text-ink placeholder:text-ink-faint disabled:opacity-50"
              />
              <Button
                disabled={asking || question.trim() === ""}
                aria-busy={asking}
                onClick={() => submit(question)}
              >
                Ask <ArrowUpRight aria-hidden="true" className="size-4" />
              </Button>
            </div>
            <p id="ask-pam-help" className="text-xs text-ink-muted">
              Ask about PAM itself. I keep only this screen and the last three exchanges.
            </p>
          </div>
          <div className="border-t border-line px-5 py-4">
            <p className="mb-2 text-xs font-medium text-ink-muted">Suggested questions</p>
            <div className="home-prompts grid gap-x-5">
              {INTENTS.map((intent) => (
                <button
                  key={intent.id}
                  type="button"
                  disabled={asking}
                  aria-label={`ask: ${intent.canonical}`}
                  onClick={() => submit(intent.canonical)}
                  className="flex min-h-9 items-center justify-between gap-2 rounded-control px-2 py-2 text-left text-sm text-ink transition-colors hover:bg-accent-soft disabled:opacity-50"
                >
                  <span>{PROMPT_LABELS[intent.id] ?? intent.label}</span>
                  <ArrowUpRight
                    aria-hidden="true"
                    className="size-3.5 shrink-0 text-ink-muted"
                  />
                </button>
              ))}
            </div>
          </div>
          {rephrase && models.data?.defaults.light === null && (
            <div className="flex flex-wrap items-center gap-3 border-t border-line px-5 py-3">
              <p className="min-w-0 flex-1 text-xs text-ink-muted">
                answers stay in my own words: no light model is set
              </p>
              <Button
                size="sm"
                variant="secondary"
                onClick={() => void navigate({ to: "/models" })}
              >
                Open Models
              </Button>
            </div>
          )}
        </Panel>

        <aside className="min-w-0 space-y-5" aria-label="Workspace overview">
          <section
            className="overflow-hidden rounded-panel border border-line bg-surface"
            aria-labelledby="system-heading"
          >
            <div className="border-b border-line px-4 py-3">
              <h2 id="system-heading" className="text-lg font-semibold">
                Current state
              </h2>
              <p className="mt-1 text-xs text-ink-muted">{greeting}</p>
            </div>
            <dl className="divide-y divide-line px-4">
              <div className="flex min-h-10 items-center justify-between gap-3 py-2">
                <dt className="flex items-center gap-2 text-ink-muted">
                  <Server aria-hidden="true" className="size-4" />
                  Daemon
                </dt>
                <dd className="font-medium">
                  {status.isPending ? "Connecting…" : connected ? "Connected" : "Offline"}
                </dd>
              </div>
              <div className="flex min-h-10 items-center justify-between gap-3 py-2">
                <dt className="text-ink-muted">Active requests</dt>
                <dd className="font-data text-xs tabular-nums">
                  {connected && typeof activeRequests === "number"
                    ? activeRequests
                    : "Unavailable"}
                </dd>
              </div>
              <div className="flex min-h-10 items-center justify-between gap-3 py-2">
                <dt className="text-ink-muted">Awaiting approval</dt>
                <dd className="font-data text-xs tabular-nums">
                  {pending.isPending ? "Loading…" : pending.isError ? "Unavailable" : hands}
                </dd>
              </div>
            </dl>
          </section>
          <section aria-labelledby="workspace-heading">
            <h2 id="workspace-heading" className="mb-2 text-sm font-semibold">
              Open workspace
            </h2>
            <div className="divide-y divide-line border-y border-line">
              {WORKSPACE_LINKS.map(({ to, label, detail, icon: Icon }) => (
                <Link
                  key={to}
                  to={to}
                  className="flex items-center gap-3 rounded-control px-2 py-3 transition-colors hover:bg-accent-soft"
                >
                  <Icon aria-hidden="true" className="size-4 shrink-0 text-ink-muted" />
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium">{label}</span>
                    <span className="block text-xs text-ink-muted">{detail}</span>
                  </span>
                  <ChevronRight
                    aria-hidden="true"
                    className="size-3.5 shrink-0 text-ink-muted"
                  />
                </Link>
              ))}
            </div>
          </section>
        </aside>
      </div>

      <section aria-labelledby="recent-heading" className="border-t border-line pt-5">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-2">
          <h2 id="recent-heading" className="text-lg font-semibold">
            Recent exchanges
          </h2>
          <span className="text-xs text-ink-muted">
            This session · up to {MEMORY_DEPTH} exchanges
          </span>
        </div>
        {exchanges.length === 0 && (
          <div className="flex items-start gap-3 rounded-panel border border-line bg-inset p-5">
            <MessageSquare
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-ink-muted"
            />
            <div>
              <p className="font-medium">Your answers will appear here</p>
              <p className="mt-1 text-xs text-ink-muted">
                Ask a question or choose a suggestion above. Each answer includes its supporting
                facts and a way to the relevant screen.
              </p>
            </div>
          </div>
        )}
        <ol
          aria-label="exchanges"
          aria-live="polite"
          aria-relevant="additions text"
          className="space-y-4"
        >
          {exchanges.map((exchange) => (
            <li key={exchange.id} className="space-y-2">
              <p className="text-sm font-medium text-ink-muted">{exchange.question}</p>
              {exchange.failure ? (
                <FailureNote failure={exchange.failure} label="ask pam" />
              ) : exchange.answer === null ? (
                <p className="text-sm text-ink-muted">thinking…</p>
              ) : (
                <AnswerCard answer={exchange.answer} onFollow={go} />
              )}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}

/** One answer: the sentence, the facts it was built from, the way there. */
function AnswerCard({
  answer,
  onFollow,
}: {
  answer: Answer;
  onFollow: (link: AskLink) => void;
}) {
  return (
    <Panel ground="raised" className="space-y-4 p-5">
      <p className="font-sans text-sm text-ink">{answer.sentence}</p>

      {answer.facts.length > 0 && (
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
          {answer.facts.map(([label, value]) => (
            <div key={label} className="min-w-0 space-y-0.5">
              <dt className="font-data text-xs text-ink-faint">{label}</dt>
              <dd className="truncate font-data text-sm text-ink tabular-nums" title={value}>
                {value}
              </dd>
            </div>
          ))}
        </dl>
      )}

      {(answer.links.length > 0 || answer.rephrased) && (
        <div className="flex flex-wrap items-center gap-3 border-t border-line pt-4">
          {answer.links.map((link) => (
            <Button key={link.label} size="sm" variant="ghost" onClick={() => onFollow(link)}>
              {link.label}
            </Button>
          ))}
          {answer.rephrased && (
            <p className="ml-auto font-data text-xs text-ink-faint">
              rephrased by {answer.rephrased.model}
            </p>
          )}
        </div>
      )}
    </Panel>
  );
}
