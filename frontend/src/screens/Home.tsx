import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { ArrowUpRight, MessageSquare } from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { PageHeader } from "../components/ui/PageHeader";
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
  const suggestions = useRef<HTMLDetailsElement>(null);

  const connected = status.data?.connected === true;
  const hands = pending.data?.pending.length ?? 0;
  const activeRequests = status.data?.status?.active_requests;
  const greeting = pending.isPending
    ? "Checking approvals…"
    : pending.isError
      ? "Approval queue unavailable."
      : hands === 0
        ? "No requests need your approval."
        : `${countWord(hands)} request${hands === 1 ? "" : "s"} awaiting your approval.`;

  const submit = (text: string) => {
    const asked = text.trim();
    if (asked === "" || asking) return;
    if (suggestions.current) suggestions.current.open = false;
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
    <div className="page-workspace home-workspace">
      <PageHeader>
        <h1 className="font-sans text-title font-semibold text-ink">Home</h1>
        <p className="text-sm text-ink-muted">
          {greetingWord}. Ask about your local workspace.
        </p>
      </PageHeader>
      <div className="page-content" role="region" aria-label="Home content" tabIndex={0}>
        <div className="home-conversation space-y-5">
          <aside
            className="home-status border-b border-line text-sm"
            aria-label="Workspace overview"
          >
            <Link
              to="/approvals"
              className="rounded-control font-medium text-ink hover:text-accent"
            >
              {greeting}
            </Link>
            <Link to="/activity" className="rounded-control text-ink-muted hover:text-ink">
              Active requests:{" "}
              {connected && typeof activeRequests === "number" ? activeRequests : "Unavailable"}
            </Link>
          </aside>
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
              <form
                aria-label="Ask PAM"
                className="flex items-center gap-2"
                onSubmit={(event) => {
                  event.preventDefault();
                  submit(question);
                }}
              >
                <input
                  id="ask-pam"
                  aria-label="ask pam"
                  aria-describedby="ask-pam-help"
                  value={question}
                  disabled={asking}
                  placeholder="Ask about requests, models, or settings"
                  onChange={(event) => setQuestion(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Escape") setQuestion("");
                  }}
                  className="field-control h-8 min-w-0 flex-1 rounded-control border border-control-line bg-inset px-3 font-sans text-sm text-ink placeholder:text-ink-faint disabled:opacity-50"
                />
                <Button
                  type="submit"
                  disabled={asking || question.trim() === ""}
                  aria-busy={asking}
                >
                  Ask <ArrowUpRight aria-hidden="true" className="size-4" />
                </Button>
              </form>
              <p id="ask-pam-help" className="text-xs text-ink-muted">
                Ask about PAM itself. I keep only this screen and the last three exchanges.
              </p>
            </div>
            <details ref={suggestions} className="border-t border-line px-5 py-3">
              <summary className="cursor-pointer rounded-control text-sm font-medium text-ink-muted">
                Suggested questions
              </summary>
              <div className="home-prompts mt-2 grid gap-x-5">
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
            </details>
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

          <section aria-labelledby="recent-heading" className="space-y-4">
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
                    Ask a question or choose a suggestion above. Each answer includes its
                    supporting facts and a way to the relevant screen.
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
      </div>
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
        <dl className="home-answer-facts grid gap-x-6 gap-y-3">
          {answer.facts.map(([label, value], index) => (
            <div key={`${label}-${index}`} className="min-w-0 space-y-0.5">
              <dt className="font-data text-xs text-ink-faint">{label}</dt>
              <dd className="break-words font-data text-sm text-ink tabular-nums" title={value}>
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
