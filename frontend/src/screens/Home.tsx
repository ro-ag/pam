import { useQuery } from "@tanstack/react-query";
import { useNavigate, useRouterState } from "@tanstack/react-router";
import { useMemo, useRef, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { liveSources } from "../lib/ask/live";
import { useRephrasePref } from "../lib/ask/prefs";
import { INTENTS, ask, type Answer, type AskLink } from "../lib/ask/router";
import { approvalsPending, daemonStatus, modelsStatus, toBridgeFailure } from "../lib/ipc";
import type { BridgeFailure } from "../lib/ipc";

/**
 * Home — the self-aware composer. Pam's own screen: a greeting that reads
 * the water, one question box, the nine things she can answer as pills,
 * and the last three exchanges.
 *
 * Every answer comes from `lib/ask` over live daemon state. The router is
 * deterministic and read-only — it never runs a flow, resolves an
 * approval, or writes a setting — so the worst a question can do here is
 * be answered honestly with "I could not read that". A model touches an
 * answer only when the owner turned the rephrase switch on in Settings ›
 * Models, and then only to reword a sentence Pam already wrote.
 *
 * Memory is deliberately short and stated in the placeholder: this screen
 * and the last three exchanges, in React state, gone on unmount. Nothing
 * is persisted, so nothing has to be forgotten.
 */

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
  const greeting = !connected
    ? "The daemon is not answering; the next question starts it."
    : pending.isError
      ? "I cannot see the approval queue right now."
      : hands === 0
        ? "The water is calm: nothing waits for you."
        : `${countWord(hands)} request${hands === 1 ? "" : "s"} wait${
            hands === 1 ? "s" : ""
          } for your hand.`;

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
    <div className="flex min-h-full flex-col px-8 pb-10">
      <header className="space-y-3 pt-8 pb-3">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          home · ask pam
        </p>
        <h1 className="font-display text-title font-semibold text-ink">{greetingWord}</h1>
        <p className="font-voice text-lg text-ink-muted italic">{greeting}</p>
      </header>

      <Panel ground="raised" className="space-y-3 p-5">
        <div className="flex items-center gap-3">
          <input
            aria-label="ask pam"
            value={question}
            disabled={asking}
            placeholder="Ask about pam itself — I keep only this screen and the last three exchanges"
            onChange={(event) => setQuestion(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") submit(question);
              if (event.key === "Escape") setQuestion("");
            }}
            className="h-10 min-w-0 flex-1 rounded-control border border-line bg-surface px-3 font-voice text-base text-ink italic placeholder:text-ink-faint disabled:opacity-50"
          />
          <Button variant="ghost" disabled={asking} onClick={() => submit(question)}>
            Ask
          </Button>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {INTENTS.map((intent) => (
            <Button
              key={intent.id}
              size="sm"
              variant="ghost"
              disabled={asking}
              aria-label={`ask: ${intent.canonical}`}
              onClick={() => submit(intent.canonical)}
            >
              {intent.label}
            </Button>
          ))}
        </div>

        {rephrase && models.data?.defaults.light === null && (
          <div className="flex flex-wrap items-center gap-3 border-t border-line pt-3">
            <p className="min-w-0 flex-1 font-voice text-sm text-ink-muted italic">
              answers stay in my own words: no light model is set
            </p>
            <Button size="sm" variant="ghost" onClick={() => void navigate({ to: "/models" })}>
              Open Models
            </Button>
          </div>
        )}
      </Panel>

      <ol aria-label="exchanges" className="space-y-4 pt-6">
        {exchanges.map((exchange) => (
          <li key={exchange.id} className="space-y-2">
            <p className="font-data text-xs text-ink-faint">{exchange.question}</p>
            {exchange.failure ? (
              <FailureNote failure={exchange.failure} label="ask pam" />
            ) : exchange.answer === null ? (
              <p className="font-data text-xs text-ink-muted">thinking…</p>
            ) : (
              <AnswerCard answer={exchange.answer} onFollow={go} />
            )}
          </li>
        ))}
      </ol>
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
      <p className="font-voice text-base text-ink italic">{answer.sentence}</p>

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
            <Button
              key={link.label}
              size="sm"
              variant="ghost"
              onClick={() => onFollow(link)}
            >
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
