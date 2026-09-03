/**
 * Ask Pam's router: a question in, an answer out.
 *
 * Deterministic on purpose. The intent table decides what a question is
 * about, the sources answer it from live daemon state, and the model — if
 * the owner turned it on — only ever gets to reword the finished
 * sentence. Nothing here runs, approves, or writes anything.
 */

import type { Answer, Args, AskContext, AskOptions, IntentId } from "./answer";
import { answerFor, captureArgs, MATCH_ORDER, SPEC_ORDER } from "./intents";
import { maybeRephrase } from "./rephrase";
import type { Sources } from "./sources";

export type {
  Answer,
  Args,
  AskContext,
  AskLink,
  AskOptions,
  AskRoute,
  IntentId,
  SettingsTopic,
} from "./answer";
export type { Sources } from "./sources";

/** The first intent whose patterns fit wins; nothing fitting is honest. */
export function matchIntent(question: string): { id: IntentId; args: Args } {
  const q = question.trim();
  if (!q) return { id: "fallback", args: {} };
  for (const intent of MATCH_ORDER) {
    if (intent.patterns.some((pattern) => pattern.test(q))) {
      return { id: intent.id, args: captureArgs(q) };
    }
  }
  return { id: "fallback", args: {} };
}

/**
 * Answer `question` from live state. Never throws: a source that fails
 * becomes a sentence naming what could not be read.
 */
export async function ask(
  question: string,
  ctx: AskContext,
  sources: Sources,
  options: AskOptions,
): Promise<Answer> {
  const { id, args } = matchIntent(question);
  const answer = await answerFor(id)(args, sources, ctx, question.trim());
  return maybeRephrase(answer, sources, options);
}

/** The pills, in the spec's reading order — the fallback is not one. */
export const INTENTS: ReadonlyArray<{ id: IntentId; label: string; canonical: string }> =
  SPEC_ORDER.map(({ id, label, canonical }) => ({ id, label, canonical }));
