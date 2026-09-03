/**
 * The optional rephrase.
 *
 * Off by default. When the preference is on and a light default model is
 * set, the template sentence is handed to that model for one warmer line
 * — and the rewrite is accepted only if it is a single line that still
 * carries every fact value and every number the template had. Anything
 * else (a refusal, a timeout, a second sentence, a dropped number) keeps
 * the template. The model may reword Pam; it may never change what she
 * said.
 */

import type { Answer, AskOptions } from "./answer";
import type { Sources } from "./sources";

const DEFAULT_TIMEOUT_MS = 8_000;
/** One sentence, so a small budget is plenty and a runaway is cheap. */
const MAX_TOKENS = 96;

/** Resolves to `""` after `ms`, and cleans up its own timer. */
function empty(ms: number): { race: Promise<string>; cancel: () => void } {
  let handle: ReturnType<typeof setTimeout> | undefined;
  const race = new Promise<string>((resolve) => {
    handle = setTimeout(() => resolve(""), ms);
  });
  return { race, cancel: () => clearTimeout(handle) };
}

export async function maybeRephrase(
  answer: Answer,
  sources: Sources,
  options: AskOptions,
): Promise<Answer> {
  if (!options.rephrase || answer.intent === "fallback") return answer;
  const status = await sources.modelsStatus().catch(() => null);
  const model = status?.defaults.light ?? null;
  if (!model) return answer;
  const prompt =
    "Rewrite in one sentence, first person, warm and plain, keeping every number and " +
    `name exactly as written: ${answer.sentence}`;
  const timer = empty(options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  const reply = await Promise.race([
    sources
      .modelsTry(prompt, MAX_TOKENS)
      .then((result) => result.text)
      .catch(() => ""),
    timer.race,
  ]);
  timer.cancel();
  const line = reply.trim();
  if (!line || line.includes("\n")) return answer;
  const values = answer.facts
    .map(([, value]) => value)
    .filter((value) => answer.sentence.includes(value));
  const numbers = answer.sentence.match(/\d[\d,.]*/g) ?? [];
  if (![...values, ...numbers].every((needle) => line.includes(needle))) return answer;
  return { ...answer, sentence: line, rephrased: { model } };
}
