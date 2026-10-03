/**
 * The optional rephrase.
 *
 * Off by default. When the preference is on and a light default model is
 * set, the template sentence is handed to that model for one warmer line.
 * The rewrite is a *field*, not a channel: it is accepted only when it has
 * the shape of the template it replaces ({@link rephraseRefusal}) — one
 * line of plain text, bounded in length, no more sentences than the
 * template, no markup, links or addresses the template did not already
 * contain — and it still carries every fact value and every number the
 * template had. Anything else (a refusal, a timeout, a preamble, an added
 * link, a dropped number) keeps the template. The model may reword Pam; it
 * may never change what she said, and a model that was handed text an agent
 * influenced cannot use the answer line to say something else.
 */

import { hasHiddenCharacters } from "../safeText";
import type { Answer, AskOptions } from "./answer";
import type { Sources } from "./sources";

const DEFAULT_TIMEOUT_MS = 8_000;
/** One sentence, so a small budget is plenty and a runaway is cheap. */
const MAX_TOKENS = 96;

/** The most a rephrased line may run to, whatever the template's length. */
const MAX_LINE_CHARS = 600;

/** A rewrite may be this much longer than the template, plus a fixed allowance for warmth. */
const LENGTH_FACTOR = 2;
const LENGTH_ALLOWANCE = 40;

/** Characters that make text markup, structure or a code/data wrapper rather than a sentence. */
const MARKUP_CHARS = new Set("`*_#[]{}<>|~\\");

/**
 * What can carry a reader somewhere else: a scheme (`https://`), `www.`, `mailto:`, an e-mail
 * address, a markdown link's `](`, or a dotted name that is not a number (`example.com`,
 * `evil.io/x`). Template text such as a capability (`repo.push`) is allowed because it is
 * compared with the template, not forbidden outright.
 */
const REACH =
  /(?:[a-z][a-z0-9+.-]*:\/\/|\bwww\.|\bmailto:|[\w.+-]+@[\w-]+\.[\w.-]+|\]\(|\b[\w-]+(?:\.[\w-]+)*\.[a-z][a-z0-9-]+\b)/gi;

/** A list bullet, a numbered item or a heading at the start: structure, not a sentence. */
const STRUCTURE = /^\s*(?:[-+•]\s|\d+[.)]\s|#)/;

/** Where one sentence ends and another begins: a terminator, whitespace, more text. */
function sentenceBreaks(text: string): number {
  return (text.match(/[.!?]+(?=\s+\S)/g) ?? []).length;
}

function count(text: string, char: string): number {
  return text.split(char).length - 1;
}

/**
 * Why `line` may not replace `template`, or `null` when it may. Public so the shape rule is
 * testable on its own. The line is already trimmed.
 */
export function rephraseRefusal(line: string, template: string): string | null {
  if (!line) return "empty";
  if (hasHiddenCharacters(line)) return "not one plain line";
  const limit = Math.min(MAX_LINE_CHARS, template.length * LENGTH_FACTOR + LENGTH_ALLOWANCE);
  if (line.length > limit) return "too long";
  if (STRUCTURE.test(line)) return "list or heading";
  for (const char of MARKUP_CHARS) {
    if (count(line, char) > count(template, char)) return "markup";
  }
  const known = new Set(template.match(REACH) ?? []);
  for (const found of line.match(REACH) ?? []) {
    if (!known.has(found)) return "link or address";
  }
  if (sentenceBreaks(line) > sentenceBreaks(template)) return "more than the one field";
  return null;
}

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
  if (
    !model ||
    status?.runtime.busy ||
    status?.runtime.state.state !== "loaded" ||
    status.runtime.state.id !== model
  )
    return answer;
  const prompt =
    "Rewrite in one sentence, first person, warm and plain, keeping every number and " +
    `name exactly as written: ${answer.sentence}`;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const timer = empty(timeoutMs);
  const reply = await Promise.race([
    sources
      .modelsTry(model, prompt, MAX_TOKENS, timeoutMs)
      .then((result) => (result.model?.id === model ? result.text : ""))
      .catch(() => ""),
    timer.race,
  ]);
  timer.cancel();
  const line = typeof reply === "string" ? reply.trim() : "";
  if (rephraseRefusal(line, answer.sentence) !== null) return answer;
  const values = answer.facts
    .map(([, value]) => value)
    .filter((value) => answer.sentence.includes(value));
  const numbers = answer.sentence.match(/\d[\d,.]*/g) ?? [];
  if (![...values, ...numbers].every((needle) => line.includes(needle))) return answer;
  return { ...answer, sentence: line, rephrased: { model } };
}
