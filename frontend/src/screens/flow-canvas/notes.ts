import type { RunStatus } from "./graph";

/**
 * The daemon narrates a flow run through progress notes; two of them name
 * a step: `"<step>: running (i/n)"` as it starts and `"<step>: <status>"`
 * as it settles, with the same status word the verdict body uses. Every
 * other note (queue position, summaries) says nothing about a step and
 * is ignored here.
 */

const STEP_NOTE =
  /^([a-z0-9-]{1,64}): (?:(running) \(\d+\/\d+\)|(succeeded|failed|skipped|blocked|cancelled))$/;

/** The step and status one note carries, or null for any other note. */
export function parseNote(note: string): { step: string; status: RunStatus } | null {
  const match = STEP_NOTE.exec(note);
  if (!match) return null;
  return { step: match[1], status: (match[2] ?? match[3]) as RunStatus };
}

/** Folds notes in arrival order into one status per step; later notes win. */
export function statusesFrom(notes: readonly string[]): Record<string, RunStatus> {
  const statuses: Record<string, RunStatus> = {};
  for (const note of notes) {
    const parsed = parseNote(note);
    if (parsed) statuses[parsed.step] = parsed.status;
  }
  return statuses;
}
