/**
 * Outcome and state ids, as words. The daemon records ids such as
 * `result_unavailable` or `scope_denied` next to the five truth verdicts;
 * every badge that shows one goes through here so the same id reads the
 * same way on every screen.
 */
const WORDS: Record<string, string> = {
  solved: "solved",
  changed: "changed",
  verified: "verified",
  unresolved: "unresolved",
  blocked: "blocked",
  waiting_approval: "awaiting review",
  result_unavailable: "result unavailable",
  evidence_unavailable: "evidence unavailable",
  scope_denied: "scope denied",
  approval_denied: "approval denied",
  approval_timeout: "approval timed out",
  capability_denied: "capability denied",
  deadline_exceeded: "deadline exceeded",
};

/** `scope_denied` → "scope denied"; unknown ids read with their underscores spaced. */
export function outcomeLabel(id: string): string {
  return WORDS[id] ?? id.replace(/_/g, " ");
}
