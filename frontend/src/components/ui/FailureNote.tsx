import type { BridgeFailure } from "../../lib/ipc";

/**
 * FailureNote — the one PAM way to render the uniform failure shape
 * ({ cause, detail, recovery }). Refusals are beautiful: the cause is
 * evidence and speaks in mono, the detail is Pam explaining herself and
 * speaks in serif, and the recovery is the way out, in mono again.
 *
 * Every screen renders every failure through this component, so a
 * daemon refusal, a dead bridge, and a rejected admin op all look like
 * the same kind of honest answer.
 */
export function FailureNote({ failure, label }: { failure: BridgeFailure; label: string }) {
  return (
    <div className="space-y-1 rounded-card border border-danger/40 bg-danger-soft p-3">
      <p className="font-data text-xs tracking-widest text-danger uppercase">
        {label} · {failure.cause}
      </p>
      <p className="font-voice text-sm text-ink italic">{failure.detail}.</p>
      <p className="font-data text-xs text-ink-muted">{failure.recovery}</p>
    </div>
  );
}
