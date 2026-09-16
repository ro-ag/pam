import type { ReactNode } from "react";
import type { BridgeFailure } from "../../lib/ipc";

/**
 * FailureNote — the one PAM way to render the uniform failure shape
 * ({ cause, detail, recovery }). Refusals are beautiful: the cause is
 * evidence and speaks in mono, the detail is Pam explaining herself and
 * speaks in serif, and the recovery is the way out, in mono again.
 *
 * Every screen renders every failure through this component, so a
 * daemon refusal, a dead bridge, and a rejected admin op all look like
 * the same kind of honest answer. `children` is the way out when there
 * is one to offer here (a Retry button); it renders under the recovery.
 */
export function FailureNote({
  failure,
  label,
  children,
}: {
  failure: BridgeFailure;
  label: string;
  children?: ReactNode;
}) {
  return (
    <div className="max-w-content space-y-1 rounded-card border border-danger/40 bg-danger-soft p-3">
      <p className="font-data text-xs text-danger">
        {label} · {failure.cause}
      </p>
      <p className="font-sans text-sm text-ink">{failure.detail}.</p>
      <p className="font-data text-xs text-ink-muted">{failure.recovery}</p>
      {children && <div className="pt-2">{children}</div>}
    </div>
  );
}
