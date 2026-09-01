import { useEffect, useState } from "react";
import { approvalsPending } from "../lib/ipc";

/**
 * Approvals — placeholder until task #29 lands the raised-hand banner flow.
 * One line, in Pam's voice; the eyebrow carries the live pending count from
 * `admin.approvals.pending` once the bridge answers.
 */
export function ApprovalsScreen() {
  const [pending, setPending] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    approvalsPending()
      .then((reply) => {
        if (!cancelled) setPending(reply.pending.length);
      })
      .catch(() => {
        // No bridge or no daemon: the placeholder copy stands alone.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex h-full flex-col p-10">
      <header className="my-auto max-w-xl space-y-4">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          {pending !== null && pending > 0
            ? `approvals · ${pending} hand${pending === 1 ? "" : "s"} raised`
            : "approvals · no hands raised"}
        </p>
        <h1 className="font-display text-hero font-semibold text-ink">Approvals</h1>
        <p className="font-voice text-lg text-ink-muted italic">
          When an agent wants more than it&rsquo;s allowed, its raised hand appears here — and
          everything waits for yours.
        </p>
      </header>
    </div>
  );
}
