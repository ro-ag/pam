/**
 * Approvals — placeholder until task #29 lands the raised-hand banner flow.
 * One line, in Pam's voice.
 */
export function ApprovalsScreen() {
  return (
    <div className="flex h-full flex-col p-10">
      <header className="my-auto max-w-xl space-y-4">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          approvals · no hands raised
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
