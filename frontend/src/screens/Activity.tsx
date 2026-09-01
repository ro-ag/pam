/**
 * Activity — the default screen. Placeholder until task #28 lands the live
 * tide (swimlanes per caller over PUB/SUB). The greeting is Pam's voice, so
 * it speaks in the serif; the eyebrow is machine furniture, so it does not.
 */
export function ActivityScreen() {
  return (
    <div className="flex h-full flex-col p-10">
      <header className="my-auto max-w-xl space-y-4">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          lifeguard tower · watching
        </p>
        <h1 className="font-display text-hero font-semibold text-ink">Activity</h1>
        <p className="font-voice text-lg text-ink-muted italic">
          I&rsquo;m watching the water. Nothing needs your hand right now — when something does,
          I&rsquo;ll raise mine first.
        </p>
      </header>
    </div>
  );
}
