import { useEffect, useState } from "react";
import { activityList } from "../lib/ipc";

/**
 * Activity — the default screen. Placeholder until task #28 lands the live
 * tide (swimlanes per caller over PUB/SUB); until then one live line proves
 * the bridge: the recent-request count from `admin.activity.list`. The
 * greeting is Pam's voice, so it speaks in the serif; the eyebrow is
 * machine furniture, so it does not.
 */
export function ActivityScreen() {
  const [recent, setRecent] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    activityList()
      .then(({ requests }) => {
        if (!cancelled) setRecent(requests.length);
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
          lifeguard tower · watching
        </p>
        <h1 className="font-display text-hero font-semibold text-ink">Activity</h1>
        <p className="font-voice text-lg text-ink-muted italic">
          I&rsquo;m watching the water. Nothing needs your hand right now — when something does,
          I&rsquo;ll raise mine first.
        </p>
        {recent !== null && (
          <p className="font-data text-xs text-ink-faint">
            {recent} recent request{recent === 1 ? "" : "s"} in the log
          </p>
        )}
      </header>
    </div>
  );
}
