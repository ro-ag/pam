import { useEffect, useRef, useState } from "react";
import { approvalsPending, daemonStatus, subscribeEvents } from "../../lib/ipc";
import type { BeaconState } from "./Beacon";

/** How often the beacon re-asks the daemon for its health. */
export const STATUS_POLL_MS = 5_000;

/**
 * Daemon liveness for the beacon, wired to the real IPC bridge:
 *
 * - green when `daemon_status` answers connected (the call also lazily
 *   starts the daemon),
 * - amber when connected **and** approvals are waiting (the status poll
 *   piggybacks an `admin.approvals.pending` count),
 * - red when the daemon is unreachable — including plain-browser dev and
 *   jsdom, where every bridge call rejects with `BridgeUnavailable`.
 *
 * A 5 s poll carries the steady state; the daemon event stream adds
 * liveness — an `approval_pending` or terminal event re-polls
 * immediately so the beacon turns amber (and back) without waiting out
 * the interval.
 */
export function useDaemonStatus(): BeaconState {
  const [state, setState] = useState<BeaconState>("down");
  // One poll in flight at a time; events and the interval share it.
  const polling = useRef(false);

  useEffect(() => {
    let cancelled = false;

    const poll = async () => {
      if (polling.current) return;
      polling.current = true;
      let next: BeaconState = "down";
      try {
        const reply = await daemonStatus();
        if (reply.connected) {
          next = "connected";
          try {
            const { pending } = await approvalsPending();
            if (pending.length > 0) next = "pending";
          } catch {
            // Pending count is best-effort; connected still stands.
          }
        }
      } catch {
        next = "down";
      }
      polling.current = false;
      if (!cancelled) setState(next);
    };

    void poll();
    const interval = setInterval(() => void poll(), STATUS_POLL_MS);

    let unlisten: (() => void) | undefined;
    subscribeEvents((payload) => {
      // Approval raised or resolved (terminal events resolve waits):
      // reflect it now instead of on the next tick.
      if (payload.event.kind !== "progress") void poll();
    })
      .then((stop) => {
        if (cancelled) stop();
        else unlisten = stop;
      })
      .catch(() => {
        // No bridge (browser dev) or no stream yet; polling covers it.
      });

    return () => {
      cancelled = true;
      clearInterval(interval);
      unlisten?.();
    };
  }, []);

  return state;
}
