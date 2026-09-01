import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";
import type { BeaconState } from "./Beacon";

/**
 * Daemon liveness for the beacon. v0 wiring per task #25: green when the
 * `ping` IPC round-trip succeeds, red otherwise (including plain-browser dev
 * and jsdom, where no Tauri bridge exists). Amber arrives with the approvals
 * task, driven by pending-approval events.
 */
export function useDaemonStatus(): BeaconState {
  const [state, setState] = useState<BeaconState>("down");

  useEffect(() => {
    if (!isTauri()) return;
    let cancelled = false;
    invoke<string>("ping")
      .then(() => {
        if (!cancelled) setState("connected");
      })
      .catch(() => {
        if (!cancelled) setState("down");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return state;
}
