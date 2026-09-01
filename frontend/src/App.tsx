import { invoke, isTauri } from "@tauri-apps/api/core";
import { useEffect, useState } from "react";

/**
 * Scaffold shell: the PAM mark plus two status lines. Everything here is a
 * placeholder — real design tokens, layout, and daemon IPC land with later
 * tasks. The only live wire is the `ping` Tauri command, invoked on mount
 * to prove the frontend↔Rust bridge works.
 */
export default function App() {
  const [shellStatus, setShellStatus] = useState("shell: checking…");

  useEffect(() => {
    if (!isTauri()) {
      // Plain-browser dev (vite without the Tauri window) and jsdom tests.
      setShellStatus("shell: running outside the Tauri window");
      return;
    }
    let cancelled = false;
    invoke<string>("ping")
      .then((reply) => {
        if (!cancelled) setShellStatus(`shell: ipc ${reply}`);
      })
      .catch((error: unknown) => {
        if (!cancelled) setShellStatus(`shell: ipc failed (${String(error)})`);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <main className="flex h-screen flex-col items-center justify-center gap-4 bg-neutral-950 text-neutral-100">
      <h1 className="text-6xl font-semibold tracking-[0.3em]">PAM</h1>
      <p className="text-sm text-neutral-400">daemon: not connected yet</p>
      <p className="text-xs text-neutral-600">{shellStatus}</p>
    </main>
  );
}
