import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import {
  engineInstall,
  engineStatus,
  toBridgeFailure,
  type EngineStatus,
} from "../lib/ipc";

/**
 * EngineCard — the truth about the pinned llama.cpp engine: installed or
 * not, why not, and what release it holds. Nothing installs on navigation
 * or on a poll; the human clicks the button, once, on purpose.
 */

/** How often the read-only status re-checks itself. */
const POLL_MS = 10_000;

/** Causes that mean the existing install needs replacing, not a first install. */
const REINSTALL_CAUSES = new Set(["stale_release", "server_missing", "manifest_invalid"]);

/** First characters of a digest, enough to eyeball without the whole hash. */
function shaPrefix(sha256: string): string {
  return sha256.slice(0, 12);
}

/** The one honest sentence for whatever `cause` the daemon reports. */
function engineStatusLine(status: EngineStatus): string {
  switch (status.cause) {
    case "not_installed":
      return "Not installed";
    case "stale_release":
      return status.manifest
        ? `Installed ${status.manifest.tag}, expected ${status.expected_tag}`
        : `Installed release is stale, expected ${status.expected_tag}`;
    case "server_missing":
    case "manifest_invalid":
      return "Broken install";
    case "unsupported_target":
      return "No release for this platform";
    case null:
      if (status.manifest) {
        return `Installed · ${status.manifest.tag} · ${status.manifest.target}`;
      }
      return status.installed ? "Installed" : "Not installed";
    default:
      return "Unknown engine state";
  }
}

export function EngineCard() {
  const client = useQueryClient();
  const status = useQuery({
    queryKey: ["engine", "status"],
    queryFn: engineStatus,
    refetchInterval: POLL_MS,
  });

  const install = useMutation({
    mutationFn: () => engineInstall(),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["engine", "status"] });
      void client.invalidateQueries({ queryKey: ["models", "status"] });
    },
  });

  const statusFailure = status.isError ? toBridgeFailure(status.error) : null;
  const installFailure = install.isError ? toBridgeFailure(install.error) : null;
  const data = status.data;
  const hideButton = data?.cause === "unsupported_target";
  // Anything already on disk — healthy, stale or broken — is a reinstall.
  const buttonLabel =
    data && (data.installed || REINSTALL_CAUSES.has(data.cause ?? ""))
      ? "Reinstall engine"
      : "Install engine";

  return (
    <Panel className="space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="font-sans text-sm font-semibold text-ink">Inference engine</h3>
        <span className="font-data text-xs text-ink-faint">llama.cpp</span>
      </div>

      {statusFailure && <FailureNote failure={statusFailure} label="engine" />}

      {!statusFailure && data && (
        <div className="space-y-1">
          <p className="font-data text-xs text-ink-muted">{engineStatusLine(data)}</p>
          {data.cause === null && data.manifest && (
            <p className="font-data text-xs text-ink-faint">
              {data.manifest.version_line ?? data.manifest.tag} · sha{" "}
              {shaPrefix(data.manifest.sha256)}
            </p>
          )}
        </div>
      )}

      {!hideButton && (
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm"
            disabled={!data || install.isPending}
            onClick={() => install.mutate()}
          >
            {install.isPending && (
              <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
            )}
            {install.isPending ? "Installing…" : buttonLabel}
          </Button>
        </div>
      )}

      {installFailure && <FailureNote failure={installFailure} label="engine" />}
    </Panel>
  );
}
