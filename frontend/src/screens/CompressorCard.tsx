import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "../components/ui/Button";
import { Panel } from "../components/ui/Panel";
import { adminCall, toBridgeFailure } from "../lib/ipc";

interface CompressorStatus {
  installed: boolean;
  enabled: boolean;
  directory: string;
  bytes: number;
}

/** Optional extractor setup alongside the existing model downloads. */
export function CompressorCard() {
  const client = useQueryClient();
  const status = useQuery({
    queryKey: ["compressor", "status"],
    queryFn: () => adminCall<CompressorStatus>("admin.models.compressor.status"),
    refetchInterval: 5_000,
  });
  const install = useMutation({
    mutationFn: (repair: boolean) => adminCall("admin.models.compressor.install", { repair }),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["models", "status"] });
      void client.invalidateQueries({ queryKey: ["compressor", "status"] });
    },
  });
  const enable = useMutation({
    mutationFn: (enabled: boolean) => adminCall("admin.models.compressor.set", { enabled }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["compressor", "status"] }),
  });
  const error = install.error ?? enable.error ?? status.error;
  return (
    <Panel className="space-y-3 p-4">
      <h3 className="font-sans text-sm font-semibold text-ink">
        Microsoft evidence compressor
      </h3>
      <p className="text-sm text-ink-muted">
        LLMLingua-2 selects complete log records before a summary. Original evidence is kept.
        Experimental: selected records do not establish the cause of a failure.
      </p>
      <p className="font-data text-xs text-ink-faint">
        {status.data?.installed
          ? "Assets installed · checked for integrity before use"
          : "About 710 MB · local CPU inference"}
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <Button
          size="sm"
          disabled={!status.data || status.data.installed || install.isPending}
          onClick={() => install.mutate(false)}
        >
          {install.isPending
            ? "Starting download…"
            : status.data?.installed
              ? "Installed"
              : "Install compressor"}
        </Button>
        <Button
          size="sm"
          disabled={!status.data || install.isPending}
          onClick={() => install.mutate(true)}
        >
          Reinstall assets
        </Button>
        <Button
          size="sm"
          disabled={
            !status.data || (!status.data.installed && !status.data.enabled) || enable.isPending
          }
          onClick={() => enable.mutate(!status.data?.enabled)}
        >
          {status.data?.enabled ? "Disable for summaries" : "Enable for summaries"}
        </Button>
      </div>
      {install.isSuccess && !status.data?.installed && (
        <p className="text-sm text-ink-muted">
          Download jobs appear with the other model downloads. Enable after all assets finish.
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-danger">
          {toBridgeFailure(error).detail}
        </p>
      )}
    </Panel>
  );
}
