import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { TextField } from "../components/ui/Fields";
import { fieldLabelClasses } from "../components/ui/field";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { ManagedNote } from "./ManagedField";
import { SafeText } from "../components/ui/SafeText";
import { formatBytes } from "../lib/bytes";
import { backoffRefetchInterval } from "../lib/polling";
import {
  engineImport,
  engineInstall,
  engineRemove,
  engineStatus,
  toBridgeFailure,
  type BridgeFailure,
  type EngineSource,
  type EngineStatus,
} from "../lib/ipc";

/**
 * EngineCard — the truth about the pinned llama.cpp engine: installed or
 * not, why not, and what release it holds. Nothing installs on navigation
 * or on a poll; the human clicks the button, once, on purpose — and the
 * card says, before that click, exactly what the click does: which file,
 * from which host, how it is checked, what runs afterwards and how to
 * remove it. Every dynamic value (host, size, digest, location) comes
 * from the daemon's status; the card only phrases it.
 */

/** How often the read-only status re-checks itself. */
const POLL_MS = 10_000;

/** The engine poll backs off while the daemon refuses or is unreachable. */
const engineRefetchInterval = backoffRefetchInterval<unknown>({ baseMs: POLL_MS });

/** Causes that mean the existing install needs replacing, not a first install. */
const REINSTALL_CAUSES = new Set(["stale_release", "server_missing", "manifest_invalid"]);

/**
 * Refusal causes that are about reaching a host: the proxy, DNS, the connection, TLS trust, the
 * CA bundle, an unusable network document. For these the recovery is in Settings › Network.
 */
const NETWORK_CAUSE = /^(proxy_|tls_|dns_|connect_|ca_bundle|network_|timeout|curl_)/;

/**
 * `engine_download_failed` carries the launcher's cause in its detail ("dns_failed", …): the
 * network link is offered when the detail names one of those words.
 */
const NETWORK_DETAIL = /\b(proxy_|tls_|dns_|connect_|ca_bundle|network_|timeout|curl_)/;

/** True when `failure` is about reaching a host, so Settings › Network is the way out. */
function isNetworkFailure(failure: BridgeFailure): boolean {
  return (
    NETWORK_CAUSE.test(failure.cause) ||
    (failure.cause === "engine_download_failed" && NETWORK_DETAIL.test(failure.detail))
  );
}

/** First characters of a digest, enough to eyeball without the whole hash. */
function shaPrefix(sha256: string): string {
  return sha256.slice(0, 12);
}

/** The head and tail of a digest, the form the disclosure copy uses. */
function shaShort(sha256: string): string {
  return sha256.length > 20 ? `${sha256.slice(0, 12)}…${sha256.slice(-6)}` : sha256;
}

/** The host of an address, or null when it does not parse. */
function hostOf(url: string): string | null {
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
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

/** Where an installed archive came from, in words. */
function sourcePhrase(source: EngineSource | null | undefined): string {
  switch (source?.kind) {
    case "download":
      return `downloaded from ${source.host}`;
    case "mirror":
      return `downloaded from your mirror ${source.host}`;
    case "import": {
      const when = source.imported_at_ms
        ? ` on ${new Date(source.imported_at_ms).toISOString().slice(0, 10)}`
        : "";
      return `imported from a local file, ${source.path}${when} (copied; the original was not changed)`;
    }
    default:
      return "source not recorded";
  }
}

/** The host Install would fetch from, and whether it is the configured mirror. */
function fromHost(status: EngineStatus): { host: string; mirror: boolean } | null {
  const host =
    status.download_host ?? (status.download_url ? hostOf(status.download_url) : null);
  return host ? { host, mirror: status.mirror_in_use === true } : null;
}

/** Why Remove is unavailable, said plainly. */
function removeBlockedReason(status: EngineStatus): string {
  return status.loaded
    ? "A model is loaded. Unload it on the Runtime tab, then remove the engine."
    : "There is nothing in the engine folder to remove.";
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <li className="font-sans text-sm text-ink-muted">
      <span className="font-medium text-ink">{label}</span> {children}
    </li>
  );
}

/** A value the daemon supplied, in mono, with hidden characters made visible. */
function Value({ value }: { value: string }) {
  return <SafeText value={value} className="font-data text-xs text-ink" />;
}

/** What Install will do, before anyone presses it. */
function InstallDisclosure({
  status,
  onOpenNetwork,
}: {
  status: EngineStatus;
  onOpenNetwork?: () => void;
}) {
  const from = fromHost(status);
  const asset = status.expected_asset ?? null;
  const hasPlan = asset !== null && from !== null;
  const folder = status.engine_dir;
  return (
    <div className="space-y-3" aria-label="what install does">
      <p className="font-sans text-sm text-ink-muted">
        PAM can run a small language model on this computer to summarize build logs. That needs
        the llama.cpp engine, which PAM does not ship inside the app. Nothing is downloaded
        until you press Install.
      </p>
      {hasPlan && (
        <div className="space-y-1">
          <p className="font-sans text-sm font-medium text-ink">What Install does</p>
          <ul className="space-y-1">
            <Fact label="Downloads">
              <Value value={asset} />
              {typeof status.expected_size === "number" &&
                ` (${formatBytes(status.expected_size)})`}
            </Fact>
            <Fact label="From">
              <Value value={from.host} />
              {from.mirror ? ", your configured mirror" : ""}
              {status.download_url && (
                <>
                  , <Value value={status.download_url} />
                </>
              )}
              {from.mirror && ` (upstream is ${status.upstream_host ?? "github.com"})`}
            </Fact>
            {status.expected_sha256 && (
              <Fact label="Checks">
                that its SHA-256 is <Value value={shaShort(status.expected_sha256)} />, the
                value built into this version of PAM. A file that differs is deleted and nothing
                is installed.
              </Fact>
            )}
            <Fact label="Installs">
              llama.cpp build <Value value={status.expected_tag} />
              {(status.install_dir ?? folder) && (
                <>
                  {" "}
                  in <Value value={status.install_dir ?? folder ?? ""} />
                </>
              )}
            </Fact>
          </ul>
        </div>
      )}
      <p className="font-sans text-sm text-ink-muted">
        After that, the engine is an ordinary program that runs as your user, as a child of the
        PAM daemon, only while a model is loaded. PAM talks to it through a private socket (on
        Windows, a local port on 127.0.0.1 protected by a per-load key). PAM starts it with a
        model file path, no network options and an almost empty environment, and never gives it
        your connector credentials.
      </p>
      <p className="font-sans text-sm text-ink-muted">
        To remove it, press Remove engine, or stop the daemon and delete{" "}
        {folder ? <Value value={folder} /> : "the engine folder"}. Downloaded models are stored
        elsewhere and are not touched.
      </p>
      <p className="font-sans text-sm text-ink-muted">
        Cannot reach {from ? from.host : "the download host"} from this network? Set a proxy or
        an internal mirror in Settings › Network, or install from a file you already have.
      </p>
      {onOpenNetwork && (
        <Button size="sm" variant="ghost" onClick={onOpenNetwork}>
          Open Settings › Network
        </Button>
      )}
    </div>
  );
}

/** The installed facts: archive, source, server, location, how it runs, how to remove it. */
function InstalledDisclosure({
  status,
  onOpenNetwork,
}: {
  status: EngineStatus;
  onOpenNetwork?: () => void;
}) {
  const manifest = status.manifest;
  if (!manifest) return null;
  const source = status.source ?? manifest.source ?? null;
  const folder = status.engine_dir;
  return (
    <div className="space-y-1" aria-label="installed engine">
      <ul className="space-y-1">
        <Fact label="Archive:">
          <Value value={manifest.asset} />, SHA-256 <Value value={shaShort(manifest.sha256)} />{" "}
          (matched the value built into PAM)
        </Fact>
        <Fact label="Source:">
          <SafeText value={sourcePhrase(source)} />
        </Fact>
        {manifest.version_line && (
          <Fact label="Server:">
            <Value value={manifest.version_line} />
          </Fact>
        )}
        {status.install_dir && (
          <Fact label="Location:">
            <Value value={status.install_dir} />
          </Fact>
        )}
        <Fact label="Runs:">
          as a local process of your user, only while a model is loaded; reached through a
          private socket; has no access to connector credentials.
        </Fact>
        <Fact label="Remove:">
          press Remove engine, or stop the daemon and delete{" "}
          {folder ? <Value value={folder} /> : "the engine folder"}. Downloaded models are
          stored elsewhere and are not touched.
        </Fact>
      </ul>
      {source?.kind === "mirror" && onOpenNetwork && (
        <Button size="sm" variant="ghost" onClick={onOpenNetwork}>
          Mirror settings in Settings › Network
        </Button>
      )}
    </div>
  );
}

/** The install-from-a-file panel: a typed path, the file the daemon expects, a two-tap confirm. */
function ImportPanel({
  status,
  busy,
  onImport,
  onClose,
}: {
  status: EngineStatus;
  busy: boolean;
  onImport: (path: string) => void;
  onClose: () => void;
}) {
  const [path, setPath] = useState("");
  const trimmed = path.trim();
  const asset = status.expected_asset ?? null;
  const size =
    typeof status.expected_size === "number" ? formatBytes(status.expected_size) : null;
  return (
    <div
      role="group"
      aria-label="install from a file"
      className="space-y-3 rounded-card border border-line p-3"
    >
      <p className="font-sans text-sm text-ink-muted">
        Give the path of the llama.cpp release archive, or a folder that contains it.
        {asset && (
          <>
            {" "}
            This computer needs <Value value={asset} />
            {size && ` (${size}`}
            {status.expected_sha256 && (
              <>
                {size ? ", " : " ("}SHA-256 <Value value={status.expected_sha256} />
              </>
            )}
            {(size || status.expected_sha256) && ")"}.
          </>
        )}{" "}
        PAM copies the file, checks it against that SHA-256, and leaves the original untouched.
        An archive from any other build is refused. No network is used.
      </p>
      <label className="block space-y-1">
        <span className={fieldLabelClasses}>Path to the archive or its folder</span>
        <TextField
          aria-label="engine archive path"
          value={path}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setPath(event.target.value)}
          placeholder={asset ? `/path/to/${asset}` : "/path/to/archive"}
        />
        <span className="block font-sans text-sm text-ink-muted">
          Type the path: this app has no file picker.
          {asset && (
            <>
              {" "}
              Expected file name: <Value value={asset} />.
            </>
          )}
        </span>
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <ConfirmButton
          label="Install from this file"
          confirmLabel="Copy, check and install?"
          variant="secondary"
          busy={busy}
          disabled={!trimmed}
          title={trimmed ? undefined : "Enter a path first"}
          onConfirm={() => onImport(trimmed)}
        />
        <Button size="sm" variant="ghost" disabled={busy} onClick={onClose}>
          Close
        </Button>
      </div>
    </div>
  );
}

/** A failure, with the way to Settings › Network when it is about reaching a host. */
function EngineFailure({
  failure,
  onOpenNetwork,
}: {
  failure: BridgeFailure;
  onOpenNetwork?: () => void;
}) {
  // The network sentences end with a full stop and FailureNote adds one; keep a single one.
  const tidy = { ...failure, detail: failure.detail.replace(/\.+$/, "") };
  return (
    <FailureNote failure={tidy} label="engine">
      {isNetworkFailure(failure) && onOpenNetwork && (
        <Button size="sm" variant="secondary" onClick={onOpenNetwork}>
          Open Settings › Network
        </Button>
      )}
    </FailureNote>
  );
}

/** Why an install or import is closed under `models.engine_source`, in the human's words. */
export function installBlockedReason(
  source: EngineStatus["source_policy"],
): string | undefined {
  switch (source?.install_blocked) {
    case "import_only":
      return "Your organization's policy only allows installing the engine from a file you already have.";
    case "mirror_missing":
      return "Your organization's policy only allows installing the engine from a mirror, and none is set in Settings › Network.";
    default:
      return undefined;
  }
}

export function EngineCard({ onOpenNetwork }: { onOpenNetwork?: () => void } = {}) {
  const client = useQueryClient();
  const status = useQuery({
    queryKey: ["engine", "status"],
    queryFn: engineStatus,
    refetchInterval: engineRefetchInterval,
  });
  const [importing, setImporting] = useState(false);

  const settle = () => {
    void client.invalidateQueries({ queryKey: ["engine", "status"] });
    void client.invalidateQueries({ queryKey: ["models", "status"] });
  };

  const install = useMutation({
    mutationFn: () => engineInstall(),
    onMutate: () => {
      importLocal.reset();
      remove.reset();
    },
    onSuccess: settle,
  });
  const importLocal = useMutation({
    mutationFn: (path: string) => engineImport(path),
    onMutate: () => {
      install.reset();
      remove.reset();
    },
    onSuccess: () => {
      setImporting(false);
      settle();
    },
  });
  const remove = useMutation({
    mutationFn: () => engineRemove(),
    onMutate: () => {
      install.reset();
      importLocal.reset();
    },
    onSettled: settle,
  });

  const statusFailure = status.isError ? toBridgeFailure(status.error) : null;
  const installFailure = install.isError ? toBridgeFailure(install.error) : null;
  const importFailure = importLocal.isError ? toBridgeFailure(importLocal.error) : null;
  const removeFailure = remove.isError ? toBridgeFailure(remove.error) : null;
  const data = status.data;
  const hideButton = data?.cause === "unsupported_target";
  // Anything already on disk — healthy, stale or broken — is a reinstall.
  const onDisk = !!data && (data.installed || REINSTALL_CAUSES.has(data.cause ?? ""));
  const healthy = !!data && data.installed && data.cause === null && !!data.manifest;
  const buttonLabel = onDisk ? "Reinstall engine" : "Install engine";
  const working = install.isPending || importLocal.isPending;
  const removable = data?.removable !== false;
  const from = data ? fromHost(data) : null;
  const sourcePolicy = data?.source_policy;
  const installBlocked = installBlockedReason(sourcePolicy);
  const importBlocked =
    sourcePolicy?.import_allowed === false
      ? "Your organization's policy does not allow importing files."
      : undefined;

  return (
    <Panel className="space-y-3 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="font-sans text-sm font-semibold text-ink">Inference engine</h3>
        <span className="font-data text-xs text-ink-faint">llama.cpp</span>
      </div>

      {statusFailure && <FailureNote failure={statusFailure} label="engine" />}

      {!statusFailure && sourcePolicy && (
        <div className="space-y-1">
          <ManagedNote entry={sourcePolicy.effective} />
          {(installBlocked ?? importBlocked) && (
            <p className="select-text font-sans text-sm text-ink-muted">
              {[installBlocked, importBlocked].filter(Boolean).join(" ")}
            </p>
          )}
        </div>
      )}

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

      {!statusFailure && data?.network_issue && (
        <EngineFailure failure={data.network_issue} onOpenNetwork={onOpenNetwork} />
      )}

      {!statusFailure && data && !hideButton && working && (
        <div role="status" aria-label="installing" className="space-y-1">
          <p className="font-sans text-sm text-ink">Installing…</p>
          <p className="font-sans text-sm text-ink-muted">
            {importLocal.isPending ? (
              <>
                Copying <Value value={importLocal.variables ?? ""} /> and checking its SHA-256.
              </>
            ) : (
              <>
                Downloading
                {data.expected_asset && (
                  <>
                    {" "}
                    <Value value={data.expected_asset} />
                  </>
                )}
                {typeof data.expected_size === "number" &&
                  ` (${formatBytes(data.expected_size)})`}
                {from && (
                  <>
                    {" "}
                    from <Value value={from.host} />
                  </>
                )}
                . Then PAM checks the SHA-256,
              </>
            )}{" "}
            {importLocal.isPending ? "Then PAM " : ""}unpacks it into the engine folder with the
            operating system's tar, and runs it once with --version to confirm it reports build{" "}
            {data.expected_build}.
          </p>
          <p className="font-sans text-sm text-ink-muted">
            This request times out after two minutes. If it does, press Install again; the
            transfer resumes where it stopped.
          </p>
        </div>
      )}

      {!statusFailure && data && !hideButton && !working && !healthy && (
        <InstallDisclosure status={data} onOpenNetwork={onOpenNetwork} />
      )}

      {!statusFailure && data && !working && healthy && (
        <InstalledDisclosure status={data} onOpenNetwork={onOpenNetwork} />
      )}

      {!hideButton && (
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm"
            disabled={!data || working || installBlocked !== undefined}
            title={installBlocked}
            onClick={() => install.mutate()}
          >
            {install.isPending && (
              <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
            )}
            {install.isPending ? "Installing…" : buttonLabel}
          </Button>
          <Button
            size="sm"
            variant="secondary"
            disabled={!data || working || importBlocked !== undefined}
            title={importBlocked}
            aria-expanded={importing}
            onClick={() => setImporting((open) => !open)}
          >
            Install from a file…
          </Button>
          {onDisk && data && (
            <ConfirmButton
              label="Remove engine"
              confirmLabel="Remove the engine?"
              busy={remove.isPending}
              disabled={working || !removable}
              title={removable ? undefined : removeBlockedReason(data)}
              onConfirm={() => remove.mutate()}
            />
          )}
        </div>
      )}

      {onDisk && data && !removable && (
        <p className="font-sans text-sm text-ink-muted">
          Remove engine is unavailable. {removeBlockedReason(data)}
        </p>
      )}

      {importing && data && !hideButton && (
        <ImportPanel
          status={data}
          busy={importLocal.isPending}
          onImport={(path) => importLocal.mutate(path)}
          onClose={() => setImporting(false)}
        />
      )}

      {installFailure && (
        <EngineFailure failure={installFailure} onOpenNetwork={onOpenNetwork} />
      )}
      {importFailure && <EngineFailure failure={importFailure} onOpenNetwork={onOpenNetwork} />}
      {removeFailure && <FailureNote failure={removeFailure} label="engine" />}
    </Panel>
  );
}
