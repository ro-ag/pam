import { TextField } from "../components/ui/Fields";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { animate, useMotionValue, useReducedMotion, useTransform } from "motion/react";
import { useEffect, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { fieldClasses, fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { formatBytes } from "../lib/bytes";
import { cn } from "../lib/cn";
import {
  evidenceStats,
  logCompress,
  modelsStatus,
  toBridgeFailure,
  type CompressReport,
} from "../lib/ipc";

/**
 * EvidenceBand — the compression observatory, sitting under the Activity
 * header: what the reducer has saved (the odometer tile) and the one
 * control that drives it by hand (the compress box).
 *
 * Compression itself is daemon-internal; flows and connector diagnoses
 * call `LogService` without asking anyone. This band exists so a human
 * can see the machine work and drive one log through it — which is why
 * it is an `admin.*` op and lives in the GUI alone.
 */

/** How long the digits take to roll to a new figure. */
const ROLL_SECONDS = 0.8;

/** The capability the compress box files its request under. */
export const COMPRESS_CAPABILITY = "admin.log.compress";

/** What the odometer shows before the first answer lands. */
const NO_FIGURE_YET = "—";

/**
 * True when `path` is one the daemon will accept: absolute, POSIX or
 * Windows. Relative paths are refused daemon-side (its working directory
 * is not a thing a human can reason about), so the button stays closed
 * rather than spending a round trip to be told so.
 */
export function isAbsolutePath(path: string): boolean {
  const trimmed = path.trim();
  return trimmed.startsWith("/") || /^[A-Za-z]:[\\/]/.test(trimmed);
}

/**
 * The rolling number. Digits ease from the previous figure to the new one
 * so a compression is *seen* to move the odometer; under
 * `prefers-reduced-motion` the value simply lands, because a number that
 * refuses to hold still is not an animation anyone asked for.
 */
function Odometer({ value }: { value: number }) {
  const reduced = useReducedMotion();
  const rolling = useMotionValue(0);
  const digits = useTransform(rolling, (raw) => Math.round(raw).toLocaleString());
  const [shown, setShown] = useState(() => digits.get());

  useEffect(() => digits.on("change", setShown), [digits]);

  useEffect(() => {
    if (reduced) {
      rolling.set(value);
      return;
    }
    const controls = animate(rolling, value, { duration: ROLL_SECONDS, ease: "easeOut" });
    return () => controls.stop();
  }, [reduced, rolling, value]);

  return (
    <span className="font-display text-hero font-semibold tabular-nums text-ink">{shown}</span>
  );
}

/** The report's one-line verdict, in the mono voice facts speak in. */
function CompressedNote({ report }: { report: CompressReport }) {
  return (
    <div className="space-y-1">
      <p className="font-data text-xs text-ink-muted tabular-nums">
        {formatBytes(report.stats.source_bytes)} → {formatBytes(report.stats.compact_bytes)} · ~
        {report.stats.tokens_avoided_est.toLocaleString()} tokens avoided
      </p>
      {report.semantic && (
        <p className="text-sm text-ink-muted">
          Semantic selection stored the kept records as evidence {report.semantic.id}. The
          original evidence is unchanged.
        </p>
      )}
      {report.compression_skipped && (
        <p className="text-sm text-ink-muted">
          Semantic compression skipped: {report.compression_skipped.detail}
        </p>
      )}
      {report.model_skipped && (
        <p className="font-sans text-sm text-ink-muted">
          No summary this time — {report.model_skipped.detail}.
        </p>
      )}
    </div>
  );
}

export function EvidenceBand({ onCompressed }: { onCompressed: () => void }) {
  const queryClient = useQueryClient();
  const [path, setPath] = useState("");
  const [exitStatus, setExitStatus] = useState("");
  const [useModel, setUseModel] = useState(true);
  // Read only while the box is ticked: the line under it is the one thing
  // here that needs the model layer, and an unticked box should cost nothing.
  const models = useQuery({
    queryKey: ["models", "status"],
    queryFn: modelsStatus,
    enabled: useModel,
  });
  const heavy = models.data?.readiness?.heavy;
  const heavyBlocked = heavy && heavy.stage !== "ready" ? heavy.blocker?.detail : null;

  const stats = useQuery({ queryKey: ["evidence-stats"], queryFn: () => evidenceStats() });

  const compress = useMutation({
    mutationFn: () =>
      logCompress({
        path: path.trim(),
        ...(exitStatus.trim() === "" ? {} : { exit_status: Number(exitStatus) }),
        model: useModel,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["activity"] });
      void queryClient.invalidateQueries({ queryKey: ["evidence-stats"] });
      onCompressed();
    },
  });

  const statsFailure = stats.isError ? toBridgeFailure(stats.error) : null;
  const compressFailure = compress.isError ? toBridgeFailure(compress.error) : null;
  const figures = stats.data;
  const inputClasses = cn(fieldClasses, "disabled:cursor-not-allowed disabled:opacity-70");

  return (
    <Panel
      ground="raised"
      aria-label="compression"
      className="mt-2 mb-4 flex flex-col gap-6 p-5 md:flex-row md:items-start md:justify-between"
    >
      <div className="space-y-1">
        <p className="font-data text-xs text-ink-faint">Tokens avoided, last 7 days</p>
        {figures ? (
          <Odometer value={figures.tokens_avoided_est} />
        ) : (
          <span className="font-display text-hero font-semibold tabular-nums text-ink-faint">
            {NO_FIGURE_YET}
          </span>
        )}
        {figures && (
          <p className="font-data text-xs text-ink-muted tabular-nums">
            {figures.compressions} compression{figures.compressions === 1 ? "" : "s"} ·{" "}
            {formatBytes(figures.source_bytes)} → {formatBytes(figures.compact_bytes)}
          </p>
        )}
        {statsFailure && <FailureNote failure={statsFailure} label="evidence stats" />}
      </div>

      <form
        className="w-full space-y-2 md:max-w-sm"
        onSubmit={(event) => {
          event.preventDefault();
          if (isAbsolutePath(path) && !compress.isPending) compress.mutate();
        }}
      >
        <p className="font-data text-xs text-ink-faint">Compress a log</p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="min-w-56 flex-1 space-y-1">
            <span className={fieldLabelClasses}>Log path</span>
            <TextField
              aria-label="log path"
              value={path}
              disabled={compress.isPending}
              onChange={(event) => setPath(event.target.value)}
              placeholder="/absolute/path/to/build.log"
              className={inputClasses}
            />
          </label>
          <label className="w-24 space-y-1">
            <span className={fieldLabelClasses}>Exit status</span>
            <TextField
              type="number"
              aria-label="exit status"
              value={exitStatus}
              disabled={compress.isPending}
              onChange={(event) => setExitStatus(event.target.value)}
              className={inputClasses}
            />
          </label>
        </div>
        <label className="flex min-h-8 cursor-pointer items-center gap-2 font-sans text-xs text-ink-muted">
          <input
            type="checkbox"
            aria-label="use model"
            checked={useModel}
            disabled={compress.isPending}
            onChange={(event) => setUseModel(event.target.checked)}
            className="size-4.5 accent-accent-strong"
          />
          Summarize with the heavy model
        </label>
        {useModel && heavyBlocked && (
          <p className="font-sans text-xs text-warning">
            No summary will come of this — {heavyBlocked}.
          </p>
        )}
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm"
            type="submit"
            disabled={compress.isPending || !isAbsolutePath(path)}
            title={!isAbsolutePath(path) ? "Enter an absolute path to a log file" : undefined}
          >
            Compress
          </Button>
          <span className="font-sans text-sm text-ink-muted">
            The daemon reads the file as your user, so name a path it can reach.
          </span>
        </div>
        {compress.data && <CompressedNote report={compress.data} />}
        {compressFailure && <FailureNote failure={compressFailure} label="compress" />}
      </form>
    </Panel>
  );
}
