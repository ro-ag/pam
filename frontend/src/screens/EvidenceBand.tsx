import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { animate, useMotionValue, useReducedMotion, useTransform } from "motion/react";
import { useEffect, useState } from "react";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { formatBytes } from "../lib/bytes";
import { evidenceStats, logCompress, toBridgeFailure, type CompressReport } from "../lib/ipc";

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
export const ROLL_SECONDS = 0.8;

/** The capability the compress box files its request under. */
export const COMPRESS_CAPABILITY = "admin.log.compress";

/** What the odometer shows before the first answer lands. */
export const NO_FIGURE_YET = "—";

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
export function Odometer({ value }: { value: number }) {
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
      {report.model_skipped && (
        <p className="font-voice text-sm text-ink-muted italic">
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
  const inputClasses =
    "h-8 w-full rounded-control border border-line bg-surface px-2.5 font-data text-xs text-ink placeholder:text-ink-faint disabled:cursor-not-allowed disabled:opacity-50";

  return (
    <Panel
      ground="raised"
      aria-label="compression"
      className="mt-2 mb-4 flex flex-col gap-6 p-5 md:flex-row md:items-start md:justify-between"
    >
      <div className="space-y-1">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          tokens avoided · 7 days
        </p>
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
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          compress a log
        </p>
        <div className="flex flex-wrap items-end gap-2">
          <label className="min-w-56 flex-1 space-y-1">
            <span className="block font-data text-xs text-ink-faint">log path</span>
            <input
              aria-label="log path"
              value={path}
              disabled={compress.isPending}
              onChange={(event) => setPath(event.target.value)}
              placeholder="/absolute/path/to/build.log"
              className={inputClasses}
            />
          </label>
          <label className="w-24 space-y-1">
            <span className="block font-data text-xs text-ink-faint">exit status</span>
            <input
              type="number"
              aria-label="exit status"
              value={exitStatus}
              disabled={compress.isPending}
              onChange={(event) => setExitStatus(event.target.value)}
              className={inputClasses}
            />
          </label>
        </div>
        <label className="flex items-center gap-2 font-data text-xs text-ink-muted">
          <input
            type="checkbox"
            aria-label="use model"
            checked={useModel}
            disabled={compress.isPending}
            onChange={(event) => setUseModel(event.target.checked)}
          />
          summarize with the heavy model
        </label>
        <div className="flex flex-wrap items-center gap-3">
          <Button size="sm" type="submit" disabled={compress.isPending || !isAbsolutePath(path)}>
            Compress
          </Button>
          <span className="font-voice text-sm text-ink-muted italic">
            I read the file as myself, so name a path I can reach.
          </span>
        </div>
        {compress.data && <CompressedNote report={compress.data} />}
        {compressFailure && <FailureNote failure={compressFailure} label="compress" />}
      </form>
    </Panel>
  );
}
