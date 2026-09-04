import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { FailureNote } from "../components/ui/FailureNote";
import { formatBytes } from "../lib/bytes";
import { cn } from "../lib/cn";
import {
  evidenceGet,
  evidenceList,
  toBridgeFailure,
  type EvidenceContent,
  type EvidenceMeta,
} from "../lib/ipc";

/**
 * EvidenceStrip — what one request left behind, inside its expanded row.
 *
 * Evidence has a foreign key onto the request, so the rows are findable
 * exactly where the tide already looks. One mono chip per row (kind and
 * blob size, the `ev_` id on the title); picking one loads it into the
 * viewer below. A request with no evidence — most of them — renders
 * nothing at all, so the row detail stays as quiet as it was.
 */

/** The compaction report kind: it is the one row with a stats line. */
export const KIND_COMPACT = "log.compact";

/** The model's prose: the one row that speaks in Pam's serif. */
export const KIND_SUMMARY = "log.summary";

/** A number out of an evidence row's parsed `meta_json`, or null. */
function metaNumber(meta: Record<string, unknown> | null, key: string): number | null {
  const raw = meta?.[key];
  return typeof raw === "number" && Number.isFinite(raw) ? raw : null;
}

/**
 * The compaction's own figures, read off the row's metadata: what the
 * reducer threw away, and what that is worth in tokens.
 */
function CompactStatsLine({ meta }: { meta: Record<string, unknown> | null }) {
  const sourceRecords = metaNumber(meta, "source_records");
  const retainedRecords = metaNumber(meta, "retained_records");
  const sourceBytes = metaNumber(meta, "source_bytes");
  const compactBytes = metaNumber(meta, "compact_bytes");
  const avoided = metaNumber(meta, "tokens_avoided_est");
  if (
    sourceRecords === null ||
    retainedRecords === null ||
    sourceBytes === null ||
    compactBytes === null ||
    avoided === null
  ) {
    return null;
  }
  return (
    <p className="font-data text-xs text-ink-muted tabular-nums">
      {sourceRecords.toLocaleString()} → {retainedRecords.toLocaleString()} records ·{" "}
      {formatBytes(sourceBytes)} → {formatBytes(compactBytes)} · ~{avoided.toLocaleString()}{" "}
      tokens avoided
    </p>
  );
}

/** One loaded evidence row, rendered in the voice its kind deserves. */
function EvidenceViewer({ content }: { content: EvidenceContent }) {
  return (
    <div className="space-y-2">
      {content.kind === KIND_COMPACT && <CompactStatsLine meta={content.meta} />}
      {content.kind === KIND_SUMMARY ? (
        <p className="font-sans text-sm whitespace-pre-line text-ink">{content.text}</p>
      ) : (
        <pre className="max-h-96 overflow-auto rounded-card border border-line bg-chrome p-3 font-data text-xs leading-relaxed text-ink-muted">
          {content.text}
        </pre>
      )}
      {content.truncated && (
        <p className="font-data text-xs text-ink-faint tabular-nums">
          showing the first {formatBytes(content.text.length)} of{" "}
          {formatBytes(content.text_bytes)}
        </p>
      )}
    </div>
  );
}

/** One chip per evidence row: the kind, its size, the id on the title. */
function EvidenceChip({
  row,
  selected,
  onSelect,
}: {
  row: EvidenceMeta;
  selected: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      title={row.id}
      aria-pressed={selected}
      onClick={onSelect}
      className={cn(
        "rounded-control border border-line px-2 py-1 font-data text-xs transition-colors duration-150",
        selected ? "bg-accent-soft text-ink" : "text-ink-muted hover:text-ink",
      )}
    >
      {row.kind} · {formatBytes(row.bytes)}
    </button>
  );
}

export function EvidenceStrip({ requestId }: { requestId: string }) {
  const [selected, setSelected] = useState<string | null>(null);

  const list = useQuery({
    queryKey: ["evidence", requestId],
    queryFn: () => evidenceList(requestId),
  });
  const content = useQuery({
    queryKey: ["evidence", selected],
    queryFn: () => evidenceGet(selected as string),
    enabled: selected !== null,
  });

  const listFailure = list.isError ? toBridgeFailure(list.error) : null;
  if (listFailure) return <FailureNote failure={listFailure} label="evidence" />;

  const rows = list.data?.evidence ?? [];
  // Nothing to say while the answer is on its way, and nothing to say
  // when a request left no evidence — which is most of them.
  if (rows.length === 0) return null;

  const contentFailure = content.isError ? toBridgeFailure(content.error) : null;

  return (
    <div className="space-y-2">
      <div role="group" aria-label="evidence" className="flex flex-wrap gap-2">
        {rows.map((row) => (
          <EvidenceChip
            key={row.id}
            row={row}
            selected={selected === row.id}
            onSelect={() => setSelected(selected === row.id ? null : row.id)}
          />
        ))}
      </div>
      {contentFailure && <FailureNote failure={contentFailure} label="evidence" />}
      {!contentFailure && content.data && <EvidenceViewer content={content.data} />}
    </div>
  );
}
