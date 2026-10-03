import { useState, type ReactNode } from "react";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { TextField } from "../components/ui/Fields";
import { fieldLabelClasses } from "../components/ui/field";
import { SafeText } from "../components/ui/SafeText";
import { formatBytes } from "../lib/bytes";
import type { CatalogPreset, ModelImportReply } from "../lib/ipc";

/**
 * The two places a weights file enters the machine: a download the human confirms after reading
 * what it will fetch, and an import of a file already on this computer. Both are presentational:
 * the screen owns the mutations, the daemon owns every host, route and digest shown here.
 */

/** A digest as the confirmation copy shows it: head and tail. */
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

function Line({ label, children }: { label: string; children: ReactNode }) {
  return (
    <li className="font-sans text-sm text-ink-muted">
      <span className="font-medium text-ink">{label}</span> {children}
    </li>
  );
}

/** The mono styling for a value the daemon supplied. */
function Value({ value }: { value: string }) {
  return <SafeText value={value} className="font-data text-xs text-ink" />;
}

/** What the daemon would fetch for `preset`: its resolved `fetch`, else the catalog address. */
function presetSource(preset: CatalogPreset): { url: string; host: string; mirror: boolean } {
  const fetchPlan = preset.fetch;
  if (fetchPlan) {
    return { url: fetchPlan.url, host: fetchPlan.host, mirror: fetchPlan.source === "mirror" };
  }
  return { url: preset.url, host: hostOf(preset.url) ?? preset.url, mirror: false };
}

/** Shown in place of starting a catalog download; the transfer starts only on its button. */
export function DownloadConfirm({
  preset,
  savedTo,
  resuming,
  busy,
  onConfirm,
  onCancel,
}: {
  preset: CatalogPreset;
  /** The directory models are saved under, when the daemon has said. */
  savedTo: string | undefined;
  resuming: boolean;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const source = presetSource(preset);
  return (
    <div
      role="group"
      aria-label={`confirm download ${preset.label}`}
      className="space-y-3 rounded-card border border-warning/40 bg-warning-soft p-3"
    >
      <p className="font-sans text-sm font-medium text-ink">
        {resuming ? "Resume" : "Download"} {preset.label}?
      </p>
      <ul className="space-y-1">
        <Line label="Size:">{formatBytes(preset.size_bytes)}</Line>
        <Line label="From:">
          <Value value={source.host} />
          {source.mirror ? ", your configured mirror" : ""}, <Value value={source.url} />
          {source.mirror
            ? " — the catalog source is huggingface.co"
            : preset.fetch
              ? " — the catalog source"
              : ""}
        </Line>
        <Line label="Checks:">
          size and SHA-256 (<Value value={shaShort(preset.sha256)} />) must equal the values
          built into this version of PAM; a file that differs is deleted.
        </Line>
        {savedTo && (
          <Line label="Saved to:">
            <Value value={`${savedTo}/${preset.vendor}/${preset.file_name}`} />
          </Line>
        )}
        <Line label="Licence:">
          {preset.license_id},{" "}
          <a
            href={preset.license_url}
            target="_blank"
            rel="noreferrer"
            className="font-data text-xs text-accent underline underline-offset-2"
          >
            {preset.license_url}
          </a>
        </Line>
      </ul>
      <p className="font-sans text-sm text-ink-muted">
        This is model data, not a program. It is read by the local engine and nothing else. If
        the transfer is interrupted, press Download again to resume.
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={busy} onClick={onConfirm}>
          Start download
        </Button>
        <Button size="sm" variant="secondary" autoFocus onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/** The pasted-address twin: nothing is expected, so the copy says what that means. */
export function PastedConfirm({
  url,
  busy,
  onConfirm,
  onCancel,
}: {
  url: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const host = hostOf(url);
  return (
    <div
      role="group"
      aria-label="confirm unverified download"
      className="space-y-3 rounded-card border border-warning/40 bg-warning-soft p-3"
    >
      <p className="font-sans text-sm font-medium text-ink">Fetch this address?</p>
      <p className="font-sans text-sm text-ink-muted">
        Unverified download. PAM has no expected SHA-256 for this address; it saves whatever the
        server sends from {host ? <Value value={host} /> : "that address"}. The file is kept as
        a test-only model and is not used for jobs until it is verified. Only https addresses
        are accepted. Mirrors do not apply to pasted addresses.
      </p>
      <p className="font-data text-xs text-ink-muted">
        <SafeText value={url} />
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" disabled={busy} onClick={onConfirm}>
          Start download
        </Button>
        <Button size="sm" variant="secondary" autoFocus onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

/** What the import form hands up: a path, and optionally a vendor and the digest it must match. */
export interface ImportRequest {
  path: string;
  vendor?: string;
  expected_sha256?: string;
}

/**
 * Import weights from a path on this computer. The path is typed (the app has no file picker).
 * The daemon decides what the file is: one whose size matches a catalog model is checked against
 * that model's digest; any other lands unverified and needs Verify, unless the human gives the
 * SHA-256 to expect. After the request the daemon's own note says which of the two happened.
 */
export function ImportWeights({
  savedTo,
  busy,
  blocked,
  result,
  onImport,
}: {
  savedTo: string | undefined;
  busy: boolean;
  /** Why importing is closed under the managed policy; undefined when it is open. */
  blocked?: string;
  /** The reply to the last import request, whose `note` says what will be trusted. */
  result: ModelImportReply | undefined;
  onImport: (request: ImportRequest) => void;
}) {
  const [open, setOpen] = useState(false);
  const [path, setPath] = useState("");
  const [vendor, setVendor] = useState("");
  const [digest, setDigest] = useState("");

  if (!open) {
    return (
      <div className="space-y-2 border-t border-line pt-4">
        <Button
          size="sm"
          variant="secondary"
          disabled={blocked !== undefined}
          title={blocked}
          onClick={() => setOpen(true)}
        >
          Import weights from file…
        </Button>
        {result && <ImportNote result={result} />}
      </div>
    );
  }

  const trimmedPath = path.trim();
  const submit = () => {
    const trimmedVendor = vendor.trim();
    const expected = digest.trim().toLowerCase();
    onImport({
      path: trimmedPath,
      ...(trimmedVendor ? { vendor: trimmedVendor } : {}),
      ...(expected ? { expected_sha256: expected } : {}),
    });
  };

  return (
    <div
      role="group"
      aria-label="import weights from a file"
      className="space-y-3 border-t border-line pt-4"
    >
      <p className="font-data text-xs text-ink-faint">Import from a file</p>
      <label className="block space-y-1">
        <span className={fieldLabelClasses}>Path to the .gguf file</span>
        <TextField
          aria-label="weights file path"
          value={path}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setPath(event.target.value)}
          placeholder="/path/to/model.gguf"
        />
        <span className="block font-sans text-sm text-ink-muted">
          Type the path: this app has no file picker. It must be an absolute path to a .gguf
          file, not a link, outside the models directory.
        </span>
      </label>
      <div className="flex flex-wrap items-end gap-2">
        <label className="w-40 space-y-1">
          <span className={fieldLabelClasses}>Vendor (optional)</span>
          <TextField
            aria-label="import vendor"
            value={vendor}
            onChange={(event) => setVendor(event.target.value)}
            placeholder="qwen"
          />
        </label>
        <label className="min-w-64 flex-1 space-y-1">
          <span className={fieldLabelClasses}>Expected SHA-256 (optional)</span>
          <TextField
            aria-label="expected sha256"
            value={digest}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setDigest(event.target.value)}
            placeholder="64 hex characters"
          />
        </label>
      </div>
      <p className="font-sans text-sm text-ink-muted">
        PAM copies the file
        {savedTo ? (
          <>
            {" "}
            into <Value value={savedTo} />
          </>
        ) : (
          " into the models directory"
        )}{" "}
        and works out its SHA-256 as it copies; the original is not changed and no network is
        used. If the file is one of the catalog models, its size and SHA-256 are checked against
        the catalog and it is saved under the catalog name. Any other file is saved as an
        unverified, test-only model: it needs Verify, and it is never a tier default until it is
        verified and qualified. Give the SHA-256 you expect and the copy must match it, and is
        then recorded as verified.
      </p>
      <div className="flex items-center gap-2">
        <ConfirmButton
          label="Import"
          confirmLabel="Copy this file in?"
          variant="secondary"
          busy={busy}
          disabled={trimmedPath === ""}
          title={trimmedPath === "" ? "Enter a path first" : undefined}
          onConfirm={submit}
        />
        <Button size="sm" variant="ghost" disabled={busy} onClick={() => setOpen(false)}>
          Close
        </Button>
      </div>
      {result && <ImportNote result={result} />}
    </div>
  );
}

/** The daemon's own sentence about the import it just started, with where the file lands. */
function ImportNote({ result }: { result: ModelImportReply }) {
  return (
    <div role="status" aria-label="import started" className="space-y-1">
      <p className="font-sans text-sm text-ink-muted">
        <SafeText value={result.note} />
      </p>
      <p className="font-data text-xs text-ink-faint">
        <SafeText value={result.dest} />
      </p>
    </div>
  );
}
