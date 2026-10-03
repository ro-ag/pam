import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { ConfirmButton } from "../components/ui/ConfirmButton";
import { FailureNote } from "../components/ui/FailureNote";
import { SelectField, TextArea, TextField } from "../components/ui/Fields";
import { fieldLabelClasses } from "../components/ui/field";
import { Panel } from "../components/ui/Panel";
import { SafeText } from "../components/ui/SafeText";
import { TypedConfirm } from "../components/ui/TypedConfirm";
import {
  CONFIRM_NETWORK,
  connectorsList,
  networkGet,
  networkSet,
  networkTest,
  toBridgeFailure,
  type BridgeFailure,
  type ConnectorSummary,
  type NetworkGetReply,
  type NetworkPatch,
  type NetworkRoute,
  type NetworkTestResult,
  type ProxyAuth,
} from "../lib/ipc";
import { escapeInvisible } from "../lib/safeText";
import { exactTime, relativeTime } from "../lib/time";

/**
 * Settings → Network: how PAM reaches connector services and download hosts
 * (spec docs/specs/2026-10-02-enterprise-network-and-engine-delivery.md).
 *
 * One bounded form with an explicit Save. The editor shows a draft layered over what the daemon
 * reports; Save sends exactly the validated draft the editor shows, as a patch of the fields that
 * changed. The proxy password is write-only: it is never read back, the reply only says whether
 * one is stored. A proxy, password or CA bundle that is set or changed asks for the typed phrase
 * `network`, because a TLS-inspecting proxy can read what PAM sends to connectors. A field a
 * managed policy owns is shown read-only.
 */

// --- validation -------------------------------------------------------------

const encoder = new TextEncoder();
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;
const SCHEME = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i;
const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function bytes(value: string): number {
  return encoder.encode(value).length;
}

/** The authority (`user@host:port`) and what follows it, split at the first `/`, `?` or `#`. */
function splitAuthority(rest: string): { authority: string; tail: string } {
  const cut = rest.search(/[/?#]/);
  return cut === -1
    ? { authority: rest, tail: "" }
    : { authority: rest.slice(0, cut), tail: rest.slice(cut) };
}

/** `host`, `host:port`, `[v6]` or `[v6]:port` into its parts; null when it is none of those. */
function splitHostPort(authority: string): { host: string; port: string | null } | null {
  const bracket = /^(\[[0-9a-f:.]+\])(?::(\d+))?$/i.exec(authority);
  if (bracket) return { host: bracket[1], port: bracket[2] ?? null };
  const plain = /^([^:\s/?#@[\]]+)(?::(\d+))?$/.exec(authority);
  return plain ? { host: plain[1], port: plain[2] ?? null } : null;
}

export interface Checked<T> {
  /** The normalized value, or null for "empty". Absent when there is an error. */
  value?: T;
  error?: string;
}

/**
 * The proxy rules of the spec's settings table: http or https, host, an explicit port, no
 * userinfo, query or fragment, nothing after an optional `/`, at most 255 bytes. The daemon
 * validates again; this only says why before the round trip.
 */
export function checkProxyUrl(raw: string): Checked<string | null> {
  const text = raw.trim();
  if (!text) return { value: null };
  if (bytes(text) > 255) return { error: "The proxy address is longer than 255 bytes." };
  if (CONTROL.test(text)) return { error: "The proxy address has a control character in it." };
  const match = SCHEME.exec(text);
  if (!match) {
    return {
      error: `Add the scheme: did you mean http://${text}? Use an http:// or https:// proxy address with its port.`,
    };
  }
  const scheme = match[1].toLowerCase();
  if (scheme.startsWith("socks")) {
    return {
      error:
        "SOCKS proxies are not supported. Use an http:// or https:// proxy address with its port.",
    };
  }
  if (scheme !== "http" && scheme !== "https") {
    return { error: "Only http:// and https:// proxy addresses are supported." };
  }
  const { authority, tail } = splitAuthority(match[2]);
  if (authority.includes("@")) {
    return {
      error:
        "Leave the user name and password out of the address; enter them in the fields below.",
    };
  }
  if (tail.includes("?")) return { error: "The proxy address cannot have a query." };
  if (tail.includes("#")) return { error: "The proxy address cannot have a fragment." };
  if (tail !== "" && tail !== "/") return { error: "The proxy address cannot have a path." };
  const parts = splitHostPort(authority);
  if (!parts)
    return { error: "Enter the proxy as host:port, for example proxy.corp.example:3128." };
  if (parts.port === null) {
    return {
      error: `Add the port, for example ${scheme}://${parts.host}:3128. PAM does not guess one.`,
    };
  }
  const port = Number(parts.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { error: "The proxy port must be between 1 and 65535." };
  }
  return { value: `${scheme}://${parts.host.toLowerCase()}:${port}` };
}

/** A host a mirror may not name: loopback, link-local (the metadata address), unspecified, multicast. */
function refusedMirrorHost(host: string): boolean {
  const name = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (name === "localhost" || name.endsWith(".localhost")) return true;
  const v4 = IPV4.exec(name);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 127 || a === 0 || (a === 169 && b === 254) || (a >= 224 && a <= 239);
  }
  if (name.includes(":")) {
    return name === "::1" || name === "::" || name.startsWith("fe80:") || name.startsWith("ff");
  }
  return false;
}

/**
 * The mirror rules: https only, a host (a name or an address, never loopback, link-local or
 * unspecified), no userinfo, query or fragment, no `.` or `..` segments, at most 512 bytes,
 * normalized with a trailing slash. An empty field clears the mirror.
 */
export function checkMirrorUrl(raw: string): Checked<string | null> {
  const text = raw.trim();
  if (!text) return { value: null };
  if (bytes(text) > 512) return { error: "The mirror address is longer than 512 bytes." };
  if (CONTROL.test(text)) return { error: "The mirror address has a control character in it." };
  const match = SCHEME.exec(text);
  if (!match || match[1].toLowerCase() !== "https") {
    return { error: "A mirror must be an https:// address." };
  }
  const { authority, tail } = splitAuthority(match[2]);
  if (authority.includes("@")) {
    return { error: "Leave the user name and password out of the mirror address." };
  }
  if (tail.includes("?")) return { error: "The mirror address cannot have a query." };
  if (tail.includes("#")) return { error: "The mirror address cannot have a fragment." };
  const parts = splitHostPort(authority);
  if (!parts) return { error: "Enter the mirror as https://host/path/." };
  if (parts.port !== null && (Number(parts.port) < 1 || Number(parts.port) > 65535)) {
    return { error: "The mirror port must be between 1 and 65535." };
  }
  if (refusedMirrorHost(parts.host)) {
    return {
      error:
        "A mirror cannot be on this computer or a link-local address; use your organisation's mirror host.",
    };
  }
  if (tail.split("/").some((segment) => segment === "." || segment === "..")) {
    return { error: "The mirror address cannot contain . or .. path segments." };
  }
  const path = tail === "" ? "/" : tail.endsWith("/") ? tail : `${tail}/`;
  const port = parts.port === null ? "" : `:${Number(parts.port)}`;
  return { value: `https://${parts.host.toLowerCase()}${port}${path}` };
}

/** The portable no-proxy grammar: `*`, a host or domain, an IP literal, or an IP range. */
export function checkNoProxy(
  raw: string,
  cidrSupported: boolean,
  curlVersion: string | undefined,
): Checked<string[]> {
  const seen = new Set<string>();
  const list: string[] = [];
  const entries = raw
    .split(/[\n,]/)
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry !== "");
  for (const entry of entries) {
    if (bytes(entry) > 255)
      return { error: `"${entry.slice(0, 40)}…" is longer than 255 bytes.` };
    if (CONTROL.test(entry))
      return { error: "A no-proxy entry has a control character in it." };
    if (entry === "<local>") {
      return { error: "<local> is not supported; list the host names or ranges instead." };
    }
    if (entry.includes("://")) {
      return { error: `"${entry}" is a URL; list only the host name, domain or address.` };
    }
    if (entry.includes("/")) {
      if (!/^[0-9a-f:.]+\/\d{1,3}$/.test(entry)) {
        return { error: `"${entry}" is not a valid address range such as 10.0.0.0/8.` };
      }
      if (!cidrSupported) {
        return {
          error: `Address ranges need curl 7.86 or newer; this computer has ${curlVersion ?? "an older curl"}. List single addresses instead.`,
        };
      }
    } else if (entry !== "*") {
      const single = /^[^:]*:\d+$/.test(entry) && !entry.startsWith("[");
      if (single) return { error: `"${entry}" has a port; no-proxy entries match hosts only.` };
      if (entry.includes("*") || /\s/.test(entry)) {
        return {
          error: `"${entry}" has a wildcard or a space; use a domain such as .corp.example.`,
        };
      }
    }
    if (!seen.has(entry)) {
      seen.add(entry);
      list.push(entry);
    }
  }
  if (list.length > 64) return { error: "At most 64 no-proxy entries are allowed." };
  return { value: list };
}

export function checkUsername(raw: string): Checked<string | null> {
  const text = raw.trim();
  if (!text) return { value: null };
  if (bytes(text) > 128) return { error: "The user name is longer than 128 bytes." };
  if (text.includes(":")) return { error: "The user name cannot contain a colon." };
  if (CONTROL.test(text)) return { error: "The user name has a control character in it." };
  return { value: text };
}

/** An absolute path on macOS or Windows (drive letter or UNC share). */
export function checkCaPath(raw: string): Checked<string | null> {
  const text = raw.trim();
  if (!text) return { value: null };
  if (CONTROL.test(text)) return { error: "The path has a control character in it." };
  if (!/^(\/|[a-z]:[\\/]|\\\\)/i.test(text)) {
    return { error: "Give the full path of the PEM file, starting from the root of the disk." };
  }
  return { value: text };
}

// --- the draft ---------------------------------------------------------------

interface Form {
  proxyUrl: string;
  auth: ProxyAuth;
  username: string;
  /** Write-only: typed here, sent once, never filled from a reply. */
  password: string;
  noProxy: string;
  caPath: string;
  engineMirror: string;
  modelsMirror: string;
}

const SAVE_FIELDS: readonly (keyof Form)[] = [
  "proxyUrl",
  "auth",
  "username",
  "password",
  "noProxy",
  "engineMirror",
  "modelsMirror",
];

function baseForm(reply: NetworkGetReply | undefined): Form {
  const settings = reply?.settings;
  return {
    proxyUrl: settings?.proxy?.url ?? "",
    auth: settings?.proxy?.auth ?? "none",
    username: settings?.proxy?.username ?? "",
    password: "",
    noProxy: (settings?.no_proxy ?? []).join("\n"),
    caPath: settings?.ca_bundle?.source_path ?? "",
    engineMirror: settings?.engine_mirror ?? "",
    modelsMirror: settings?.models_mirror ?? "",
  };
}

type Errors = Partial<Record<keyof Form, string>>;

interface Check {
  errors: Errors;
  /** The patch Save sends: only what differs from what the daemon reports. */
  patch: NetworkPatch;
  /** True when the patch sets or changes a proxy or a password: the typed phrase is needed. */
  needsPhrase: boolean;
  /** The CA path, when it is valid and non-empty. */
  caPath: string | null;
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((item, index) => item === b[index]);
}

/** Validates the draft the editor shows and derives from it the patch Save would send. */
export function checkForm(form: Form, reply: NetworkGetReply | undefined): Check {
  const errors: Errors = {};
  const patch: NetworkPatch = {};
  const settings = reply?.settings;
  let needsPhrase = false;

  const proxy = checkProxyUrl(form.proxyUrl);
  const username = checkUsername(form.username);
  if (proxy.error) errors.proxyUrl = proxy.error;
  if (username.error && form.auth !== "none") errors.username = username.error;
  if (form.password) {
    if (CONTROL.test(form.password)) {
      errors.password = "A password cannot contain a control character such as a line break.";
    } else if (form.auth === "none") {
      errors.password = "Choose Basic or Any as the sign-in mode to use a password.";
    } else if (proxy.value === null && !errors.proxyUrl) {
      errors.proxyUrl =
        "Enter the proxy address first; the password is used only with a proxy.";
    }
  }
  if (!errors.proxyUrl && !errors.username) {
    if (proxy.value === null || proxy.value === undefined) {
      if (settings?.proxy) patch.proxy = null;
    } else {
      const next = {
        url: proxy.value,
        auth: form.auth,
        username: form.auth === "none" ? null : (username.value ?? null),
      };
      const current = settings?.proxy;
      if (
        !current ||
        current.url !== next.url ||
        current.auth !== next.auth ||
        (current.username ?? null) !== next.username
      ) {
        patch.proxy = next;
        needsPhrase = true;
      }
    }
  }
  if (form.password && !errors.password && !errors.proxyUrl) {
    patch.credential = { set: form.password };
    needsPhrase = true;
  }

  const noProxy = checkNoProxy(
    form.noProxy,
    reply?.curl?.supports_cidr_no_proxy ?? true,
    reply?.curl?.version,
  );
  if (noProxy.error) errors.noProxy = noProxy.error;
  else if (noProxy.value && !sameList(noProxy.value, settings?.no_proxy ?? [])) {
    patch.no_proxy = noProxy.value;
  }

  for (const [key, field] of [
    ["engineMirror", "engine_mirror"],
    ["modelsMirror", "models_mirror"],
  ] as const) {
    const mirror = checkMirrorUrl(form[key]);
    if (mirror.error) errors[key] = mirror.error;
    else if ((mirror.value ?? null) !== (settings?.[field] ?? null)) {
      patch[field] = mirror.value ?? null;
    }
  }

  const ca = checkCaPath(form.caPath);
  if (ca.error) errors.caPath = ca.error;
  return { errors, patch, needsPhrase, caPath: ca.value ?? null };
}

// --- presentation helpers -------------------------------------------------------

const ROUTE_PHRASE: Record<NetworkRoute, string> = {
  direct: "direct connection",
  bypass: "direct, matched your no-proxy list",
  proxy: "through the proxy",
};

const STAGE_PHRASE: Record<NetworkTestResult["stage"], string> = {
  connect: "connecting, and the first connection did not complete",
  proxy: "connected to the proxy, then stopped",
  tunnel: "the proxy tunnel opened, then stopped before TLS",
  tls: "the TLS handshake verified, then stopped before an answer",
  http: "an HTTP answer came back",
};

/**
 * The stage word for a result. "Connected to the proxy" is only true on a proxy route, so a
 * `proxy` stage on a direct or bypassed route is the first connection itself: say "connecting".
 */
function stagePhrase(result: NetworkTestResult): string {
  const stage = result.stage === "proxy" && result.route !== "proxy" ? "connect" : result.stage;
  return STAGE_PHRASE[stage];
}

/** The daemon's sentences end with a full stop and FailureNote adds one; keep a single one. */
function noStop(sentence: string): string {
  return sentence.replace(/\.+$/, "");
}

/** The first 12 hex characters of a digest, the length the audit row and the card show. */
function digestPrefix(sha256: string): string {
  return sha256.slice(0, 12);
}

function Field({
  label,
  error,
  hint,
  children,
}: {
  label: string;
  error?: string;
  hint?: ReactNode;
  children: ReactNode;
}) {
  return (
    <label className="block space-y-1">
      <span className={fieldLabelClasses}>{label}</span>
      {children}
      {hint && <span className="block font-sans text-sm text-ink-muted">{hint}</span>}
      {error && (
        <span role="alert" className="block select-text font-sans text-sm text-danger">
          {error}
        </span>
      )}
    </label>
  );
}

const LOCKED_NOTE = "Set by your organisation";

// --- the test panel ---------------------------------------------------------------

function ResultRow({
  result,
  proxyHost,
}: {
  result: NetworkTestResult;
  proxyHost: string | null;
}) {
  const route =
    result.route === "proxy" && proxyHost
      ? `through the proxy ${proxyHost}`
      : ROUTE_PHRASE[result.route];
  if (result.ok) {
    const verified = result.stage === "tls" || result.stage === "http";
    return (
      <li
        aria-label={`result ${result.target}`}
        className="select-text space-y-1 rounded-card border border-line p-3"
      >
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone="success">reached</Badge>
          <span className="font-data text-xs text-ink">
            {result.target} · <SafeText value={result.host} />
          </span>
        </div>
        <p className="font-sans text-sm text-ink-muted">
          Route: {route}.{verified ? " The server's TLS certificate was verified." : ""}
          {result.http_status !== null && ` It answered HTTP ${result.http_status}`}
          {result.http_status !== null &&
            ", and any answer, even 401 or 404, means the network path works."}
        </p>
      </li>
    );
  }
  const failure: BridgeFailure = {
    cause: escapeInvisible(result.cause ?? "unknown_failure"),
    detail: noStop(escapeInvisible(result.detail ?? "the test failed without saying why")),
    recovery: escapeInvisible(
      result.recovery ?? "Check the proxy and certificate settings, then test again.",
    ),
  };
  return (
    <li aria-label={`result ${result.target}`}>
      <FailureNote
        failure={failure}
        label={`${result.target} · ${escapeInvisible(result.host)}`}
      >
        <p className="font-data text-xs text-ink-muted">
          Route: {route}. Reached: {stagePhrase(result)}.
        </p>
      </FailureNote>
    </li>
  );
}

function TestPanel({ reply, dirty }: { reply: NetworkGetReply | undefined; dirty: boolean }) {
  const connectors = useQuery({ queryKey: ["connectors"], queryFn: connectorsList });
  const [chosen, setChosen] = useState<string | null>(null);
  const options: ConnectorSummary[] = (connectors.data?.connectors ?? []).filter(
    (connector) => connector.enabled && (!connector.needs_base_url || connector.base_url),
  );
  const target = options.some((connector) => connector.id === chosen)
    ? chosen
    : (options[0]?.id ?? null);

  const test = useMutation({
    mutationFn: (id: string) => networkTest(id),
  });
  const proxyUrl = reply?.settings.proxy?.url ?? null;
  const proxyHost = proxyUrl ? proxyUrl.replace(/^https?:\/\//, "") : null;
  const loadFailure = connectors.isError ? toBridgeFailure(connectors.error) : null;
  const testFailure = test.isError ? toBridgeFailure(test.error) : null;

  return (
    <Panel ground="raised" className="space-y-4 p-4">
      <p className="font-data text-xs text-ink-faint">Test network settings</p>
      <p className="font-sans text-sm text-ink-muted">
        Reaches the chosen connector's address the way PAM would, with the saved settings. It
        sends no credentials; any answer, even 401 or 404, shows the network path works.
        {dirty && " You have unsaved edits; save them first to test them."}
      </p>
      {loadFailure && <FailureNote failure={loadFailure} label="connectors" />}
      {!loadFailure && !connectors.isPending && options.length === 0 && (
        <p className="font-sans text-sm text-ink-muted">
          No connector is enabled with an address yet, so there is nothing to test. Set one up
          in Connectors, then come back.
        </p>
      )}
      <div className="flex flex-wrap items-end gap-2">
        <label className="min-w-0 flex-1 space-y-1">
          <span className={fieldLabelClasses}>Connector to test</span>
          <SelectField
            aria-label="connector to test"
            value={target ?? ""}
            disabled={options.length === 0 || test.isPending}
            onChange={(event) => {
              setChosen(event.target.value);
              test.reset();
            }}
          >
            {options.map((connector) => (
              <option key={connector.id} value={connector.id}>
                {connector.base_url
                  ? `${connector.name} · ${connector.base_url}`
                  : connector.name}
              </option>
            ))}
          </SelectField>
        </label>
        <Button
          size="sm"
          variant="secondary"
          disabled={target === null || test.isPending}
          title={target === null ? "Enable a connector with an address first" : undefined}
          onClick={() => {
            if (target !== null) test.mutate(target);
          }}
        >
          {test.isPending && (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          )}
          {test.isPending ? "Testing…" : "Test network settings"}
        </Button>
      </div>
      <div aria-live="polite" className="space-y-2">
        {test.isPending && (
          <p className="font-data text-xs text-ink-muted">
            Reaching the connector through your settings…
          </p>
        )}
        {testFailure && <FailureNote failure={testFailure} label="network test" />}
        {test.data && (
          <ul className="space-y-2" aria-label="test results">
            {test.data.results.length === 0 && (
              <li className="font-sans text-sm text-ink-muted">
                The daemon found nothing to test for that connector.
              </li>
            )}
            {test.data.results.map((result) => (
              <ResultRow
                key={`${result.target}:${result.host}`}
                result={result}
                proxyHost={proxyHost}
              />
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
}

// --- the section ----------------------------------------------------------------------

type Job =
  | { kind: "save"; confirmation?: string }
  | { kind: "ca-import"; confirmation: string }
  | { kind: "ca-remove" }
  | { kind: "password-clear" };

/** The Network block Settings mounts between Connectors and Daemon. */
export function SettingsNetworkSection() {
  const queryClient = useQueryClient();
  const network = useQuery({ queryKey: ["network"], queryFn: networkGet });
  const reply = network.data;
  const [draft, setDraft] = useState<Partial<Form>>({});
  const [confirming, setConfirming] = useState<"save" | "ca-import" | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const form: Form = { ...baseForm(reply), ...draft };
  const check = checkForm(form, reply);
  const dirty = Object.keys(check.patch).length > 0 || draft.caPath !== undefined;

  const apply = useMutation({
    // The password is read from the draft inside the mutation function, so only the job kind
    // is kept in React Query's mutation cache.
    mutationFn: (job: Job) => {
      const patch: NetworkPatch =
        job.kind === "save"
          ? check.patch
          : job.kind === "ca-import"
            ? { ca_bundle: check.caPath === null ? null : { path: check.caPath } }
            : job.kind === "ca-remove"
              ? { ca_bundle: null }
              : { credential: { clear: true } };
      return networkSet(patch, "confirmation" in job ? job.confirmation : undefined);
    },
    onMutate: () => setNote(null),
    onSuccess: (reply, job) => {
      setConfirming(null);
      const warning =
        reply && typeof reply === "object" && typeof reply.warning === "string"
          ? reply.warning
          : null;
      setDraft((current) => {
        const rest = { ...current };
        const drop: readonly (keyof Form)[] =
          job.kind === "save"
            ? SAVE_FIELDS
            : job.kind === "password-clear"
              ? ["password"]
              : ["caPath"];
        for (const key of drop) delete rest[key];
        return rest;
      });
      const done =
        job.kind === "save"
          ? "Saved. Run the test below to check the new settings."
          : job.kind === "ca-import"
            ? "CA bundle imported. Run the test below to check it."
            : job.kind === "ca-remove"
              ? "CA bundle removed."
              : "Stored password cleared.";
      setNote(warning ? `${done} ${warning}` : done);
    },
    onError: () => setConfirming(null),
    onSettled: () => void queryClient.invalidateQueries({ queryKey: ["network"] }),
  });

  function edit(change: Partial<Form>) {
    setDraft((current) => ({ ...current, ...change }));
    setNote(null);
    apply.reset();
  }

  const effective = reply?.effective ?? {};
  const proxyLocked = effective.proxy?.locked === true;
  const passwordLocked = (effective.credential ?? effective.proxy)?.locked === true;
  const noProxyLocked = effective.no_proxy?.locked === true;
  const caLocked = effective.ca_bundle?.locked === true;
  const engineLocked = effective.engine_mirror?.locked === true;
  const modelsLocked = effective.models_mirror?.locked === true;

  const loading = !network.isSuccess;
  const busy = loading || network.isFetching || apply.isPending;
  const hasErrors = Object.entries(check.errors).some(
    ([field, message]) => field !== "caPath" && message,
  );
  const patchEmpty = Object.keys(check.patch).length === 0;
  const saveBlocker = hasErrors
    ? "Fix the highlighted fields first"
    : patchEmpty
      ? "Nothing has changed"
      : undefined;
  const caBundle = reply?.settings.ca_bundle ?? null;
  // Windows: the daemon takes no bundle file; the OS certificate store is the way.
  const caUnsupported = caBundle?.supported === false;
  const bundle = caBundle?.sha256 ? caBundle : null;
  const credential = reply?.settings.credential;
  const allowedHosts = reply?.settings.mirror_allowed_hosts ?? [];
  const failure = network.isError
    ? toBridgeFailure(network.error)
    : apply.isError
      ? toBridgeFailure(apply.error)
      : null;
  const needsPassword =
    form.auth !== "none" &&
    form.proxyUrl.trim() !== "" &&
    !(credential?.present ?? false) &&
    form.password === "";

  return (
    <div className="max-w-content space-y-3">
      <Panel ground="raised" className="select-text space-y-2 p-4">
        <p className="font-data text-xs text-ink-faint">What this changes</p>
        <p className="font-sans text-sm text-ink-muted">
          These settings apply to requests PAM makes to connector services and to downloads of
          the inference engine and of models. They never apply to the engine's own local socket,
          and nothing here is read from environment variables: only what you save on this page
          is used.
        </p>
        {reply?.ignored_env && reply.ignored_env.length > 0 && (
          <p className="font-data text-xs text-warning">
            Ignored in the daemon's environment: {reply.ignored_env.join(", ")}. PAM does not
            import them.
          </p>
        )}
      </Panel>

      {failure && <FailureNote failure={failure} label="network" />}
      {loading && !failure && (
        <p className="font-data text-xs text-ink-faint">reading the network settings…</p>
      )}

      <Panel ground="raised" className="space-y-4 p-4">
        <p className="font-data text-xs text-ink-faint">Proxy</p>
        <p className="font-sans text-sm text-ink-muted">
          Use an http:// or https:// proxy address with its port. SOCKS and automatic
          configuration (PAC) scripts are not supported. A user name and password are stored in
          this computer's keychain. With an http:// proxy and Basic sign-in the password is sent
          to the proxy without encryption on your network.
        </p>
        {reply?.curl && !reply.curl.supports_proxy && (
          <p className="font-sans text-sm text-warning">
            The curl on this computer ({reply.curl.version}) is too old to use a proxy.
          </p>
        )}
        {proxyLocked && <Badge tone="warning">{LOCKED_NOTE}</Badge>}
        <div className="grid grid-cols-1 gap-3">
          <Field label="Proxy address" error={check.errors.proxyUrl}>
            <TextField
              aria-label="proxy URL"
              value={form.proxyUrl}
              disabled={busy || proxyLocked}
              autoComplete="off"
              spellCheck={false}
              placeholder="http://proxy.corp.example:3128"
              onChange={(event) => edit({ proxyUrl: event.target.value })}
            />
          </Field>
          <Field label="Sign-in">
            <SelectField
              aria-label="proxy sign-in"
              value={form.auth}
              disabled={busy || proxyLocked}
              onChange={(event) => edit({ auth: event.target.value as ProxyAuth })}
            >
              <option value="none">None</option>
              <option value="basic">Basic</option>
              <option value="anyauth">Any (Basic, Digest or NTLM)</option>
            </SelectField>
          </Field>
          <Field
            label="User name"
            error={check.errors.username}
            hint={form.auth === "anyauth" ? "For NTLM, write it as DOMAIN\\user." : undefined}
          >
            <TextField
              aria-label="proxy user name"
              value={form.username}
              disabled={busy || proxyLocked || form.auth === "none"}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => edit({ username: event.target.value })}
            />
          </Field>
          <Field label="Password" error={check.errors.password}>
            <TextField
              type="password"
              aria-label="proxy password"
              autoComplete="new-password"
              value={form.password}
              disabled={busy || passwordLocked || form.auth === "none"}
              placeholder={credential?.present ? "Stored; type to replace it" : "Not set"}
              onChange={(event) => edit({ password: event.target.value })}
            />
          </Field>
          <div className="flex flex-wrap items-center gap-2">
            {credential?.present ? (
              <Badge tone="success">password is set</Badge>
            ) : (
              <Badge>no password stored</Badge>
            )}
            {credential && !credential.store_available && (
              <span className="font-data text-xs text-warning">
                the OS credential store is unavailable; see the daemon log
              </span>
            )}
            <ConfirmButton
              label="Clear password"
              confirmLabel="clear it?"
              busy={apply.isPending}
              disabled={loading || passwordLocked || !credential?.present}
              title={!credential?.present ? "No password is stored" : undefined}
              onConfirm={() => apply.mutate({ kind: "password-clear" })}
            />
            <span className="font-sans text-sm text-ink-muted">
              The password is never shown again after it is saved.
            </span>
          </div>
          {needsPassword && (
            <p className="font-sans text-sm text-warning">
              This sign-in mode needs a password, and none is stored. The test will report that
              the proxy wants authentication.
            </p>
          )}
        </div>
        <Field
          label="No-proxy list"
          error={check.errors.noProxy}
          hint="One entry per line (commas also work): a host or domain such as .corp.example, an IP address, or a range such as 10.0.0.0/8. Loopback never uses the proxy."
        >
          <TextArea
            aria-label="no-proxy list"
            rows={4}
            value={form.noProxy}
            disabled={busy || noProxyLocked}
            spellCheck={false}
            onChange={(event) => edit({ noProxy: event.target.value })}
          />
        </Field>
        {noProxyLocked && <Badge tone="warning">{LOCKED_NOTE}</Badge>}
      </Panel>

      <Panel ground="raised" className="space-y-4 p-4">
        <p className="font-data text-xs text-ink-faint">Certificate authority</p>
        <p className="font-sans text-sm text-ink-muted">
          If your organisation inspects TLS and this computer's keychain or certificate store
          already trusts its root, leave this empty. Otherwise import a PEM file of the
          certificates PAM should trust. It replaces the system's trust for PAM's requests, so
          include every root those services need. A proxy that inspects TLS can read the
          credentials PAM sends to connectors.
        </p>
        {reply?.curl && (
          <p className="font-data text-xs text-ink-faint">
            curl {reply.curl.version} · {reply.curl.backend}
          </p>
        )}
        {caLocked && <Badge tone="warning">{LOCKED_NOTE}</Badge>}
        {bundle ? (
          <div
            aria-label="imported CA bundle"
            className="select-text space-y-1 rounded-card border border-line p-3"
          >
            <p className="font-sans text-sm text-ink">
              PAM holds a private copy: {bundle.certificates ?? 0}{" "}
              {(bundle.certificates ?? 0) === 1 ? "certificate" : "certificates"}, SHA-256{" "}
              <span className="font-data text-xs">{digestPrefix(bundle.sha256 ?? "")}…</span>
            </p>
            {bundle.source_path && (
              <p className="font-data text-xs text-ink-muted">
                imported from <SafeText value={bundle.source_path} />
                {bundle.imported_ts !== undefined && (
                  <>
                    {" "}
                    <span title={exactTime(bundle.imported_ts)}>
                      {relativeTime(bundle.imported_ts)}
                    </span>
                  </>
                )}
              </p>
            )}
            {bundle.source_changed && (
              <p className="font-sans text-sm text-warning">
                The source file changed since it was imported. PAM still uses the copy it made;
                import again to pick up the change.
              </p>
            )}
          </div>
        ) : (
          <p className="font-sans text-sm text-ink-muted">
            {caUnsupported ? (
              <SafeText
                value={caBundle?.reason ?? "A CA bundle file is not used on this computer."}
              />
            ) : (
              "No CA bundle is set; PAM uses this computer's own trust."
            )}
          </p>
        )}
        <Field label="PEM file path" error={check.errors.caPath}>
          <TextField
            aria-label="CA bundle path"
            value={form.caPath}
            disabled={busy || caLocked || caUnsupported}
            autoComplete="off"
            spellCheck={false}
            placeholder="/etc/corp/ca.pem"
            onChange={(event) => edit({ caPath: event.target.value })}
          />
        </Field>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="secondary"
            disabled={
              busy ||
              caLocked ||
              caUnsupported ||
              check.caPath === null ||
              confirming === "ca-import"
            }
            title={check.caPath === null ? "Give the path of a PEM file first" : undefined}
            onClick={() => setConfirming("ca-import")}
          >
            {bundle ? "Import again" : "Import CA bundle"}
          </Button>
          <ConfirmButton
            label="Remove CA bundle"
            confirmLabel="remove it?"
            busy={apply.isPending}
            disabled={loading || caLocked || caUnsupported || bundle === null}
            title={bundle === null ? "No CA bundle is set" : undefined}
            onConfirm={() => apply.mutate({ kind: "ca-remove" })}
          />
          <span className="font-sans text-sm text-ink-muted">
            PAM copies the file once and never reads the original again.
          </span>
        </div>
        {confirming === "ca-import" && (
          <TypedConfirm
            phrase={CONFIRM_NETWORK}
            title="Trust these certificates?"
            confirmLabel="Import CA bundle"
            busy={apply.isPending}
            onCancel={() => setConfirming(null)}
            onConfirm={(typed) => apply.mutate({ kind: "ca-import", confirmation: typed })}
          >
            <p>
              PAM will trust any certificate this bundle signs for its connector and download
              requests. Anyone who holds the bundle's keys, such as a TLS-inspecting proxy, can
              read the credentials PAM sends to connectors.
            </p>
          </TypedConfirm>
        )}
      </Panel>

      <Panel ground="raised" className="space-y-4 p-4">
        <p className="font-data text-xs text-ink-faint">Mirrors</p>
        <p className="font-sans text-sm text-ink-muted">
          An internal address to download from instead of GitHub (the inference engine) or
          Hugging Face (models). The size and SHA-256 checks built into PAM still apply to
          whatever the mirror serves. Leave empty to use the original hosts.
        </p>
        {(engineLocked || modelsLocked) && <Badge tone="warning">{LOCKED_NOTE}</Badge>}
        <div className="grid grid-cols-1 gap-3">
          <Field label="Engine mirror" error={check.errors.engineMirror}>
            <TextField
              aria-label="engine mirror URL"
              value={form.engineMirror}
              disabled={busy || engineLocked}
              autoComplete="off"
              spellCheck={false}
              placeholder="https://artifacts.corp.example/llama.cpp/b10938/"
              onChange={(event) => edit({ engineMirror: event.target.value })}
            />
          </Field>
          <Field label="Models mirror" error={check.errors.modelsMirror}>
            <TextField
              aria-label="models mirror URL"
              value={form.modelsMirror}
              disabled={busy || modelsLocked}
              autoComplete="off"
              spellCheck={false}
              placeholder="https://artifacts.corp.example/api/huggingfaceml/hf-remote/"
              onChange={(event) => edit({ modelsMirror: event.target.value })}
            />
          </Field>
        </div>
        {allowedHosts.length > 0 && (
          <p
            aria-label="allowed mirror hosts"
            className="select-text font-sans text-sm text-ink-muted"
          >
            Your organisation allows mirrors only on: {allowedHosts.join(", ")}. This list is
            set by policy and cannot be edited here.
          </p>
        )}
      </Panel>

      <Panel ground="raised" className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            disabled={busy || saveBlocker !== undefined}
            title={saveBlocker}
            onClick={() => {
              if (check.needsPhrase) setConfirming("save");
              else apply.mutate({ kind: "save" });
            }}
          >
            {apply.isPending && apply.variables?.kind === "save" && (
              <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
            )}
            Save network settings
          </Button>
          {dirty && <span className="font-data text-xs text-ink-muted">unsaved edits</span>}
          {note && <span className="select-text font-data text-xs text-ink-muted">{note}</span>}
        </div>
        {confirming === "save" && (
          <TypedConfirm
            phrase={CONFIRM_NETWORK}
            title="Change how PAM reaches the network?"
            confirmLabel="Save network settings"
            busy={apply.isPending}
            onCancel={() => setConfirming(null)}
            onConfirm={(typed) => apply.mutate({ kind: "save", confirmation: typed })}
          >
            <p>
              A proxy sits between PAM and your connector services. If it inspects TLS it can
              read the credentials PAM sends. Only continue with a proxy and password your
              organisation gave you.
            </p>
          </TypedConfirm>
        )}
      </Panel>

      <TestPanel reply={reply} dirty={dirty} />
    </div>
  );
}
