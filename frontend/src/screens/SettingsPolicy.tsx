import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { LoaderCircle, RefreshCw } from "lucide-react";
import type { ReactNode } from "react";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { FailureNote } from "../components/ui/FailureNote";
import { Panel } from "../components/ui/Panel";
import { SafeText } from "../components/ui/SafeText";
import {
  policyGet,
  policyReload,
  serviceInstall,
  toBridgeFailure,
  type PolicyBody,
  type PolicyState,
} from "../lib/ipc";
import { exactTime, relativeTime } from "../lib/time";

/**
 * Settings → Security → Managed policy: what governs this computer, read-only, and the one
 * button that re-reads it. The daemon owns every fact here; the screen only words them. A policy
 * file is administrator-authored text, so every path, reason and detail goes through `SafeText`.
 */

/** Every cached read that carries an `effective` block; a reload may change all of them. */
const EFFECTIVE_QUERIES = [
  ["profile"],
  ["grants"],
  ["flow-settings"],
  ["landing-policy"],
  ["connectors"],
  ["models"],
  ["curator"],
  ["retention"],
  ["network"],
] as const;

export const POLICY_KEY = ["policy"] as const;

/** The policy read every Settings page shares; a failed read renders nothing but the panel's note. */
export function usePolicy() {
  return useQuery({ queryKey: POLICY_KEY, queryFn: policyGet, retry: false });
}

const STATE_LABEL: Record<PolicyState, string> = {
  none: "no policy",
  active: "active",
  degraded: "degraded",
  last_good: "last good copy",
  frozen: "frozen",
};

/** Whether the state means the policy is in trouble and deserves a warning. */
export function isPolicyWarning(state: PolicyState): boolean {
  return state === "degraded" || state === "last_good" || state === "frozen";
}

function problemCount(policy: PolicyBody): number {
  return Math.max(policy.rejected_leaves, policy.diagnostics.length);
}

/** The state in the daemon's own words for the human: one sentence each. */
export function policySentence(policy: PolicyBody): string {
  const contact = policy.contact ? ` Contact ${policy.contact}.` : "";
  switch (policy.state) {
    case "none":
      return "No managed policy is installed on this computer.";
    case "active":
      return policy.organization
        ? `Managed by ${policy.organization}.`
        : "Managed by your organization's policy.";
    case "degraded": {
      const count = problemCount(policy);
      return `Your organization's policy has ${count} ${count === 1 ? "problem" : "problems"}; the settings affected are listed below.${contact}`;
    }
    case "last_good":
      return `The policy file on this computer cannot be read or trusted. PAM is using the last good copy${policy.revision ? ` (revision ${policy.revision})` : ""}.${contact}`;
    case "frozen":
      return `The policy file cannot be read or trusted. Changes that would widen what agents can do are paused until it is fixed.${contact}`;
  }
}

/** The one line every Settings page shows while a policy is present; nothing when there is none. */
export function PolicyStatusLine({ onOpen }: { onOpen: () => void }) {
  const policy = usePolicy();
  const body = policy.data;
  if (!body || body.state === "none") return null;
  const warning = isPolicyWarning(body.state);
  return (
    <div
      role="status"
      aria-label="managed policy status"
      className="flex flex-wrap items-center gap-2"
    >
      <Badge tone={warning ? "warning" : "neutral"}>
        {warning ? STATE_LABEL[body.state] : "managed"}
      </Badge>
      <span className="font-sans text-sm text-ink-muted">
        {warning ? policySentence(body) : "Managed by your organization's policy."}
      </span>
      <Button size="sm" variant="ghost" onClick={onOpen}>
        View policy
      </Button>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0 space-y-0.5">
      <dt className="font-data text-xs text-ink-faint">{label}</dt>
      <dd className="select-text font-data text-sm text-ink">{children}</dd>
    </div>
  );
}

function stamp(ts: number | null) {
  return ts === null ? "never" : <span title={exactTime(ts)}>{relativeTime(ts)}</span>;
}

function trustLine(policy: PolicyBody): string {
  const trust = policy.origin.trust;
  const parts: string[] = [trust.verdict];
  if (trust.code) parts.push(trust.code);
  if (trust.owner) parts.push(`owner ${trust.owner}`);
  if (trust.writable_by_user === true) parts.push("writable by you");
  if (trust.symlink === true) parts.push("symlink");
  if (trust.parents && trust.parents !== "ok") parts.push(`parents ${trust.parents}`);
  return parts.join(" · ");
}

function PolicyDetails({ policy }: { policy: PolicyBody }) {
  const trust = policy.origin.trust;
  const untrusted = trust.verdict === "untrusted";
  return (
    <>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
        {policy.organization && <Fact label="organization">{policy.organization}</Fact>}
        {policy.contact && (
          <Fact label="contact">
            <SafeText value={policy.contact} />
          </Fact>
        )}
        {policy.revision && (
          <Fact label="revision">
            <SafeText value={policy.revision} />
          </Fact>
        )}
        {policy.digest && <Fact label="digest">{policy.digest.slice(0, 12)}</Fact>}
        <Fact label="loaded">{stamp(policy.loaded_ts)}</Fact>
        <Fact label="last checked">{stamp(policy.checked_ts)}</Fact>
        {policy.origin.path && (
          <div className="min-w-0 space-y-0.5 sm:col-span-2">
            <dt className="font-data text-xs text-ink-faint">path</dt>
            <dd className="select-text font-data text-sm text-ink">
              <SafeText value={policy.origin.path} />
            </dd>
          </div>
        )}
        <div className="min-w-0 space-y-0.5 sm:col-span-2">
          <dt className="font-data text-xs text-ink-faint">trust</dt>
          <dd
            className={
              untrusted
                ? "select-text font-data text-sm text-warning"
                : "select-text font-data text-sm text-ink"
            }
          >
            {trustLine(policy)}
          </dd>
          {untrusted && trust.recovery && (
            <dd className="select-text font-data text-xs text-ink-muted">
              <SafeText value={trust.recovery} />
            </dd>
          )}
        </div>
        {policy.last_good && (
          <Fact label="last good copy">
            {policy.last_good.digest.slice(0, 12)} · {stamp(policy.last_good.loaded_ts)}
          </Fact>
        )}
      </dl>

      {policy.reason_detail && (
        <p className="select-text font-sans text-sm text-ink-muted">
          <SafeText value={policy.reason_detail} />
        </p>
      )}

      {policy.diagnostics.length > 0 && (
        <div className="space-y-1.5" role="group" aria-label="policy diagnostics">
          <p className="font-data text-xs text-ink-faint">Problems</p>
          <ul className="space-y-1.5">
            {policy.diagnostics.map((item, index) => (
              <li key={`${item.code}-${item.key}-${index}`} className="select-text space-y-0.5">
                <p className="font-data text-xs text-warning">
                  <SafeText value={item.code} />
                  {item.key && (
                    <>
                      {" · "}
                      <SafeText value={item.key} />
                    </>
                  )}
                </p>
                <p className="font-sans text-sm text-ink-muted">
                  <SafeText value={item.detail} />
                </p>
              </li>
            ))}
          </ul>
        </div>
      )}

      {policy.keys.length > 0 && (
        <div className="overflow-x-auto" role="group" aria-label="policy keys">
          <table className="w-full border-collapse">
            <thead>
              <tr className="text-left font-data text-xs text-ink-faint">
                <th className="pb-2 pr-3 font-medium">setting</th>
                <th className="pb-2 pr-3 font-medium">how</th>
                <th className="pb-2 font-medium">state</th>
              </tr>
            </thead>
            <tbody>
              {policy.keys.map((row) => (
                <tr key={row.key} className="border-t border-line">
                  <td className="py-2 pr-3 font-data text-xs text-ink">
                    <SafeText value={row.key} />
                  </td>
                  <td className="py-2 pr-3 font-data text-xs text-ink-muted">
                    {row.mode.join(", ")}
                  </td>
                  <td className="py-2 font-data text-xs">
                    <Badge
                      tone={
                        row.state === "applied"
                          ? "success"
                          : row.state === "held"
                            ? "warning"
                            : "danger"
                      }
                    >
                      {row.state}
                    </Badge>
                    {row.detail && (
                      <span className="ml-2 text-ink-muted">
                        <SafeText value={row.detail} />
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

export function PolicyPanel() {
  const queryClient = useQueryClient();
  const policy = usePolicy();
  const reload = useMutation({
    mutationFn: () => policyReload(),
    onSuccess: (fresh) => {
      queryClient.setQueryData(POLICY_KEY, fresh);
      // A re-read can change what any screen reports as managed.
      for (const key of EFFECTIVE_QUERIES) {
        void queryClient.invalidateQueries({ queryKey: key });
      }
    },
  });
  const install = useMutation({
    mutationFn: () => serviceInstall(),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["daemon"] });
      void queryClient.invalidateQueries({ queryKey: POLICY_KEY });
    },
  });

  const body = policy.data;
  const failure = reload.isError
    ? toBridgeFailure(reload.error)
    : install.isError
      ? toBridgeFailure(install.error)
      : policy.isError
        ? toBridgeFailure(policy.error)
        : null;
  const warning = body ? isPolicyWarning(body.state) : false;
  const needsLoginUnit =
    body?.compliance.login_unit.required === true &&
    body.compliance.login_unit.present === false;

  return (
    <Panel ground="raised" aria-label="managed policy" className="col-span-full space-y-4 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <p className="font-data text-xs text-ink-faint">Managed policy</p>
          {body && (
            <Badge tone={warning ? "warning" : body.state === "active" ? "success" : "neutral"}>
              {STATE_LABEL[body.state]}
            </Badge>
          )}
        </div>
        <Button
          size="sm"
          variant="secondary"
          disabled={reload.isPending || policy.isPending}
          onClick={() => reload.mutate()}
        >
          {reload.isPending ? (
            <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />
          ) : (
            <RefreshCw aria-hidden="true" className="size-3.5" />
          )}
          Check now
        </Button>
      </div>

      {body && (
        <p
          className={
            warning
              ? "select-text font-sans text-sm text-warning"
              : "select-text font-sans text-sm text-ink-muted"
          }
        >
          {policySentence(body)}
        </p>
      )}

      {needsLoginUnit && (
        <div className="flex flex-wrap items-center gap-3 rounded-card border border-line p-3">
          <p className="min-w-0 flex-1 font-sans text-sm text-warning">
            Your organization requires PAM to start at login.
          </p>
          <Button size="sm" disabled={install.isPending} onClick={() => install.mutate()}>
            Install
          </Button>
        </div>
      )}

      {body && body.state !== "none" && <PolicyDetails policy={body} />}

      {failure && <FailureNote failure={failure} label="policy" />}
    </Panel>
  );
}
