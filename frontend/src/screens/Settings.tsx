import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Panel } from "../components/ui/Panel";

/**
 * Settings — placeholder until task #30 lands the real sidebar-groups view.
 * Until then it hosts the design system's living style proof (migrated from
 * the pre-shell App.tsx): the odometer card on the raised ground, the truth
 * vocabulary, and the three button voices. Deleting this section must never
 * orphan a token — everything here is semantic utilities only.
 */
export function SettingsScreen() {
  return (
    <div className="space-y-8 p-10">
      <header className="max-w-xl space-y-4">
        <p className="font-data text-xs tracking-widest text-ink-faint uppercase">
          settings · every knob, one place
        </p>
        <h1 className="font-display text-hero font-semibold text-ink">Settings</h1>
        <p className="font-voice text-lg text-ink-muted italic">
          Everything I can be told will live here; today it keeps the design system&rsquo;s
          living proof.
        </p>
      </header>

      {/* Raised ground: machine facts in the data voice. */}
      <Panel ground="raised" className="max-w-xl space-y-4 p-5">
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <p className="font-display text-3xl font-semibold tracking-tight tabular-nums">0</p>
            <p className="font-data text-xs text-ink-faint">tokens avoided this week</p>
          </div>
          <Badge tone="accent">odometer</Badge>
        </div>
        <div className="space-y-1 border-t border-line pt-4 font-data text-xs text-ink-muted">
          <p>daemon: state lives in the beacon, top right</p>
        </div>
      </Panel>

      {/* Truth vocabulary — the five verdicts, plus a held approval. */}
      <div className="flex max-w-xl flex-wrap items-center gap-2">
        <Badge tone="success">verified</Badge>
        <Badge tone="accent">changed</Badge>
        <Badge tone="neutral">queued</Badge>
        <Badge tone="warning">approval held</Badge>
        <Badge tone="danger">refused</Badge>
      </div>

      <div className="flex max-w-xl flex-wrap items-center gap-3 border-t border-line pt-6">
        <Button>Ask Pam</Button>
        <Button variant="ghost">Activity</Button>
        <Button variant="danger">Revoke access</Button>
      </div>
    </div>
  );
}
