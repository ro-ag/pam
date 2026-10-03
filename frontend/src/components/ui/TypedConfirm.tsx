import { useState, type ReactNode } from "react";
import { Button } from "./Button";
import { TextField } from "./Fields";

/**
 * A typed confirmation for a decision that widens what agents may do (the relaxed profile, a
 * global grant). One click is not enough: the human types the phrase the bridge will demand
 * (`pam_gui::bridge::required_confirmation`), so the decision is read, not reflexed. Cancel is the
 * focused control — Enter on a freshly opened prompt never confirms — and Confirm stays disabled
 * until the phrase matches. The bridge re-checks the phrase in Rust, then asks again in a native
 * system dialog it draws itself ("Confirm in PAM", `pam_gui::confirm`) and sends the op only on
 * Allow. This prompt is the in-page wall against misclicks; the system dialog is the security
 * step, which the page cannot answer for the human.
 */
export function TypedConfirm({
  phrase,
  title,
  children,
  confirmLabel,
  busy,
  onConfirm,
  onCancel,
}: {
  /** What the human must type, e.g. "grant". */
  phrase: string;
  title: string;
  /** What is about to happen and how far it reaches. */
  children: ReactNode;
  confirmLabel: string;
  busy?: boolean;
  /** Called with the phrase as typed, to pass on to the bridge. */
  onConfirm: (typed: string) => void;
  onCancel: () => void;
}) {
  const [typed, setTyped] = useState("");
  const matches = typed.trim().toLowerCase() === phrase;
  const submit = () => {
    if (matches && !busy) onConfirm(typed.trim());
  };
  return (
    <div
      role="group"
      aria-label={title}
      className="space-y-3 rounded-card border border-warning/40 bg-warning-soft p-3"
    >
      <p className="font-sans text-sm font-medium text-ink">{title}</p>
      <div className="font-sans text-sm text-ink-muted">{children}</div>
      <label className="block space-y-1">
        <span className="block font-sans text-xs text-ink-muted">
          Type <span className="font-data text-ink">{phrase}</span> to continue
        </span>
        <TextField
          aria-label={`type ${phrase} to confirm`}
          value={typed}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => setTyped(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") {
              event.preventDefault();
              submit();
            }
          }}
        />
      </label>
      <p className="font-sans text-xs text-ink-muted">
        Your system then asks you to confirm in a PAM dialog; choose Allow there to go ahead.
      </p>
      <div className="flex items-center gap-2">
        <Button size="sm" variant="secondary" autoFocus onClick={onCancel}>
          Cancel
        </Button>
        <Button size="sm" disabled={!matches || busy} onClick={submit}>
          {confirmLabel}
        </Button>
      </div>
    </div>
  );
}
