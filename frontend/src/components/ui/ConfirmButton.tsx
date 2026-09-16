import { LoaderCircle } from "lucide-react";
import { useState } from "react";
import { Button } from "./Button";

/**
 * Two-tap destructive action (memento law: destructive actions confirm).
 * First tap arms — the button turns into its "sure?" wording; the second
 * tap fires. Leaving the button (blur) disarms. `danger` by default; a
 * disruptive but not destructive action (restart) may ask as `secondary`.
 */
export function ConfirmButton({
  label,
  confirmLabel,
  busy,
  disabled,
  title,
  onConfirm,
  size = "sm",
  variant = "danger",
}: {
  label: string;
  confirmLabel: string;
  busy?: boolean;
  disabled?: boolean;
  /** Why the button is disabled, shown as its tooltip. */
  title?: string;
  onConfirm: () => void;
  size?: "sm" | "md";
  variant?: "danger" | "secondary";
}) {
  const [armed, setArmed] = useState(false);
  return (
    <Button
      variant={variant}
      size={size}
      title={title}
      disabled={disabled || busy}
      aria-label={armed ? confirmLabel : label}
      onBlur={() => setArmed(false)}
      onClick={() => {
        if (!armed) {
          setArmed(true);
          return;
        }
        setArmed(false);
        onConfirm();
      }}
    >
      {busy && <LoaderCircle aria-hidden="true" className="size-3.5 animate-spin" />}
      {armed ? confirmLabel : label}
    </Button>
  );
}
