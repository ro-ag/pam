import { LoaderCircle } from "lucide-react";
import { useState } from "react";
import { Button } from "./Button";

/**
 * Two-tap destructive action (memento law: destructive actions confirm).
 * First tap arms — the button turns into its "sure?" wording; the second
 * tap fires. Leaving the button (blur) disarms.
 */
export function ConfirmButton({
  label,
  confirmLabel,
  busy,
  disabled,
  onConfirm,
  size = "sm",
}: {
  label: string;
  confirmLabel: string;
  busy?: boolean;
  disabled?: boolean;
  onConfirm: () => void;
  size?: "sm" | "md";
}) {
  const [armed, setArmed] = useState(false);
  return (
    <Button
      variant="danger"
      size={size}
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
