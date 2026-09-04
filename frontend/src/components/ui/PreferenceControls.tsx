import { useId, type CSSProperties } from "react";

/** Native keyboard-accessible inputs, with bounded desktop presentation. */
export function PreferenceRange({
  label,
  value,
  min,
  max,
  step = 1,
  readout,
  valueText,
  low,
  high,
  disabled,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  step?: number;
  readout: string;
  valueText?: string;
  low: string;
  high: string;
  disabled?: boolean;
  onChange: (value: number) => void;
}) {
  const id = useId();
  return (
    <div className="preference-range" data-disabled={disabled || undefined}>
      <div className="preference-range-heading">
        <label htmlFor={id}>{label}</label>
        <output htmlFor={id}>{readout}</output>
      </div>
      <input
        id={id}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        aria-valuetext={valueText ?? readout}
        disabled={disabled}
        onChange={(event) => onChange(Number(event.target.value))}
        style={{ "--range-fill": `${(100 * (value - min)) / (max - min)}%` } as CSSProperties}
      />
      <div className="preference-range-extents" aria-hidden="true">
        <span>{low}</span>
        <span>{high}</span>
      </div>
    </div>
  );
}

export function PreferenceToggle({
  label,
  checked,
  onChange,
  describedBy,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
  describedBy?: string;
}) {
  return (
    <label className="preference-toggle">
      <span>{label}</span>
      <span className="preference-switch">
        <input
          type="checkbox"
          checked={checked}
          onChange={(event) => onChange(event.target.checked)}
          aria-describedby={describedBy}
        />
        <span className="preference-switch-track" aria-hidden="true">
          <span />
        </span>
      </span>
    </label>
  );
}
