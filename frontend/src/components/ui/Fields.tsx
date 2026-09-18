import type { ComponentPropsWithRef } from "react";
import { cn } from "../../lib/cn";
import { fieldClasses } from "./field";

type Appearance = { appearance?: "field" | "plain" };
type TextFieldProps = Omit<ComponentPropsWithRef<"input">, "type"> &
  Appearance & {
    type?:
      | "text"
      | "search"
      | "password"
      | "email"
      | "url"
      | "tel"
      | "number"
      | "date"
      | "time"
      | "datetime-local";
  };

/** Native form semantics and refs, with one shared visual recipe. */
export function TextField({ appearance = "field", className, ...props }: TextFieldProps) {
  return <input className={cn(appearance === "field" && fieldClasses, className)} {...props} />;
}

export function TextArea({
  appearance = "field",
  className,
  ...props
}: ComponentPropsWithRef<"textarea"> & Appearance) {
  return (
    <textarea
      className={cn(appearance === "field" && [fieldClasses, "h-auto py-2"], className)}
      {...props}
    />
  );
}

export function SelectField({
  appearance = "field",
  className,
  ...props
}: ComponentPropsWithRef<"select"> & Appearance) {
  return (
    <select className={cn(appearance === "field" && fieldClasses, className)} {...props} />
  );
}
