import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

/**
 * Compose class names the PAM way: clsx for conditionals, tailwind-merge so
 * a caller's override (`<Button className="px-8">`) wins over the variant's
 * own utility instead of fighting it. Every component's className funnels
 * through here — no string-concatenated class soup.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/** Variant definitions live next to their component, always via cva. */
export { cva, type VariantProps } from "class-variance-authority";
