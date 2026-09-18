import {
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type ComponentPropsWithRef,
} from "react";
import { createPortal } from "react-dom";
import { ChevronDown } from "lucide-react";
import { Button } from "./Button";
import { cn } from "../../lib/cn";

/** Portaled actions with shared placement, dismissal and keyboard behavior. */
export function ActionMenu({
  label = "More",
  triggerLabel,
  menuLabel,
  disabled,
  children,
}: {
  label?: string;
  triggerLabel: string;
  menuLabel: string;
  disabled?: boolean;
  children: (close: () => void) => ReactNode;
}) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const menu = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  useLayoutEffect(() => {
    if (!open) return;
    const element = menu.current!;
    const opener = trigger.current!;
    const position = () => {
      const rect = opener.getBoundingClientRect();
      const roomBelow = window.innerHeight - rect.bottom - 8;
      const top =
        roomBelow >= element.offsetHeight
          ? rect.bottom + 4
          : Math.max(8, rect.top - element.offsetHeight - 4);
      element.style.top = `${top}px`;
      element.style.left = `${Math.max(8, Math.min(rect.right - element.offsetWidth, window.innerWidth - element.offsetWidth - 8))}px`;
    };
    const outside = (event: PointerEvent) => {
      if (!element.contains(event.target as Node) && !opener.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    position();
    element.querySelector<HTMLButtonElement>("button:enabled")?.focus();
    window.addEventListener("resize", position);
    document.addEventListener("scroll", position, true);
    document.addEventListener("pointerdown", outside);
    return () => {
      window.removeEventListener("resize", position);
      document.removeEventListener("scroll", position, true);
      document.removeEventListener("pointerdown", outside);
    };
  }, [open]);
  const close = () => {
    setOpen(false);
    trigger.current?.focus();
  };
  const keyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
    }
    if (!open || !["ArrowDown", "ArrowUp", "Home", "End"].includes(event.key)) return;
    event.preventDefault();
    const items = Array.from(
      menu.current?.querySelectorAll<HTMLButtonElement>("button:enabled") ?? [],
    );
    if (items.length === 0) return;
    const current = items.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? items.length - 1
          : (current + (event.key === "ArrowDown" ? 1 : -1) + items.length) % items.length;
    items[next]?.focus();
  };
  return (
    <div
      className="relative"
      onBlur={(event) => {
        const next = event.relatedTarget as Node | null;
        if (!event.currentTarget.contains(next) && !menu.current?.contains(next))
          setOpen(false);
      }}
      onKeyDown={keyDown}
    >
      <Button
        ref={trigger}
        size="sm"
        variant="ghost"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        aria-label={triggerLabel}
        disabled={disabled}
        onClick={() => setOpen((value) => !value)}
      >
        {label}
        <ChevronDown size={14} aria-hidden="true" />
      </Button>
      {open &&
        createPortal(
          <div
            ref={menu}
            id={id}
            role="menu"
            aria-label={menuLabel}
            className="action-menu fixed z-50 w-44 space-y-0.5 overflow-y-auto rounded-card border border-line-strong bg-surface-raised p-1 text-ink shadow-float"
          >
            {children(close)}
          </div>,
          document.body,
        )}
    </div>
  );
}

export function MenuItem({
  className,
  type = "button",
  ...props
}: ComponentPropsWithRef<"button">) {
  return (
    <button
      {...props}
      type={type}
      role="menuitem"
      className={cn(
        "flex h-8 w-full items-center rounded-control px-2.5 text-left font-sans text-sm text-ink enabled:hover:bg-accent-soft disabled:cursor-not-allowed disabled:opacity-70",
        className,
      )}
    />
  );
}
