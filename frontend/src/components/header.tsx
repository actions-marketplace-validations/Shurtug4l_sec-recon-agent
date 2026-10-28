"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  BarChart3,
  BookOpen,
  ClipboardCheck,
  FileSearch,
  Home,
  Library,
  Menu,
  MessageSquare,
  Search,
  ShieldAlert,
  X,
} from "lucide-react";

import { useCommandPalette } from "@/components/command-palette";
import { GithubLogo } from "@/components/icons/github-logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { cn } from "@/lib/utils";

type Tab = {
  href: string;
  label: string;
  icon: typeof Home;
  match: (p: string) => boolean;
};

// Two clusters with a divider between them: the interactive product surfaces
// first (Home leads), then the reading/learning surfaces. Guide leads the
// learn cluster so onboarding is no longer the far-right tab behind Docs.
const PRODUCT_TABS: Tab[] = [
  { href: "/", label: "Home", icon: Home, match: (p) => p === "/" },
  { href: "/triage", label: "Triage", icon: MessageSquare, match: (p) => p.startsWith("/triage") },
  { href: "/dashboard", label: "Dashboard", icon: BarChart3, match: (p) => p.startsWith("/dashboard") },
  { href: "/scorecard", label: "Scorecard", icon: ClipboardCheck, match: (p) => p.startsWith("/scorecard") },
];
const LEARN_TABS: Tab[] = [
  { href: "/guide", label: "Guide", icon: BookOpen, match: (p) => p.startsWith("/guide") },
  { href: "/case-study", label: "Case study", icon: FileSearch, match: (p) => p.startsWith("/case-study") },
  { href: "/docs", label: "Docs", icon: Library, match: (p) => p.startsWith("/docs") },
];

// Focus ring shared by every interactive element in the bar.
const RING =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background";

export function Header() {
  const pathname = usePathname();
  const { openPalette } = useCommandPalette();
  // Set after mount so the prerendered HTML (no kbd) matches the first
  // client render; the platform is only knowable client-side.
  const [modKey, setModKey] = useState<string | null>(null);
  // Seven routes never fit a phone bar inline; below lg they collapse behind
  // this disclosure. A non-modal menu (no focus trap): Escape and outside
  // click close it, navigation closes it, focus returns to the trigger.
  const [menuOpen, setMenuOpen] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setModKey(/Mac|iP(hone|ad|od)/.test(navigator.platform) ? "⌘" : "Ctrl");
  }, []);

  // Close on route change (a link in the panel navigated).
  useEffect(() => {
    setMenuOpen(false);
  }, [pathname]);

  // Escape + outside-click dismissal while open.
  useEffect(() => {
    if (!menuOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setMenuOpen(false);
        triggerRef.current?.focus();
      }
    }
    function onPointer(e: MouseEvent) {
      const t = e.target as Node;
      if (
        panelRef.current &&
        !panelRef.current.contains(t) &&
        triggerRef.current &&
        !triggerRef.current.contains(t)
      ) {
        setMenuOpen(false);
      }
    }
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onPointer);
    };
  }, [menuOpen]);

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-background/80 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      {/* Keyboard bypass for the repeated nav block (WCAG 2.4.1). */}
      <a
        href="#main-content"
        className={cn(
          "sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-2.5 focus:z-50 focus:rounded-md focus:bg-primary focus:px-3 focus:py-1.5 focus:text-sm focus:font-medium focus:text-primary-foreground",
          RING,
        )}
      >
        Skip to content
      </a>
      <div className="container flex h-14 items-center justify-between gap-3">
        {/* The label carries the tagline too: every word visible at xl must be
            in the accessible name, so speech users can say what they see
            (WCAG 2.5.3, axe label-content-name-mismatch). */}
        <Link
          href="/"
          className="flex shrink-0 items-center gap-2"
          aria-label="sec-recon-agent, Pydantic AI + MCP security triage, home"
        >
          <ShieldAlert className="h-5 w-5 text-primary" />
          <span className="hidden font-mono text-sm font-semibold sm:inline">sec-recon-agent</span>
          <span className="hidden text-xs text-muted-foreground xl:inline">
            &middot; Pydantic AI + MCP security triage
          </span>
        </Link>

        {/* Desktop primary nav: labelled tabs from lg up (they need the room;
            below lg the disclosure carries them). */}
        <nav aria-label="Primary" className="hidden items-center gap-1 lg:flex">
          {PRODUCT_TABS.map((tab) => (
            <DesktopTab key={tab.href} tab={tab} pathname={pathname} />
          ))}
          <div className="mx-1 h-5 w-px shrink-0 bg-border" aria-hidden />
          {LEARN_TABS.map((tab) => (
            <DesktopTab key={tab.href} tab={tab} pathname={pathname} />
          ))}
        </nav>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={openPalette}
            // Mirrors the visible "Search..." label and kbd hint in order, so
            // the name contains what is on screen (WCAG 2.5.3).
            aria-label={modKey ? `Search ${modKey}K, open command palette` : "Search, open command palette"}
            aria-keyshortcuts={modKey === "⌘" ? "Meta+K" : "Control+K"}
            className={cn(
              "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs font-medium text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
              RING,
            )}
          >
            <Search className="h-3.5 w-3.5" />
            {/* Icon-only from lg to xl: the 7 inline tabs appear at lg and, on
                classic-scrollbar platforms (Linux/Windows), the label+kbd here
                pushed the bar ~18px past a 1024px window. The label returns at xl
                alongside the brand subtitle, where there is room to spare. */}
            <span className="hidden xl:inline">Search...</span>
            {modKey && (
              <kbd className="hidden rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground xl:inline">
                {modKey}K
              </kbd>
            )}
          </button>
          <ThemeToggle />
          <a
            href="https://github.com/Shurtug4l/sec-recon-agent"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="GitHub repository"
            className={cn(
              "inline-flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
              RING,
            )}
          >
            <GithubLogo className="h-4 w-4" />
          </a>
          <button
            ref={triggerRef}
            type="button"
            onClick={() => setMenuOpen((o) => !o)}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            className={cn(
              "inline-flex items-center justify-center rounded-md p-1.5 text-muted-foreground transition-colors hover:bg-accent hover:text-foreground lg:hidden",
              RING,
            )}
          >
            {menuOpen ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Disclosure panel: the same seven routes stacked, below lg only. */}
      {menuOpen && (
        <div
          ref={panelRef}
          id="mobile-nav"
          className="border-t border-border bg-background/95 backdrop-blur lg:hidden"
        >
          <nav aria-label="Primary" className="container flex flex-col gap-0.5 py-2">
            {PRODUCT_TABS.map((tab) => (
              <MobileTab key={tab.href} tab={tab} pathname={pathname} />
            ))}
            <div className="my-1 h-px bg-border" aria-hidden />
            {LEARN_TABS.map((tab) => (
              <MobileTab key={tab.href} tab={tab} pathname={pathname} />
            ))}
          </nav>
        </div>
      )}
    </header>
  );
}

function DesktopTab({ tab, pathname }: { tab: Tab; pathname: string }) {
  const active = tab.match(pathname);
  const Icon = tab.icon;
  return (
    <Link
      href={tab.href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "inline-flex items-center gap-1.5 whitespace-nowrap rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors xl:px-3",
        RING,
        active
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <Icon className="h-3.5 w-3.5 shrink-0" />
      {tab.label}
    </Link>
  );
}

function MobileTab({ tab, pathname }: { tab: Tab; pathname: string }) {
  const active = tab.match(pathname);
  const Icon = tab.icon;
  return (
    <Link
      href={tab.href}
      aria-current={active ? "page" : undefined}
      className={cn(
        "inline-flex items-center gap-2.5 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
        RING,
        active
          ? "bg-accent text-accent-foreground"
          : "text-muted-foreground hover:bg-accent hover:text-foreground",
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {tab.label}
    </Link>
  );
}
