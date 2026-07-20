import { useState } from "react";
import { ShieldCheck, LogOut, Lock, Accessibility, Contrast, Clock } from "lucide-react";
import type { AuthSession } from "../types";
import { ROLE_LABELS } from "../types";
import { Button } from "./ui/button";
import { SocDashboard } from "./soc/SocDashboard";

interface RoleHomeProps {
  session: AuthSession;
  onLogout: () => void;
  fontScale: number;
  setFontScale: (n: number) => void;
  highContrast: boolean;
  setHighContrast: (b: boolean) => void;
}

// Role-gated landing after login. Candidates never see proctor/examiner routes and
// vice versa — enforced by which branch renders here.
const ROLE_NAV: Record<AuthSession["role"], { title: string; items: string[] }> = {
  candidate: {
    title: "Candidate Portal",
    items: ["Candidate Registration", "Hall Ticket", "Exam Interface", "Results Portal", "My Certificate"],
  },
  invigilator: {
    title: "Proctor Dashboard",
    items: ["Live Centre Monitor", "Flagged for Review", "Session Timeline", "Integrity Board Queue"],
  },
  examiner: {
    title: "Examiner — On-Screen Marking",
    items: ["Scanned Script", "Marking Panel", "Blind-Marking Guide", "Session Activity Log"],
  },
  security: {
    title: "SOC Command Center",
    items: ["Anomaly Feed", "ATT&CK Attribution", "SOAR Playbooks", "CVE Queue", "Digital Twin", "Audit Trail"],
  },
};

export function RoleHome({
  session,
  onLogout,
  fontScale,
  setFontScale,
  highContrast,
  setHighContrast,
}: RoleHomeProps) {
  const isExaminer = session.role === "examiner";
  const nav = ROLE_NAV[session.role];
  const [srMode, setSrMode] = useState(false);

  return (
    <div className="min-h-screen w-full bg-background">
      {/* Shared accessibility toolkit — always visible, never inside a collapsed menu */}
      <div className="flex items-center justify-end gap-1 border-b border-border/70 bg-muted px-4 py-1.5">
        <span className="mr-auto font-mono text-[11px] tracking-wide text-muted-foreground">ACCESSIBILITY</span>
        <button
          onClick={() => setFontScale(Math.max(0.85, fontScale - 0.1))}
          aria-label="Decrease font size"
          className="rounded-sm px-2 py-1 text-[12px] text-foreground hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          A−
        </button>
        <button
          onClick={() => setFontScale(Math.min(1.4, fontScale + 0.1))}
          aria-label="Increase font size"
          className="rounded-sm px-2 py-1 text-[14px] text-foreground hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          A+
        </button>
        <button
          onClick={() => setHighContrast(!highContrast)}
          aria-pressed={highContrast}
          className="inline-flex items-center gap-1 rounded-sm px-2 py-1 text-[12px] text-foreground hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Contrast className="size-3.5" /> Contrast
        </button>
        <button
          onClick={() => setSrMode(!srMode)}
          aria-pressed={srMode}
          className="inline-flex items-center gap-1 rounded-sm px-2 py-1 text-[12px] text-foreground hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <Accessibility className="size-3.5" /> Screen reader
        </button>
      </div>

      {/* Header — examiner gets the distinct near-black secured treatment */}
      <header
        className={[
          "flex items-center justify-between px-6 py-4",
          isExaminer ? "bg-[var(--examiner-header)] text-white" : "bg-primary text-primary-foreground",
        ].join(" ")}
      >
        <div className="flex items-center gap-3">
          <ShieldCheck className="size-6" />
          <div>
            <div style={{ fontFamily: "var(--font-serif)", fontWeight: 600 }} className="text-[16px]">
              Pariksha Kendra
            </div>
            <div className="font-mono text-[11px] tracking-wide opacity-70">{nav.title.toUpperCase()}</div>
          </div>
        </div>
        <Button
          variant="ghost"
          onClick={onLogout}
          className={isExaminer ? "text-white hover:bg-white/10" : "text-primary-foreground hover:bg-white/10"}
        >
          <LogOut className="size-4" /> Sign out
        </Button>
      </header>

      {/* Examiner explicit session banner with lock icon */}
      {isExaminer && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border/70 bg-[var(--examiner-header)]/95 px-6 py-2 text-white">
          <Lock className="size-4" />
          <span className="font-mono text-[12px] tracking-wide">
            EXAMINER SESSION — {session.displayName} — Session #{session.sessionId} —{" "}
            {new Date().toLocaleTimeString()}
          </span>
        </div>
      )}

      {session.role === "security" ? (
        <SocDashboard />
      ) : (
      <main className="mx-auto max-w-4xl px-6 py-10">
        <p className="font-mono text-[11px] tracking-wide text-muted-foreground">
          SIGNED IN AS {session.userId} · {ROLE_LABELS[session.role].toUpperCase()}
        </p>
        <h1 style={{ fontFamily: "var(--font-serif)" }} className="mt-1 text-[24px] text-foreground">
          Welcome, {session.displayName}
        </h1>
        <p className="mt-2 max-w-xl text-[15px] text-muted-foreground">
          You've reached the {nav.title}. Only routes permitted for your role are shown below.
          {srMode && " Screen-reader mode is active."}
        </p>

        {session.role === "candidate" && fontScale !== 1 && (
          <p className="mt-2 inline-flex items-center gap-1 text-[13px] text-muted-foreground">
            <Clock className="size-3.5" /> Extended-time indicator appears on the Exam Interface when granted.
          </p>
        )}

        <div className="mt-6 grid gap-3 sm:grid-cols-2">
          {nav.items.map((item) => (
            <div
              key={item}
              className="rounded-sm border border-border/70 bg-card p-4 text-[14px] text-card-foreground transition-colors hover:border-ring"
            >
              {item}
            </div>
          ))}
        </div>
      </main>
      )}
    </div>
  );
}
