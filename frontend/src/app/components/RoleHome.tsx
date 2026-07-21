import { useState } from "react";
import {
  Accessibility,
  BadgeCheck,
  Bell,
  BookOpenCheck,
  CalendarClock,
  CheckCircle2,
  ClipboardCheck,
  Contrast,
  FileCheck2,
  GraduationCap,
  History,
  IdCard,
  LayoutDashboard,
  LogOut,
  Lock,
  MonitorCheck,
  Scan,
  ShieldCheck,
  TimerReset,
  UserCheck,
} from "lucide-react";
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

const ROLE_WORKSPACE: Record<
  Exclude<AuthSession["role"], "security">,
  {
    title: string;
    subtitle: string;
    icon: typeof GraduationCap;
    status: { label: string; value: string }[];
    actions: { icon: typeof IdCard; title: string; detail: string; status: string }[];
    timeline: string[];
  }
> = {
  candidate: {
    title: "Candidate Services",
    subtitle: "Admit card, exam readiness, result services, and certificate verification in a protected portal.",
    icon: GraduationCap,
    status: [
      { label: "Application", value: "Verified" },
      { label: "Admit Card", value: "Available" },
      { label: "Exam Centre", value: "Mapped" },
      { label: "Security", value: "Protected" },
    ],
    actions: [
      { icon: IdCard, title: "Download Admit Card", detail: "Identity, centre, subject, and reporting-time details.", status: "Ready" },
      { icon: MonitorCheck, title: "Exam Interface", detail: "Launches only during the scheduled protected window.", status: "Locked" },
      { icon: FileCheck2, title: "Results and Marks", detail: "Result access, marks statement, and verification requests.", status: "Pending" },
      { icon: BadgeCheck, title: "Certificate Verification", detail: "Public verification token for institutions and employers.", status: "Open" },
    ],
    timeline: ["Registration validated", "Centre mapped", "Admit card issued", "Mock system check pending"],
  },
  invigilator: {
    title: "Centre Proctoring",
    subtitle: "Operational view for live centre supervision, exception handling, attendance, and integrity review.",
    icon: UserCheck,
    status: [
      { label: "Centre", value: "DEL-09" },
      { label: "Candidates", value: "486" },
      { label: "Exceptions", value: "4" },
      { label: "SOC Link", value: "Active" },
    ],
    actions: [
      { icon: ClipboardCheck, title: "Attendance Integrity", detail: "Candidate check-in, duplicate-device markers, and late-entry review.", status: "Live" },
      { icon: Bell, title: "Exception Queue", detail: "Identity mismatch, connectivity, and accommodation cases.", status: "4 Open" },
      { icon: History, title: "Session Timeline", detail: "Immutable event trail shared with audit and SOC layers.", status: "Synced" },
      { icon: ShieldCheck, title: "Centre Security", detail: "Network isolation, device health, and perimeter telemetry.", status: "Healthy" },
    ],
    timeline: ["Centre opened", "Biometric desk active", "Candidate entry in progress", "SOC telemetry streaming"],
  },
  examiner: {
    title: "On-Screen Marking",
    subtitle: "Secured blind-marking workspace with role isolation, timing control, and audit-ready submissions.",
    icon: Scan,
    status: [
      { label: "Bundle", value: "Assigned" },
      { label: "Blind Mode", value: "On" },
      { label: "Autosave", value: "Synced" },
      { label: "Session", value: "Secured" },
    ],
    actions: [
      { icon: Scan, title: "Scanned Script", detail: "Candidate identity hidden, page order locked, rubric visible.", status: "Open" },
      { icon: BookOpenCheck, title: "Marking Panel", detail: "Question-wise marks, annotation controls, and validation checks.", status: "Ready" },
      { icon: TimerReset, title: "Session Control", detail: "Timeout, re-authentication, and suspicious activity telemetry.", status: "Active" },
      { icon: Lock, title: "Submission Lock", detail: "Final submit requires rubric completion and audit confirmation.", status: "Guarded" },
    ],
    timeline: ["Secure login verified", "Bundle assigned", "Blind marking active", "Audit autosave running"],
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
  const [srMode, setSrMode] = useState(false);

  return (
    <div className="min-h-screen w-full bg-background">
      <div className="flex items-center justify-end gap-1 border-b border-border/70 bg-muted px-4 py-1.5">
        <span className="mr-auto font-mono text-[11px] tracking-wide text-muted-foreground">ACCESSIBILITY</span>
        <button
          onClick={() => setFontScale(Math.max(0.85, fontScale - 0.1))}
          aria-label="Decrease font size"
          className="rounded-sm px-2 py-1 text-[12px] text-foreground hover:bg-secondary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          A-
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

      <header className={["border-b border-border/70", isExaminer ? "bg-[var(--examiner-header)] text-white" : "bg-primary text-primary-foreground"].join(" ")}>
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-3 px-4 py-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-sm bg-white/10">
              <ShieldCheck className="size-5" />
            </div>
            <div>
              <div style={{ fontFamily: "var(--font-serif)", fontWeight: 600 }} className="text-[17px]">
                Central Board Examination Services
              </div>
              <div className="font-mono text-[11px] tracking-wide opacity-75">{ROLE_LABELS[session.role].toUpperCase()}</div>
            </div>
          </div>
          <Button
            variant="ghost"
            onClick={onLogout}
            className={isExaminer ? "text-white hover:bg-white/10" : "text-primary-foreground hover:bg-white/10"}
          >
            <LogOut className="size-4" /> Sign out
          </Button>
        </div>
      </header>

      {isExaminer && (
        <div className="border-b border-border/70 bg-[var(--examiner-header)]/95 px-4 py-2 text-white">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center gap-2">
            <Lock className="size-4" />
            <span className="font-mono text-[12px] tracking-wide">
              EXAMINER SESSION - {session.displayName} - Session #{session.sessionId} - {new Date().toLocaleTimeString()}
            </span>
          </div>
        </div>
      )}

      {session.role === "security" ? (
        <SocDashboard />
      ) : (
        <Workspace session={session} screenReaderMode={srMode} />
      )}
    </div>
  );
}

function Workspace({ session, screenReaderMode }: { session: AuthSession; screenReaderMode: boolean }) {
  const workspace = ROLE_WORKSPACE[session.role as Exclude<AuthSession["role"], "security">];
  const Icon = workspace.icon;

  return (
    <main className="mx-auto max-w-7xl px-4 py-6">
      <div className="mb-5 grid gap-4 lg:grid-cols-[1fr_340px]">
        <section className="rounded-sm border border-border/70 bg-card p-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="flex items-start gap-3">
              <div className="flex size-12 items-center justify-center rounded-sm bg-primary text-primary-foreground">
                <Icon className="size-6" />
              </div>
              <div>
                <p className="font-mono text-[11px] tracking-wide text-muted-foreground">
                  SIGNED IN AS {session.userId} - SESSION {session.sessionId}
                </p>
                <h1 style={{ fontFamily: "var(--font-serif)" }} className="mt-1 text-[25px] text-foreground">
                  {workspace.title}
                </h1>
                <p className="mt-2 max-w-2xl text-[14px] leading-relaxed text-muted-foreground">
                  {workspace.subtitle}
                  {screenReaderMode && " Screen-reader mode is active."}
                </p>
              </div>
            </div>
            <span className="rounded-sm bg-muted px-3 py-2 font-mono text-[11px] text-foreground">PROTECTED</span>
          </div>

          <div className="mt-5 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {workspace.status.map((item) => (
              <div key={item.label} className="rounded-sm border border-border/70 bg-background p-3">
                <p className="text-[11px] text-muted-foreground">{item.label}</p>
                <p className="mt-1 font-mono text-[14px] text-foreground">{item.value}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="rounded-sm border border-border/70 bg-card p-4">
          <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
            <CalendarClock className="size-4" /> Session Timeline
          </h2>
          <div className="grid gap-2">
            {workspace.timeline.map((item) => (
              <div key={item} className="flex items-start gap-2 text-[12px] text-muted-foreground">
                <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
                <span>{item}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        {workspace.actions.map((action) => {
          const ActionIcon = action.icon;
          return (
            <article key={action.title} className="rounded-sm border border-border/70 bg-card p-4 transition-colors hover:border-ring">
              <div className="mb-3 flex items-start justify-between gap-3">
                <div className="flex size-9 items-center justify-center rounded-sm bg-primary text-primary-foreground">
                  <ActionIcon className="size-4" />
                </div>
                <span className="rounded-sm bg-muted px-2 py-1 font-mono text-[10px] uppercase text-foreground">{action.status}</span>
              </div>
              <h2 className="text-[14px] font-semibold text-foreground">{action.title}</h2>
              <p className="mt-2 text-[12px] leading-relaxed text-muted-foreground">{action.detail}</p>
            </article>
          );
        })}
      </section>

      <section className="mt-5 rounded-sm border border-border/70 bg-card p-4">
        <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
          <LayoutDashboard className="size-4" /> Security Controls Applied To This Session
        </h2>
        <div className="grid gap-2 md:grid-cols-4">
          {["Role-gated routes", "Telemetry ingestion", "Anomaly scoring", "Hash-chain audit"].map((item) => (
            <div key={item} className="rounded-sm border border-border/70 bg-background p-3 text-[12px] text-muted-foreground">
              {item}
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
