import { useState, type FormEvent } from "react";
import {
  AlertTriangle,
  ArrowLeft,
  BadgeCheck,
  BookOpen,
  Building2,
  CheckCircle2,
  ChevronRight,
  Eye,
  FileCheck2,
  GraduationCap,
  IdCard,
  Landmark,
  Lock,
  Megaphone,
  Network,
  Radar,
  Scan,
  Search,
  ShieldCheck,
  User,
} from "lucide-react";
import type { Role } from "../types";
import { ROLE_LABELS } from "../types";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { PasswordField } from "./PasswordField";
import heroImage from "../../assets/exam-operations-hero.png";
import type { LoginResult } from "../hooks/useAuth";

type Mode = "login" | "signup" | "reset";

interface AuthScreenProps {
  onLogin: (role: Role, id: string, password: string, otp?: string, challengeId?: string) => Promise<LoginResult>;
  onRegister: (id: string, password: string, name: string) => Promise<{ ok: boolean; error?: string }>;
  onVerifyCertificate: () => void;
}

const ROLE_META: Record<
  Role,
  { icon: typeof GraduationCap; blurb: string; idLabel: string; idPlaceholder: string; demo: string }
> = {
  candidate: {
    icon: GraduationCap,
    blurb: "Admit card, examination services, result access, certificate verification, and candidate support.",
    idLabel: "Roll Number",
    idPlaceholder: "CAND-2026-004821",
    demo: "CAND-2026-004821 / candidate",
  },
  invigilator: {
    icon: Eye,
    blurb: "Centre operations, attendance integrity, candidate exceptions, and proctor review queues.",
    idLabel: "Staff ID",
    idPlaceholder: "INV-DEL-0097",
    demo: "INV-DEL-0097 / invigilator",
  },
  examiner: {
    icon: Scan,
    blurb: "Secure on-screen marking, blind evaluation, review workflow, and audit-ready submissions.",
    idLabel: "Marker Staff ID",
    idPlaceholder: "OSM-7731",
    demo: "OSM-7731 / examiner",
  },
  security: {
    icon: Radar,
    blurb: "Aegis-CNI live attack detection, GenAI attribution, playbook containment, and audit verification.",
    idLabel: "SOC Operator ID",
    idPlaceholder: "SOC-AEGIS-001",
    demo: "SOC-AEGIS-001 / security",
  },
};

const services = [
  { icon: Landmark, title: "Main Website", text: "Circulars, notices, academic documents, and institutional advisories." },
  { icon: Network, title: "Pariksha Sangam", text: "Unified exam operations hub for schools, regions, centres, and results." },
  { icon: FileCheck2, title: "Results", text: "Result access, marks verification, certificate lookup, and re-evaluation status." },
  { icon: Building2, title: "Affiliation", text: "School affiliation, inspection status, compliance submissions, and renewals." },
  { icon: BookOpen, title: "Academic", text: "Curriculum, sample papers, question bank references, and learning resources." },
  { icon: ShieldCheck, title: "Cyber Resilience", text: "Behaviour-based protection, zero-day prevention posture, and SOC auditability." },
];

const notices = [
  "Class X and XII examination services window: candidate corrections and admit-card checks active.",
  "Schools must review centre readiness, network isolation, and identity access before mock examinations.",
  "Aegis-CNI zero-day prevention posture is active for live request monitoring and SOAR containment.",
];

const defences = [
  "Client-side validation reduces accidental bad input before it reaches the API.",
  "Live perimeter detection blocks high-confidence SQLi, command, XSS, traversal, and oversized requests.",
  "Predictive ML catches abnormal sequences even when a CVE or signature is unknown.",
  "Ollama GenAI explains attribution and mitigation using defensive-only incident context.",
  "SOAR containment, approval gates, and hash-chained audit records make response verifiable.",
];

export function AuthScreen({ onLogin, onRegister, onVerifyCertificate }: AuthScreenProps) {
  const [role, setRole] = useState<Role | null>(null);
  const [mode, setMode] = useState<Mode>("login");
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [otp, setOtp] = useState("");
  const [mfaChallengeId, setMfaChallengeId] = useState<string | null>(null);
  const [demoOtp, setDemoOtp] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const isExaminer = role === "examiner";

  function reset() {
    setId("");
    setName("");
    setPassword("");
    setConfirm("");
    setOtp("");
    setMfaChallengeId(null);
    setDemoOtp(null);
    setError(null);
    setNotice(null);
  }

  function chooseRole(nextRole: Role) {
    setRole(nextRole);
    setMode("login");
    reset();
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (!role) return;

    const cleanId = id.trim();
    if (!/^[A-Z0-9-]{3,32}$/i.test(cleanId)) {
      setError("Use only letters, numbers, and hyphens in the ID field.");
      return;
    }

    if (mode === "reset") {
      setNotice(`Password reset instructions sent for ${cleanId}. Check your registered email.`);
      return;
    }

    if (mode === "signup") {
      if (!name.trim()) {
        setError("Full name is required.");
        return;
      }
      if (password.length < 12) {
        setError("Password must be at least 12 characters and must not reuse your name or roll number.");
        return;
      }
      if (password !== confirm) {
        setError("Passwords do not match.");
        return;
      }
      setBusy(true);
      const result = await onRegister(cleanId, password, name.trim()).finally(() => setBusy(false));
      if (!result.ok) setError(result.error ?? "Registration failed.");
      return;
    }

    if (!password) {
      setError("Password is required.");
      return;
    }
    if (mfaChallengeId && otp.length !== 6) {
      setError("Enter the 6-digit two-factor authentication code.");
      return;
    }
    setBusy(true);
    const result = await onLogin(role, cleanId, password, otp || undefined, mfaChallengeId || undefined).finally(() => setBusy(false));
    if (result.mfaRequired) {
      setMfaChallengeId(result.challengeId ?? null);
      setDemoOtp(result.demoCode ?? null);
      setNotice(`Two-factor code sent through demo delivery${result.demoCode ? `: ${result.demoCode}` : "."}`);
      return;
    }
    if (!result.ok) setError(result.error ?? "Login failed.");
  }

  if (!role) {
    return (
      <div className="min-h-screen w-full bg-background">
        <div className="border-b border-border/70 bg-primary text-primary-foreground">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-2 px-4 py-2 text-[11px]">
            <span className="font-mono tracking-wide">GOVERNMENT EDUCATION SERVICES DEMO</span>
            <div className="flex flex-wrap items-center gap-3 opacity-90">
              <span>Screen Reader Access</span>
              <span>Skip to Services</span>
              <span>English</span>
              <span>Hindi</span>
            </div>
          </div>
        </div>

        <header className="border-b border-border/70 bg-card">
          <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-4">
            <div className="flex items-center gap-3">
              <div className="flex size-12 items-center justify-center rounded-sm bg-primary text-primary-foreground">
                <Landmark className="size-7" />
              </div>
              <div>
                <p className="font-mono text-[11px] tracking-wide text-muted-foreground">Aegis-CNI Protected Portal</p>
                <h1 style={{ fontFamily: "var(--font-serif)" }} className="text-[22px] leading-tight text-foreground">
                  Central Board Examination Services
                </h1>
                <p className="text-[12px] text-muted-foreground">CBSE-style sample portal for secure digital examination delivery</p>
              </div>
            </div>
            <Button variant="outline" onClick={onVerifyCertificate} className="border-border/70">
              <BadgeCheck className="size-4" /> Verify Certificate
            </Button>
          </div>
        </header>

        <main>
          <section
            className="relative overflow-hidden border-b border-border/70 bg-cover bg-center"
            style={{ backgroundImage: `linear-gradient(90deg, rgba(238,240,244,0.98) 0%, rgba(238,240,244,0.92) 34%, rgba(238,240,244,0.18) 70%), url(${heroImage})` }}
          >
            <div className="mx-auto grid min-h-[430px] max-w-7xl content-center gap-8 px-4 py-10 lg:grid-cols-[0.9fr_1.1fr]">
              <div>
                <p className="font-mono text-[11px] tracking-wide text-primary">SECURE EXAMINATION INFRASTRUCTURE</p>
                <h2 style={{ fontFamily: "var(--font-serif)" }} className="mt-2 max-w-xl text-[34px] leading-tight text-foreground">
                  Public services, exam operations, and cyber-resilience in one board portal.
                </h2>
                <p className="mt-3 max-w-lg text-[15px] leading-relaxed text-muted-foreground">
                  A sample national examination website with candidate services, staff access, certificate verification,
                  and a live SOC that detects and contains cyber attacks against the portal.
                </p>
                <div className="mt-5 flex flex-wrap gap-2">
                  <Button onClick={() => chooseRole("candidate")} className="bg-primary text-primary-foreground">
                    <GraduationCap className="size-4" /> Candidate Login
                  </Button>
                  <Button variant="outline" onClick={() => chooseRole("security")} className="border-border/70 bg-card/90">
                    <ShieldCheck className="size-4" /> SOC Command Center
                  </Button>
                </div>
              </div>
              <div className="hidden lg:block" />
            </div>
          </section>

          <section className="border-b border-border/70 bg-card">
            <div className="mx-auto grid max-w-7xl gap-3 px-4 py-4 md:grid-cols-4">
              <StatusItem label="Portal Status" value="Operational" />
              <StatusItem label="Live Defence" value="Aegis-CNI Active" />
              <StatusItem label="Zero-Day Posture" value="Behaviour Based" />
              <StatusItem label="Audit Integrity" value="Hash-Chained" />
            </div>
          </section>

          <section className="mx-auto grid max-w-7xl gap-5 px-4 py-6 lg:grid-cols-[1fr_360px]">
            <div>
              <div className="mb-3 flex items-center justify-between gap-3">
                <h2 className="flex items-center gap-2 text-[16px] font-semibold text-foreground">
                  <Search className="size-4" /> Citizen and Institution Services
                </h2>
                <span className="font-mono text-[11px] text-muted-foreground">SAMPLE BOARD PORTAL</span>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                {services.map((service) => {
                  const Icon = service.icon;
                  return (
                    <button
                      key={service.title}
                      onClick={() => service.title === "Cyber Resilience" && chooseRole("security")}
                      className="group rounded-sm border border-border/70 bg-card p-4 text-left transition-colors hover:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <div className="flex items-start gap-3">
                        <span className="flex size-9 shrink-0 items-center justify-center rounded-sm bg-primary text-primary-foreground">
                          <Icon className="size-4" />
                        </span>
                        <span>
                          <span className="flex items-center gap-1 text-[14px] font-semibold text-foreground">
                            {service.title} <ChevronRight className="size-3.5 opacity-50 group-hover:opacity-100" />
                          </span>
                          <span className="mt-1 block text-[12px] leading-relaxed text-muted-foreground">{service.text}</span>
                        </span>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            <aside className="grid gap-3">
              <section className="rounded-sm border border-border/70 bg-card p-4">
                <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
                  <Lock className="size-4" /> Secure Access
                </h2>
                <div className="grid gap-2">
                  {(Object.keys(ROLE_META) as Role[]).map((item) => {
                    const meta = ROLE_META[item];
                    const Icon = meta.icon;
                    return (
                      <button
                        key={item}
                        onClick={() => chooseRole(item)}
                        className="flex items-center gap-3 rounded-sm border border-border/70 bg-background p-3 text-left transition-colors hover:border-ring focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <Icon className="size-4 text-primary" />
                        <span className="min-w-0">
                          <span className="block text-[13px] font-medium text-foreground">{ROLE_LABELS[item]}</span>
                          <span className="block truncate text-[11px] text-muted-foreground">{meta.demo}</span>
                        </span>
                      </button>
                    );
                  })}
                </div>
              </section>

              <section className="rounded-sm border border-border/70 bg-card p-4">
                <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
                  <Megaphone className="size-4" /> Latest Notices
                </h2>
                <div className="space-y-3">
                  {notices.map((item) => (
                    <p key={item} className="border-b border-border/50 pb-2 text-[12px] leading-relaxed text-muted-foreground last:border-b-0 last:pb-0">
                      {item}
                    </p>
                  ))}
                </div>
              </section>
            </aside>
          </section>

          <section className="border-t border-border/70 bg-muted/60">
            <div className="mx-auto max-w-7xl px-4 py-6">
              <h2 className="mb-3 flex items-center gap-2 text-[16px] font-semibold text-foreground">
                <ShieldCheck className="size-4" /> Layered Cyber-Resilience Controls
              </h2>
              <div className="grid gap-2 md:grid-cols-5">
                {defences.map((item) => (
                  <div key={item} className="rounded-sm border border-border/70 bg-card p-3 text-[11px] leading-relaxed text-muted-foreground">
                    {item}
                  </div>
                ))}
              </div>
            </div>
          </section>
        </main>
      </div>
    );
  }

  const meta = ROLE_META[role];
  const Icon = meta.icon;

  return (
    <div className={["min-h-screen w-full", isExaminer ? "bg-[var(--examiner-header)]" : "bg-background"].join(" ")}>
      <div className="mx-auto grid min-h-screen max-w-6xl items-center gap-8 px-6 py-12 md:grid-cols-[0.9fr_1.1fr]">
        <div className={isExaminer ? "text-white" : "text-foreground"}>
          <button
            onClick={() => setRole(null)}
            className={[
              "mb-8 inline-flex items-center gap-2 rounded-sm text-[13px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              isExaminer ? "text-white/70 hover:text-white" : "text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            <ArrowLeft className="size-4" /> Back to public portal
          </button>

          <div className="mb-5 flex items-center gap-3">
            <div
              className={[
                "flex size-11 items-center justify-center rounded-sm",
                isExaminer ? "bg-white/10 text-white" : "bg-primary text-primary-foreground",
              ].join(" ")}
            >
              <Icon className="size-6" />
            </div>
            <div>
              <p className={isExaminer ? "font-mono text-[11px] tracking-wide text-white/60" : "font-mono text-[11px] tracking-wide text-muted-foreground"}>
                PROTECTED ROLE ACCESS
              </p>
              <h1 style={{ fontFamily: "var(--font-serif)" }} className="text-[24px] leading-tight">
                {ROLE_LABELS[role]}
              </h1>
            </div>
          </div>

          <p className={isExaminer ? "max-w-md text-[15px] leading-relaxed text-white/75" : "max-w-md text-[15px] leading-relaxed text-muted-foreground"}>
            {meta.blurb}
          </p>

          <div className={["mt-6 grid gap-2 rounded-sm border p-4", isExaminer ? "border-white/15 bg-white/5" : "border-border/70 bg-card"].join(" ")}>
            {["Role-scoped access", "Telemetry sent to Aegis-CNI", "Anomalies scored live", "Audit trail preserved"].map((item) => (
              <div key={item} className="flex items-center gap-2 text-[12px]">
                <CheckCircle2 className={isExaminer ? "size-4 text-white/80" : "size-4 text-primary"} />
                <span className={isExaminer ? "text-white/75" : "text-muted-foreground"}>{item}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="w-full rounded-sm border border-border/70 bg-card p-6 shadow-sm md:p-8">
          <h2 style={{ fontFamily: "var(--font-serif)" }} className="text-[20px] text-card-foreground">
            {mode === "login" && "Sign in to secure services"}
            {mode === "signup" && "Create candidate account"}
            {mode === "reset" && "Reset candidate password"}
          </h2>
          <p className="mb-5 mt-1 text-[13px] text-muted-foreground">
            {mode === "login" && `Enter your ${meta.idLabel.toLowerCase()} and password. Demo: ${meta.demo}.`}
            {mode === "signup" && "Candidate registration is role-scoped and validates the account before opening services."}
            {mode === "reset" && "Reset instructions are sent to the registered candidate contact."}
          </p>

          {error && (
            <div role="alert" className="mb-4 flex items-start gap-2 rounded-sm border border-accent/40 bg-accent/5 px-3 py-2 text-[13px] text-foreground">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-accent" />
              <span>{error}</span>
            </div>
          )}
          {notice && (
            <div role="status" className="mb-4 flex items-start gap-2 rounded-sm border border-border bg-muted px-3 py-2 text-[13px] text-foreground">
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-primary" />
              <span>{notice}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="auth-id" className="text-[13px] text-foreground">
                {meta.idLabel}
              </Label>
              <div className="relative">
                <IdCard className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="auth-id"
                  value={id}
                  onChange={(event) => {
                    setId(event.target.value);
                    setOtp("");
                    setMfaChallengeId(null);
                    setDemoOtp(null);
                  }}
                  placeholder={meta.idPlaceholder}
                  autoComplete="username"
                  className="border-border/70 bg-input-background pl-9 font-mono text-[13px] focus-visible:border-ring focus-visible:ring-ring/40"
                />
              </div>
            </div>

            {mode === "signup" && (
              <div className="grid gap-2">
                <Label htmlFor="auth-name" className="text-[13px] text-foreground">
                  Full Name
                </Label>
                <div className="relative">
                  <User className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
                  <Input
                    id="auth-name"
                    value={name}
                    onChange={(event) => setName(event.target.value)}
                    placeholder="As printed on candidate ID"
                    autoComplete="name"
                    className="border-border/70 bg-input-background pl-9 focus-visible:border-ring focus-visible:ring-ring/40"
                  />
                </div>
              </div>
            )}

            {mode !== "reset" && (
              <PasswordField
                id="auth-password"
                label="Password"
                value={password}
                onChange={(value) => {
                  setPassword(value);
                  setOtp("");
                  setMfaChallengeId(null);
                  setDemoOtp(null);
                }}
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
              />
            )}

            {mode === "login" && mfaChallengeId && (
              <div className="grid gap-2">
                <Label htmlFor="auth-otp" className="text-[13px] text-foreground">
                  Two-Factor Code
                </Label>
                <Input
                  id="auth-otp"
                  value={otp}
                  onChange={(event) => setOtp(event.target.value.replace(/\D/g, "").slice(0, 6))}
                  placeholder="6-digit OTP"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  className="border-border/70 bg-input-background font-mono tracking-[0.28em] focus-visible:border-ring focus-visible:ring-ring/40"
                />
                {demoOtp && <p className="text-[11px] text-muted-foreground">Demo OTP: {demoOtp}</p>}
              </div>
            )}

            {mode === "signup" && (
              <PasswordField id="auth-confirm" label="Confirm Password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
            )}

            {mode === "login" && role === "candidate" && (
              <button
                type="button"
                onClick={() => {
                  setMode("reset");
                  setError(null);
                  setNotice(null);
                }}
                className="justify-self-start text-[13px] text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                Forgot password?
              </button>
            )}

            {mode === "login" && role !== "candidate" && (
              <p className="rounded-sm bg-muted px-3 py-2 text-[12px] text-muted-foreground">
                Staff accounts are institution-managed. Self-service reset is disabled for privileged roles.
              </p>
            )}

            {mode === "signup" && (
              <p className="rounded-sm bg-muted px-3 py-2 text-[12px] text-muted-foreground">
                Passwords cannot include your roll number, name, common exam terms, or other sensitive personal details.
              </p>
            )}

            <Button type="submit" disabled={busy} className="mt-1 w-full bg-primary text-primary-foreground hover:brightness-110 active:brightness-95">
              {mode === "login" && (mfaChallengeId ? "Verify code and sign in" : "Continue with password")}
              {mode === "signup" && "Create account"}
              {mode === "reset" && "Send reset instructions"}
            </Button>
          </form>

          <div className="mt-5 border-t border-border/70 pt-4 text-[13px] text-muted-foreground">
            {mode === "login" && role === "candidate" && (
              <span>
                New candidate?{" "}
                <button
                  onClick={() => {
                    setMode("signup");
                    reset();
                  }}
                  className="text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  Create an account
                </button>
              </span>
            )}
            {mode === "login" && role !== "candidate" && <span>Accounts for this role are provisioned by the institution only.</span>}
            {(mode === "signup" || mode === "reset") && (
              <button
                onClick={() => {
                  setMode("login");
                  reset();
                }}
                className="inline-flex items-center gap-1 text-primary underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              >
                <ArrowLeft className="size-3.5" /> Back to sign in
              </button>
            )}
          </div>

          <p className="mt-4 font-mono text-[11px] tracking-wide text-muted-foreground">DEMO CREDENTIALS - {meta.demo}</p>
        </div>
      </div>
    </div>
  );
}

function StatusItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-sm border border-border/70 bg-background px-3 py-2">
      <span className="text-[12px] text-muted-foreground">{label}</span>
      <span className="font-mono text-[11px] text-foreground">{value}</span>
    </div>
  );
}
