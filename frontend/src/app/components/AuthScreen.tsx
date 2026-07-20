import { useState } from "react";
import {
  ShieldCheck,
  GraduationCap,
  Eye,
  Scan,
  ArrowLeft,
  AlertTriangle,
  CheckCircle2,
  User,
  IdCard,
  BadgeCheck,
  Radar,
} from "lucide-react";
import type { Role } from "../types";
import { ROLE_LABELS } from "../types";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { PasswordField } from "./PasswordField";

type Mode = "login" | "signup" | "reset";

interface AuthScreenProps {
  onLogin: (role: Role, id: string, password: string) => { ok: boolean; error?: string };
  onRegister: (id: string, password: string, name: string) => { ok: boolean; error?: string };
  onVerifyCertificate: () => void;
}

const ROLE_META: Record<
  Role,
  { icon: typeof GraduationCap; blurb: string; idLabel: string; idPlaceholder: string; demo: string }
> = {
  candidate: {
    icon: GraduationCap,
    blurb: "Sit your examination, download your hall ticket, and view results.",
    idLabel: "Roll Number",
    idPlaceholder: "CAND-2026-004821",
    demo: "CAND-2026-004821 / candidate",
  },
  invigilator: {
    icon: Eye,
    blurb: "Monitor centres and review flagged sessions for human judgement.",
    idLabel: "Staff ID",
    idPlaceholder: "INV-DEL-0097",
    demo: "INV-DEL-0097 / invigilator",
  },
  examiner: {
    icon: Scan,
    blurb: "Enter the secured on-screen marking environment (blind marking).",
    idLabel: "Marker Staff ID",
    idPlaceholder: "OSM-7731",
    demo: "OSM-7731 / examiner",
  },
  security: {
    icon: Radar,
    blurb: "Operate Aegis-CNI behavioural detection, attribution, and containment.",
    idLabel: "SOC Operator ID",
    idPlaceholder: "SOC-AEGIS-001",
    demo: "SOC-AEGIS-001 / security",
  },
};

export function AuthScreen({ onLogin, onRegister, onVerifyCertificate }: AuthScreenProps) {
  const [role, setRole] = useState<Role | null>(null);
  const [mode, setMode] = useState<Mode>("login");

  // form fields
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const isExaminer = role === "examiner";

  function reset() {
    setId("");
    setName("");
    setPassword("");
    setConfirm("");
    setError(null);
    setNotice(null);
  }

  function chooseRole(r: Role) {
    setRole(r);
    setMode("login");
    reset();
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setNotice(null);
    if (!role) return;

    if (mode === "reset") {
      // Candidate-only lower-assurance reset flow.
      if (!id.trim()) {
        setError("Enter your roll number to receive reset instructions.");
        return;
      }
      setNotice(`Password reset instructions sent for ${id.trim()}. Check your registered email.`);
      return;
    }

    if (mode === "signup") {
      if (!id.trim() || !name.trim()) {
        setError("Roll number and full name are required.");
        return;
      }
      if (password.length < 8) {
        setError("Password must be at least 8 characters.");
        return;
      }
      if (password !== confirm) {
        setError("Passwords do not match.");
        return;
      }
      const res = onRegister(id, password, name.trim());
      if (!res.ok) setError(res.error ?? "Registration failed.");
      return;
    }

    // login
    if (!id.trim() || !password) {
      setError("Both fields are required.");
      return;
    }
    const res = onLogin(role, id, password);
    if (!res.ok) setError(res.error ?? "Login failed.");
  }

  // ---- Role selection landing ----
  if (!role) {
    return (
      <div className="min-h-screen w-full bg-background">
        <div className="mx-auto flex min-h-screen max-w-5xl flex-col justify-center px-6 py-16">
          <div className="mb-10 flex items-center gap-3">
            <div className="flex size-11 items-center justify-center rounded-sm bg-primary text-primary-foreground">
              <ShieldCheck className="size-6" />
            </div>
            <div>
              <h1 style={{ fontFamily: "var(--font-serif)" }} className="text-[22px] leading-tight text-foreground">
                Pariksha Kendra
              </h1>
              <p className="font-mono text-[11px] tracking-wide text-muted-foreground">
                NATIONAL EXAMINATION DELIVERY PLATFORM
              </p>
            </div>
          </div>

          <h2 style={{ fontFamily: "var(--font-serif)" }} className="mb-1 text-[18px] text-foreground">
            Select how you are signing in
          </h2>
          <p className="mb-6 text-[14px] text-muted-foreground">
            Each credential grants access to exactly one interface.
          </p>

          <div className="grid gap-4 md:grid-cols-4">
            {(Object.keys(ROLE_META) as Role[]).map((r) => {
              const meta = ROLE_META[r];
              const Icon = meta.icon;
              const dark = r === "examiner";
              return (
                <button
                  key={r}
                  onClick={() => chooseRole(r)}
                  className={[
                    "group flex flex-col gap-3 rounded-sm border p-5 text-left transition-all",
                    "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
                    dark
                      ? "border-transparent bg-[var(--examiner-header)] text-white hover:brightness-125"
                      : "border-border/70 bg-card text-foreground hover:border-ring hover:shadow-[0_0_0_1px_var(--ring)]",
                  ].join(" ")}
                >
                  <div
                    className={[
                      "flex size-10 items-center justify-center rounded-sm",
                      dark ? "bg-white/10 text-white" : "bg-primary text-primary-foreground",
                    ].join(" ")}
                  >
                    <Icon className="size-5" />
                  </div>
                  <div>
                    <div className="text-[15px]" style={{ fontWeight: 600 }}>
                      {ROLE_LABELS[r]}
                    </div>
                    <p className={dark ? "mt-1 text-[13px] text-white/70" : "mt-1 text-[13px] text-muted-foreground"}>
                      {meta.blurb}
                    </p>
                  </div>
                  {dark && (
                    <span className="mt-1 font-mono text-[11px] tracking-wide text-white/60">
                      SECURED SESSION ENVIRONMENT
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Public certificate verification — never requires login */}
          <div className="mt-8 flex flex-col items-start gap-3 rounded-sm border border-border/70 bg-card p-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex items-center gap-3">
              <BadgeCheck className="size-5 text-primary" />
              <div>
                <div className="text-[14px] text-foreground" style={{ fontWeight: 600 }}>
                  Verify a Certificate
                </div>
                <p className="text-[13px] text-muted-foreground">
                  Public verification for employers &amp; institutions — no login required.
                </p>
              </div>
            </div>
            <Button variant="outline" onClick={onVerifyCertificate} className="border-border/70">
              Open verification
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // ---- Login / Sign-up / Reset for the chosen role ----
  const meta = ROLE_META[role];
  const Icon = meta.icon;

  return (
    <div
      className={[
        "min-h-screen w-full",
        isExaminer ? "bg-[var(--examiner-header)]" : "bg-background",
      ].join(" ")}
    >
      <div className="mx-auto grid min-h-screen max-w-5xl items-center gap-8 px-6 py-12 md:grid-cols-2">
        {/* Brand / context panel */}
        <div className={isExaminer ? "text-white" : "text-foreground"}>
          <button
            onClick={() => setRole(null)}
            className={[
              "mb-8 inline-flex items-center gap-2 rounded-sm text-[13px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
              isExaminer ? "text-white/70 hover:text-white" : "text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            <ArrowLeft className="size-4" /> Choose a different role
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
              <h1 style={{ fontFamily: "var(--font-serif)" }} className="text-[22px] leading-tight">
                Pariksha Kendra
              </h1>
              <p
                className={[
                  "font-mono text-[11px] tracking-wide",
                  isExaminer ? "text-white/60" : "text-muted-foreground",
                ].join(" ")}
              >
                {ROLE_LABELS[role].toUpperCase()}
              </p>
            </div>
          </div>

          <p className={isExaminer ? "max-w-sm text-[15px] text-white/75" : "max-w-sm text-[15px] text-muted-foreground"}>
            {meta.blurb}
          </p>

          {isExaminer && (
            <div className="mt-6 inline-flex items-center gap-2 rounded-sm border border-white/15 bg-white/5 px-3 py-2">
              <ShieldCheck className="size-4 text-white/80" />
              <span className="font-mono text-[11px] tracking-wide text-white/70">
                DISTINCT SECURED ENVIRONMENT · BLIND MARKING
              </span>
            </div>
          )}
        </div>

        {/* Form card */}
        <div className="w-full rounded-sm border border-border/70 bg-card p-6 shadow-sm md:p-8">
          <h2 style={{ fontFamily: "var(--font-serif)" }} className="text-[18px] text-card-foreground">
            {mode === "login" && "Sign in"}
            {mode === "signup" && "Create candidate account"}
            {mode === "reset" && "Reset password"}
          </h2>
          <p className="mb-5 mt-1 text-[13px] text-muted-foreground">
            {mode === "login" && `Enter your ${meta.idLabel.toLowerCase()} and password.`}
            {mode === "signup" && "Registration is available to candidates only."}
            {mode === "reset" && "We'll email reset instructions to your registered address."}
          </p>

          {error && (
            <div
              role="alert"
              className="mb-4 flex items-start gap-2 rounded-sm border border-accent/40 bg-accent/5 px-3 py-2 text-[13px] text-foreground"
            >
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-accent" />
              <span>{error}</span>
            </div>
          )}
          {notice && (
            <div
              role="status"
              className="mb-4 flex items-start gap-2 rounded-sm border border-border bg-muted px-3 py-2 text-[13px] text-foreground"
            >
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
                  onChange={(e) => setId(e.target.value)}
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
                    onChange={(e) => setName(e.target.value)}
                    placeholder="As printed on your ID document"
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
                onChange={setPassword}
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
              />
            )}

            {mode === "signup" && (
              <PasswordField
                id="auth-confirm"
                label="Confirm Password"
                value={confirm}
                onChange={setConfirm}
                autoComplete="new-password"
              />
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
                Staff credentials are institution-managed. Contact your controller of
                examinations for account recovery — no self-service reset.
              </p>
            )}

            <Button
              type="submit"
              className={[
                "mt-1 w-full bg-primary text-primary-foreground hover:brightness-110 active:brightness-95",
                "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
              ].join(" ")}
            >
              {mode === "login" && "Sign in"}
              {mode === "signup" && "Create account"}
              {mode === "reset" && "Send reset instructions"}
            </Button>
          </form>

          {/* Mode switches */}
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
            {mode === "login" && role !== "candidate" && (
              <span>Accounts for this role are provisioned by the institution only.</span>
            )}
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

          <p className="mt-4 font-mono text-[11px] tracking-wide text-muted-foreground">
            DEMO · {meta.demo}
          </p>
        </div>
      </div>
    </div>
  );
}
