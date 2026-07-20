import { useState } from "react";
import { ArrowLeft, ShieldCheck, CheckCircle2, XCircle, QrCode } from "lucide-react";
import { Input } from "./ui/input";
import { Label } from "./ui/label";
import { Button } from "./ui/button";
import { api } from "../lib/api";

interface CertificateVerificationProps {
  onBack: () => void;
}

// Public path: never requires login, never exposes more than status/name/exam.
const SAMPLE_CERTS: Record<string, { name: string; exam: string; year: string; result: string }> = {
  "PK-2025-NEET-88213": { name: "Ananya Rao", exam: "National Eligibility Test (NEET)", year: "2025", result: "Qualified" },
  "PK-2025-CS-40917": { name: "Vikram Menon", exam: "Civil Services Preliminary", year: "2025", result: "Qualified" },
  "PK-2024-GATE-11002": { name: "Sara Iqbal", exam: "Graduate Aptitude Test (GATE)", year: "2024", result: "Qualified" },
};

export function CertificateVerification({ onBack }: CertificateVerificationProps) {
  const [query, setQuery] = useState("");
  const [result, setResult] = useState<
    null | { status: "valid"; data: (typeof SAMPLE_CERTS)[string]; id: string } | { status: "invalid"; id: string }
  >(null);

  function verify(e: React.FormEvent) {
    e.preventDefault();
    const key = query.trim().toUpperCase();
    if (!key) return;
    const data = SAMPLE_CERTS[key];
    setResult(data ? { status: "valid", data, id: key } : { status: "invalid", id: key });
    void api.ingestEvent({
      user_id: "public-certificate-lookup",
      role: "candidate",
      device_id: "PUBLIC-WEB",
      segment: "certificate-service",
      ip: "127.0.0.1",
      event_type: "cert_lookup",
      success: Boolean(data),
      latency_ms: data ? 145 : 260,
      bytes_out: data ? 18 : 4,
      metadata: { certificate_id: key },
    });
  }

  return (
    <div className="min-h-screen w-full bg-background">
      <div className="mx-auto max-w-2xl px-6 py-16">
        <button
          onClick={onBack}
          className="mb-8 inline-flex items-center gap-2 rounded-sm text-[13px] text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <ArrowLeft className="size-4" /> Back to home
        </button>

        <div className="mb-6 flex items-center gap-3">
          <div className="flex size-11 items-center justify-center rounded-sm bg-primary text-primary-foreground">
            <ShieldCheck className="size-6" />
          </div>
          <div>
            <h1 style={{ fontFamily: "var(--font-serif)" }} className="text-[22px] leading-tight text-foreground">
              Verify a Certificate
            </h1>
            <p className="font-mono text-[11px] tracking-wide text-muted-foreground">PUBLIC · NO LOGIN REQUIRED</p>
          </div>
        </div>

        <form
          onSubmit={verify}
          className="rounded-sm border border-border/70 bg-card p-6"
        >
          <Label htmlFor="cert-id" className="text-[13px] text-foreground">
            Certificate ID or QR reference
          </Label>
          <div className="mt-2 flex gap-2">
            <div className="relative flex-1">
              <QrCode className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                id="cert-id"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="PK-2025-NEET-88213"
                className="border-border/70 bg-input-background pl-9 font-mono text-[13px] focus-visible:border-ring focus-visible:ring-ring/40"
              />
            </div>
            <Button type="submit" className="bg-primary text-primary-foreground hover:brightness-110">
              Verify
            </Button>
          </div>
          <p className="mt-3 font-mono text-[11px] tracking-wide text-muted-foreground">
            TRY · PK-2025-NEET-88213 · PK-2025-CS-40917 · PK-2024-GATE-11002
          </p>
        </form>

        {result?.status === "valid" && (
          <div className="mt-6 overflow-hidden rounded-sm border border-border/70 bg-card">
            <div className="flex items-center gap-2 border-b border-border/70 bg-primary/5 px-5 py-3">
              <CheckCircle2 className="size-5 text-primary" />
              <span className="text-[14px] text-foreground" style={{ fontWeight: 600 }}>
                Verified — Authentic
              </span>
            </div>
            <dl className="grid gap-3 p-5 text-[14px]">
              {[
                ["Candidate", result.data.name],
                ["Examination", result.data.exam],
                ["Year", result.data.year],
                ["Result", result.data.result],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-4">
                  <dt className="font-mono text-[11px] tracking-wide text-muted-foreground">{k.toUpperCase()}</dt>
                  <dd className="text-right text-foreground">{v}</dd>
                </div>
              ))}
              <div className="mt-1 flex justify-between gap-4 border-t border-border/70 pt-3">
                <dt className="font-mono text-[11px] tracking-wide text-muted-foreground">CERTIFICATE ID</dt>
                <dd className="text-right font-mono text-[12px] text-foreground">{result.id}</dd>
              </div>
            </dl>
          </div>
        )}

        {/* Invalid state — one of the three sanctioned uses of --accent (red). */}
        {result?.status === "invalid" && (
          <div className="mt-6 rounded-sm border-2 border-accent bg-accent/5 p-5">
            <div className="flex items-center gap-2">
              <XCircle className="size-5 text-accent" />
              <span className="text-[14px] text-foreground" style={{ fontWeight: 600 }}>
                Not Found — Could Not Be Verified
              </span>
            </div>
            <p className="mt-2 text-[13px] text-muted-foreground">
              No certificate matches{" "}
              <span className="font-mono text-foreground">{result.id}</span>. Check the ID and try again.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
