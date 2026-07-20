import { useCallback, useState } from "react";
import type { AuthSession, Role } from "../types";
import { api } from "../lib/api";

// PRODUCTION NOTE: role separation is enforced here at the frontend router for demo
// purposes only; a production backend must independently reject any request outside
// the authenticated user's permitted scope.

// Demo credential store. In production this is never client-side.
const DEMO_ACCOUNTS: Record<
  Role,
  { id: string; password: string; name: string }[]
> = {
  candidate: [{ id: "CAND-2026-004821", password: "candidate", name: "Roll 2026-004821" }],
  invigilator: [{ id: "INV-DEL-0097", password: "invigilator", name: "A. Sharma" }],
  examiner: [{ id: "OSM-7731", password: "examiner", name: "Marker 7731" }],
  security: [{ id: "SOC-AEGIS-001", password: "security", name: "Aegis-CNI Operator" }],
};

function generateSessionId(): string {
  return "SESS-" + Math.random().toString(36).slice(2, 8).toUpperCase();
}

export function useAuth() {
  const [session, setSession] = useState<AuthSession | null>(null);

  function emitAuthEvent(event_type: string, role: Role, id: string, success: boolean, metadata: Record<string, unknown> = {}) {
    const deviceId = window.localStorage.getItem("aegis-device-id") ?? `WEB-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    window.localStorage.setItem("aegis-device-id", deviceId);
    void api.ingestEvent({
      user_id: id || "anonymous",
      role,
      device_id: deviceId,
      segment: role === "security" ? "soc" : role === "examiner" ? "marking" : role === "invigilator" ? "proctoring" : "candidate-portal",
      ip: "127.0.0.1",
      event_type,
      success,
      latency_ms: success ? 95 : 240,
      bytes_out: event_type === "logout" ? 2 : 12,
      metadata,
    });
  }

  const login = useCallback(
    (role: Role, id: string, password: string): { ok: boolean; error?: string } => {
      const match = DEMO_ACCOUNTS[role].find(
        (a) => a.id.toLowerCase() === id.trim().toLowerCase() && a.password === password,
      );
      if (!match) {
        emitAuthEvent("login", role, id.trim(), false, { reason: "invalid_credentials" });
        return { ok: false, error: "Invalid credentials for the selected role." };
      }
      const nextSession = {
        userId: match.id,
        role,
        sessionId: generateSessionId(),
        displayName: match.name,
      };
      setSession(nextSession);
      emitAuthEvent("login", role, match.id, true, { session_id: nextSession.sessionId });
      return { ok: true };
    },
    [],
  );

  // Only candidates may self-register; staff accounts are institution-provisioned.
  const registerCandidate = useCallback(
    (id: string, password: string, name: string): { ok: boolean; error?: string } => {
      if (DEMO_ACCOUNTS.candidate.some((a) => a.id.toLowerCase() === id.trim().toLowerCase())) {
        return { ok: false, error: "An account with this roll number already exists." };
      }
      DEMO_ACCOUNTS.candidate.push({ id: id.trim(), password, name });
      const nextSession = {
        userId: id.trim(),
        role: "candidate",
        sessionId: generateSessionId(),
        displayName: name,
      } as AuthSession;
      setSession(nextSession);
      emitAuthEvent("register_candidate", "candidate", id.trim(), true, { session_id: nextSession.sessionId });
      return { ok: true };
    },
    [],
  );

  const logout = useCallback(() => {
    if (session) emitAuthEvent("logout", session.role, session.userId, true, { session_id: session.sessionId });
    setSession(null);
  }, [session]);

  return { session, login, registerCandidate, logout };
}
