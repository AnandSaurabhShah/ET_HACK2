// Cross-cutting auth model (Part 6). Roles are mutually exclusive; each credential
// entitles a person to exactly one interface.
export type Role = "candidate" | "invigilator" | "examiner" | "security";

export interface AuthSession {
  userId: string; // roll number (candidate) or staff/operator ID
  role: Role;
  sessionId: string;
  displayName: string;
}

export const ROLE_LABELS: Record<Role, string> = {
  candidate: "Candidate",
  invigilator: "Invigilator / Proctor",
  examiner: "Examiner (On-Screen Marker)",
  security: "Security (SOC Command Center)",
};
