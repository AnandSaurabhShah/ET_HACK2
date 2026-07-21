import { Bot, Send } from "lucide-react";
import { useState } from "react";
import type { CopilotAnswer, SocAlert } from "../../lib/api";
import { Button } from "../ui/button";

export function SocCopilot({
  alert,
  answer,
  onAsk,
}: {
  alert?: SocAlert;
  answer?: CopilotAnswer | null;
  onAsk: (question: string) => Promise<void>;
}) {
  const [question, setQuestion] = useState("Why was this blocked?");
  const [busy, setBusy] = useState(false);

  async function ask() {
    setBusy(true);
    try {
      await onAsk(question);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Bot className="size-4" /> SOC Copilot
      </h2>
      <div className="flex gap-2">
        <input
          value={question}
          onChange={(event) => setQuestion(event.target.value)}
          className="min-w-0 flex-1 rounded-sm border border-border/70 bg-background px-2 py-2 text-[12px] text-foreground outline-none focus:ring-2 focus:ring-ring"
          placeholder={alert ? `Ask about ${alert.alert_id}` : "Ask about live incidents"}
        />
        <Button size="sm" className="h-9" onClick={() => void ask()} disabled={busy}>
          <Send className="size-3.5" />
        </Button>
      </div>
      {answer && (
        <div className="mt-3 rounded-sm bg-muted p-3 text-[12px]">
          <p className="text-foreground">{answer.answer}</p>
          <div className="mt-2 grid gap-1 text-[11px] text-muted-foreground">
            {answer.recommended_actions.slice(0, 4).map((item) => (
              <span key={item}>{item}</span>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
