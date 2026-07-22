import { Ban, CheckCircle2 } from "lucide-react";
import type { BlockEntry } from "../../lib/api";
import { Button } from "../ui/button";

function remaining(entry: BlockEntry) {
  const seconds = Math.max(0, entry.expires_at - Date.now() / 1000);
  if (seconds >= 60) return `${Math.ceil(seconds / 60)}m`;
  return `${Math.ceil(seconds)}s`;
}

export function ActiveBlocks({ items, onUnblock }: { items: BlockEntry[]; onUnblock: (ip: string) => void }) {
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Ban className="size-4" /> Active Attack Blocks
      </h2>
      <div className="grid gap-2">
        {items.map((entry) => (
          <div key={entry.ip} className="rounded-sm border border-border/70 bg-background p-3">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="font-mono text-[12px] text-foreground">{entry.ip}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">{entry.reason}</p>
              </div>
              <span className="rounded-sm bg-muted px-2 py-1 font-mono text-[10px] text-foreground">{remaining(entry)}</span>
            </div>
            <div className="mt-2 flex items-center justify-between gap-2">
              <span className="font-mono text-[10px] text-muted-foreground">
                {entry.technique_id} - {Math.round(entry.confidence * 100)}%
              </span>
              <Button size="sm" variant="outline" className="h-7 border-border/70 text-[11px]" onClick={() => onUnblock(entry.ip)}>
                Unblock
              </Button>
            </div>
          </div>
        ))}
        {!items.length && (
          <p className="flex items-center gap-2 text-[13px] text-muted-foreground">
            <CheckCircle2 className="size-4 text-primary" /> No active source blocks.
          </p>
        )}
      </div>
    </section>
  );
}
