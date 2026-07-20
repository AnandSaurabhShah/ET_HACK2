import { Wrench } from "lucide-react";

export function CveQueue({ items }: { items: any[] }) {
  return (
    <section className="rounded-sm border border-border/70 bg-card p-4">
      <h2 className="mb-3 flex items-center gap-2 text-[15px] font-semibold text-foreground">
        <Wrench className="size-4" /> Vulnerability Remediation Queue
      </h2>
      <div className="overflow-auto">
        <table className="w-full min-w-[520px] text-left text-[12px]">
          <thead className="border-b border-border/70 text-muted-foreground">
            <tr>
              <th className="py-2 font-medium">CVE</th>
              <th className="py-2 font-medium">Asset</th>
              <th className="py-2 font-medium">Risk</th>
              <th className="py-2 font-medium">TTP</th>
              <th className="py-2 font-medium">Source</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.cve} className="border-b border-border/40">
                <td className="py-2 font-mono text-foreground">{item.cve}</td>
                <td className="py-2 text-foreground">{item.asset?.name ?? item.asset_id}</td>
                <td className="py-2 font-mono text-foreground">{item.risk_score}</td>
                <td className="py-2 font-mono text-muted-foreground">{item.related_techniques?.join(", ")}</td>
                <td className="py-2">
                  <span className="rounded-sm bg-muted px-2 py-1 font-mono text-[11px] text-foreground">
                    {item.source ?? "cached"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
