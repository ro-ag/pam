import { ArrowClockwise, PuzzlePiece, WarningCircle } from "@phosphor-icons/react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { sameFence, withOperation } from "../bridge";
import type { CommandFence, PamBridge, SkillInventoryDataDto } from "../domain";
import { presentError } from "../state";

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function driftSummary(data: SkillInventoryDataDto): string {
  const { added, changed, removed, resurrected } = data.drift;
  if (added === 0 && changed === 0 && removed === 0 && resurrected === 0) {
    return "No inventory drift detected.";
  }
  return `Inventory drift: ${added} added, ${changed} changed, ${removed} removed, ${resurrected} restored.`;
}

export interface SkillInventoryPanelProps {
  bridge: PamBridge;
  fence: CommandFence;
}

export function SkillInventoryPanel({ bridge, fence }: SkillInventoryPanelProps) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { gcTime: 0, retry: false, staleTime: 0 } },
  }));
  return (
    <QueryClientProvider client={queryClient}>
      <SkillInventoryContent bridge={bridge} fence={fence} />
    </QueryClientProvider>
  );
}

function SkillInventoryContent({ bridge, fence }: SkillInventoryPanelProps) {
  const inventoryQuery = useQuery({
    queryKey: ["skill-inventory", fence.projectHandle, fence.generation],
    queryFn: async (): Promise<SkillInventoryDataDto> => {
      const requestFence = withOperation(fence);
      const response = await bridge.loadSkillInventory(requestFence);
      if (!sameFence(requestFence, response.fence)) {
        throw new Error("The skill inventory response did not match the active project request. Retry inventory.");
      }
      return response.data;
    },
  });
  const inventory = inventoryQuery.data ?? null;
  const error = inventoryQuery.error ? presentError(inventoryQuery.error) : null;
  const loading = inventoryQuery.isPending;

  return (
    <section className="panel skill-inventory-panel" aria-labelledby="skill-inventory-heading">
      <div className="panel-title">
        <div><span className="eyebrow">Agent ecosystems</span><h2 id="skill-inventory-heading">Skill inventory</h2></div>
        <PuzzlePiece size={22} />
      </div>
      {loading && !inventory ? (
        <div className="skill-inventory-state" role="status">Scanning bounded local agent configuration…</div>
      ) : error && !inventory ? (
        <div className="skill-inventory-state is-error" role="alert">
          <WarningCircle size={24} />
          <div><strong>Skill inventory unavailable</strong><p>{error}</p></div>
          <button type="button" className="button button--secondary" onClick={() => { void inventoryQuery.refetch(); }}><ArrowClockwise size={18} /> Retry inventory</button>
        </div>
      ) : inventory ? (
        <>
          <div className="skill-inventory-summary" role="status">
            <span>{driftSummary(inventory)}</span>
            <span>Cursor global rules: {label(inventory.cursorGlobalRulesStatus)}.</span>
          </div>
          {inventory.artifacts.length === 0 ? (
            <p className="panel-empty">No supported agent artifacts were found for this project.</p>
          ) : (
            <div className="skill-inventory-list">
              {inventory.artifacts.map((artifact) => (
                <article key={artifact.id}>
                  <span className="access-icon"><PuzzlePiece size={20} /></span>
                  <div>
                    <strong>{artifact.name}</strong>
                    <p>{artifact.logicalPath}</p>
                    <small>{label(artifact.kind)} · {label(artifact.scope)} · {label(artifact.loadSemantics)}</small>
                  </div>
                  <span className="state-pill">{label(artifact.origin)}</span>
                </article>
              ))}
            </div>
          )}
          {inventory.truncated && <p className="skill-inventory-truncated">Showing {inventory.artifacts.length} of {inventory.total} artifacts. The native response is bounded.</p>}
        </>
      ) : null}
    </section>
  );
}
