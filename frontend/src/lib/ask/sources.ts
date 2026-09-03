/**
 * The reads the Ask router is allowed to make.
 *
 * The router is a pure library: it never touches `../ipc`, never runs
 * anything, and never writes. Everything it knows arrives through this
 * interface, so the screen injects a thin object over the bridge and the
 * tests inject fakes. The shapes are structural copies of the ipc
 * wrappers — narrow to what an answer actually reads — so the real
 * wrappers satisfy them without either side importing the other.
 */
export interface Sources {
  daemonStatus(): Promise<{ connected: boolean; status: Record<string, unknown> | null }>;
  approvalsPending(): Promise<{
    pending: Array<{
      request_id: string;
      capability: string;
      repo: string;
      agent: string;
      requested_ts: number;
    }>;
  }>;
  activityList(f: {
    limit?: number;
    repo?: string;
    agent?: string;
    state?: string;
    capability?: string;
    hide_probes?: boolean;
  }): Promise<{
    requests: Array<{
      id: string;
      capability: string;
      repo: string;
      agent: string;
      state: string;
      outcome: string | null;
      created_ts: number;
    }>;
  }>;
  modelsStatus(): Promise<{
    runtime: {
      state: {
        state: string;
        id?: string;
        device?: string;
        weight_bytes?: number;
        context_length?: number;
        quant?: string;
        last_used_at?: number;
        phase?: string;
      };
      busy: boolean;
    };
    defaults: { light: string | null; heavy: string | null };
    host_ram_bytes: number;
    models_dir: string;
  }>;
  retentionGet(): Promise<{ evidence_days: number | null; audit_days: number | null }>;
  serviceStatus(): Promise<{
    platform: string;
    state:
      | { kind: "installed"; unit: string; loaded: boolean }
      | { kind: "not_installed"; unit: string }
      | { kind: "unsupported"; reason: string };
  }>;
  evidenceStats(sinceTs: number): Promise<{
    compressions: number;
    source_bytes: number;
    compact_bytes: number;
    tokens_avoided_est: number;
  }>;
  flowsList(): Promise<{ flows: Array<{ id: string; name: string; valid: boolean }> }>;
  auditRequest(id: string): Promise<{
    rows: Array<{
      action: string;
      decision: string;
      actor: string;
      detail: unknown;
      ts: number;
    }>;
  }>;
  modelsTry(prompt: string, maxTokens: number): Promise<{ text: string }>;
}
