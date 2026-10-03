import { adminCall, type EffectiveBlock, type PolicyDrop } from "./ipc";

export interface LandingCheck {
  name: string;
  argv: string[];
  timeout_seconds: number;
}
/** How a landing merges its pull request; `squash` when unset. */
export type LandingMergeMethod = "squash" | "merge" | "rebase";
export const MERGE_METHODS: LandingMergeMethod[] = ["squash", "merge", "rebase"];
/**
 * A required check: a bare name (legacy, matched from any app) or the name pinned to the GitHub
 * App that reports it, so a same-named check from another app cannot satisfy it.
 */
export type LandingRequiredCheck = string | { name: string; app_id: number };
export interface LandingRepository {
  root: string;
  repository: string;
  github_server: string;
  github_repository: string;
  base: string;
  branches: string[];
  workspace_root: string;
  read_cache_roots?: string[];
  checks: LandingCheck[];
  required_checks: LandingRequiredCheck[];
  main_checks: LandingRequiredCheck[];
  permissions: { push: boolean; create_pr: boolean; merge: boolean; sync: boolean };
  merge_method?: LandingMergeMethod;
}
export interface LandingPolicy {
  revision: string;
  /** The Git the landing broker runs; null uses the first trusted installation. */
  git_path?: string | null;
  /** What the human saved; the editor shows and sends these. */
  repositories: LandingRepository[];
  /**
   * What landing checks read under the managed policy: `max_permissions` carries the ceiling as
   * its `value`, `allowed_github_servers` the allowed servers (or null), `repositories` the
   * recipes in force.
   */
  effective?: EffectiveBlock<
    "max_permissions" | "allowed_github_servers" | "git_path" | "merge_method" | "repositories"
  >;
  /** Recipes the managed policy stops using: kept, reported, never used. */
  landing_policy_dropped?: PolicyDrop[];
}
export function landingGet(): Promise<LandingPolicy> {
  return adminCall("admin.flows.landing.get");
}
export function landingSet(
  expected_revision: string,
  repositories: LandingRepository[],
  git_path: string | null = null,
): Promise<LandingPolicy> {
  return adminCall("admin.flows.landing.set", { expected_revision, git_path, repositories });
}
export function emptyLandingRepository(): LandingRepository {
  return {
    root: "",
    repository: "",
    github_server: "https://api.github.com/",
    github_repository: "",
    base: "main",
    branches: [],
    workspace_root: "",
    read_cache_roots: [],
    checks: [{ name: "", argv: [""], timeout_seconds: 300 }],
    required_checks: [],
    main_checks: [],
    permissions: { push: false, create_pr: false, merge: false, sync: false },
  };
}
