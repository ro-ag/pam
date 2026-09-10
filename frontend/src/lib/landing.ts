import { adminCall } from "./ipc";

export interface LandingCheck {
  name: string;
  argv: string[];
  timeout_seconds: number;
}
export interface LandingRepository {
  root: string;
  repository: string;
  github_server: string;
  github_repository: string;
  base: string;
  branches: string[];
  workspace_root: string;
  checks: LandingCheck[];
  required_checks: string[];
  main_checks: string[];
  permissions: { push: boolean; create_pr: boolean; merge: boolean; sync: boolean };
}
export interface LandingPolicy {
  revision: string;
  repositories: LandingRepository[];
}
export function landingGet(): Promise<LandingPolicy> {
  return adminCall("admin.flows.landing.get");
}
export function landingSet(
  expected_revision: string,
  repositories: LandingRepository[],
): Promise<LandingPolicy> {
  return adminCall("admin.flows.landing.set", { expected_revision, repositories });
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
    checks: [{ name: "", argv: [""], timeout_seconds: 300 }],
    required_checks: [],
    main_checks: [],
    permissions: { push: false, create_pr: false, merge: false, sync: false },
  };
}
