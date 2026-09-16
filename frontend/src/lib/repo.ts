/** The last segment of a repo path: `/Users/me/pam` → `pam`. The full path rides on a title. */
export function repoTail(repo: string): string {
  const segments = repo.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? repo;
}
