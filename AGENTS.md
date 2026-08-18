<!-- ptrack:begin -->
## ptrack — session context

This project uses `ptrack` to persist planning state so a fresh agent can
resume after a previous session grew too large.

**At session start** — reload context:
- `ptrack context` — goal, summary, active plan, open tasks, blockers, open issues, inventory (add `--json` to parse).

**If the project is empty** — populate it from this repo (README, docs, code, git
log, open issues), then keep it current:
- Goal: `ptrack goal set "north star"`
- Milestones (checkpoints): `ptrack milestone add "v1.0" [--due YYYY-MM-DD]`
- Plans (workstreams): `ptrack plan add "..." [--milestone N]`, then `ptrack plan use N`
- Tasks with status: `ptrack task add "..." [--plan N]` then `task start` (in progress) / `task done` / `task block` (todo = pending)
- Issues (bugs/problems): `ptrack issue add "..." [--severity high] [--task N]`
- Decisions: `ptrack note add "..." [--task N | --plan N]`

**Titles are names, not status.** Do not prefix titles with "Pending:", "In
progress:", "Done:", etc. — ptrack tracks status separately. Set it with
`task start|done|block`, `plan done|use`, `milestone done`, `issue close`. Rename with
`ptrack <plan|task|milestone|issue> rename <id> "new title"`.

**Record decisions, not narration.** Notes are the human-visible audit trail of
what you did and *why*. When you make a choice, hit a blocker, or find a
constraint, capture it — one decision per note:
`ptrack note add "chose X over Y because Z" --task N`. Do not log routine
steps, tool output, or restate the code.

**Commits are tracked.** Reference the task in commit messages as `#<id>` so the
commit links to it (`ptrack hook install` records commits automatically; each
commit's `#<id>` links it to that task, otherwise the active plan).

**Before ending** — save the narrative for the next agent:
- `ptrack summary set "where we are"`

**Query on demand** (all bounded, `--json` available):
- `ptrack next` · `ptrack board` · `ptrack milestone list` · `ptrack plan show <id>` · `ptrack task show <id>` · `ptrack task list --status doing,blocked` · `ptrack issue list` · `ptrack search <term>` · `ptrack note list`

If no project exists yet: `ptrack init --goal "..."`.

---

## Working agreements

Standing rules for any agent working in this project (from ~/dev/ai):

- **Branch first.** Never commit to `main`/`master`. Land work via PR + squash
  merge; leave only `main` behind in local and remote.
- **No AI attribution** in commits, PRs, or release notes — no `Co-Authored-By`,
  no "Generated with …".
- **Stay in scope.** Do not refactor unrelated code, modify unrelated files, or
  add dependencies without approval.
- **Releases only on explicit request**, and only via CI on tag push — never a
  local publish. Keep tag, changelog, and README consistent; tests green first.
- **CI stays cheap.** No new workflows without an explicit request; triggers on
  merge to `main` / release tags only. When CI exists or is requested: lint and
  portable unit tests on Linux only, Windows gated to PRs + `main`, macOS
  UI/AppKit tests gated to approved PRs / `main` / nightly / releases. Cancel
  superseded PR runs (`concurrency`), filter paths, cache dependencies, and
  make expensive jobs `needs:` the cheap Linux checks first.
- **No repo or no remote → stop and ask** before making changes.
<!-- ptrack:end -->
