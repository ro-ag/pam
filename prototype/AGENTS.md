# Prototype Instructions

Run the local server yourself and open the preview in the browser available to this environment. Do not give the user server-start instructions when you can run it.

Before making substantial visual changes, use the Product Design plugin's `get-context` skill when the visual source is unclear or no longer matches the current goal. When the user gives durable prototype-specific design feedback, preferences, or decisions, record them in `AGENTS.md`.

When implementing from a selected generated mock, treat that image as the source of truth for layout, component anatomy, density, spacing, color, typography, visible content, and hierarchy.

## PAM visual direction

- The approved target is the revised timeline-led "Project Current" screen at
  `reference/pam-project-current-approved.png`.
- PAM is "Baywatch for developers": confident, warm, glamorous, coastal, and
  always watching the project. It is not an emergency-response or rescue tool.
- Preserve the midnight navy, sunset coral, Pacific aqua, and warm sand visual
  identity. Avoid sirens, shields, medical symbols, lifebuoys, warning stripes,
  military/security-console styling, or generic disaster language.
- The primary UX is durable continuity: a project timeline expands into a
  provenance-backed brief that is ready for the next coding agent.

Build app UI in `src/`. Keep `.openai/hosting.json`, `worker/index.js`, `scripts/prepare-sites-build.mjs`, and `tests/sites-worker.test.mjs` intact so the same local prototype can be handed to Sites. Before a Sites handoff, run `npm run build` and `npm run test:sites`; the build must leave `dist/client/index.html`, `dist/server/index.js`, and `dist/.openai/hosting.json`.
