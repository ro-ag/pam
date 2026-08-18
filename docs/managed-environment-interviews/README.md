# Managed-environment developer study

Status: public-source baseline and optional study kit complete for the
solo-maintainer product foundation; recruitment and field validation have never
started

## Objective

The public-source baseline documents how developers on company-managed machines
resume work, diagnose CI failures, and cross approval boundaries while using
coding agents and corporate tools. The optional study kit prepares a future
field study that can test PAM's product assumptions with real behavior.

Public issue reports and prototype scenarios may inform the interview guide, but
they do not count as interviews or observations. No participants have been
recruited, and no interviews or workflow observations have occurred.

## Eligibility and cohort

A participant must:

- be an adult professional developer who works in a company-managed development
  environment;
- use at least one corporate source-control, CI, ticketing, documentation,
  quality, access, or deployment system;
- currently use a coding agent for work or be able to explain how employer
  policy prevents its use;
- confirm that their employer permits the interview and proposed observation;
  and
- be able to discuss and demonstrate a real workflow without exposing employer
  secrets or violating policy.

Recruit five to eight eligible managed-environment developers. The cohort must
include at least three developers using managed macOS, including Apple Silicon
where available. Also aim for:

- exposure to managed Linux or Windows through at least one participant, if
  recruitment permits;
- at least two CI systems or materially different CI governance models;
- both individual contributors and developers with review, release, or
  operational responsibility; and
- a mix of environments with ordinary controls and stricter proxy, certificate,
  access, audit, or local-model restrictions.

One participant may satisfy multiple mix criteria. Record shortfalls rather than
quietly substituting an ineligible participant.

## Recruitment copy

> We are researching how developers on company-managed computers resume work,
> investigate CI failures, and handle actions that require approval. We are
> looking for professional developers for a 45-60 minute remote session. The
> session includes an interview and observation of a real workflow that you are
> permitted to show. Please do not reveal source code, credentials, customer
> data, internal URLs, or other employer-confidential information. You may pause,
> skip any question, redact the screen, or stop at any time. Recording is
> optional and requires separate explicit consent.

## Session protocol (45-60 minutes)

1. **Consent and safety — 5 minutes.** Confirm eligibility, voluntary
   participation, note-taking permission, whether recording is allowed, and
   what must not be captured. Explain that the participant controls the screen
   and all actions.
2. **Environment map — 5-10 minutes.** Ask about device management, coding-agent
   use, repositories, CI, ticketing, documentation, quality gates, proxies,
   certificates, credentials, and relevant approval policies.
3. **Workflow observation — 20-25 minutes.** Observe one permitted real workflow
   from its natural starting point. Ask the participant to work normally and use
   neutral prompts such as "What are you looking for now?" Record tools,
   handoffs, waits, repeated work, evidence consulted, approval boundaries, and
   the final outcome. Do not turn the observation into a PAM demo.
4. **Decision questions — 10-15 minutes.** Ask the four questions below only
   after observing current behavior. Probe for conditions, objections, and
   counterexamples rather than seeking agreement.
5. **Recap — 5 minutes.** Read back the main findings, invite corrections,
   confirm what may appear in a redacted synthesis, and explain how deletion of
   private material can be requested.

## Future field-study workflow gates

If the future field study proceeds, observe both of these workflows at least
once across the cohort:

Both field-study completion gates require live direct observation. A
participant-driven replay or recollection of a recent case may provide
supplemental interview evidence, but it does not satisfy either required
workflow observation.

1. **Real CI diagnosis.** A participant investigates an actual failing CI run
   for work they are authorized to show, from notification or run discovery
   through evidence collection and a diagnosed, blocked, or unresolved outcome.
   A hypothetical scenario or recollection without observable artifacts does
   not count.
2. **Approval-heavy task.** A participant performs a real task that reaches a
   meaningful human or policy boundary, such as requesting access, rerunning or
   deploying with approval, changing a ticket, or publishing a result. Observe
   preparation, review context, the approval interaction, and verification or
   blockage. The researcher must never ask the participant to make an otherwise
   unnecessary external change.

For each observation, retain a redacted timeline with timestamps or durations,
tools and surfaces used, evidence sought, interruptions, approval points,
outcome, and a private source reference. One session may cover both workflows
only when both occur naturally and each has distinct evidence.

## Four decision questions

1. Under what conditions would the participant and their company allow a local
   PAM daemon to run, and what would make it unacceptable?
2. Which audit events and source evidence should PAM retain, for how long, where,
   and under whose deletion or export control?
3. Does company policy permit local model weights and inference; if so, which
   acquisition, license, storage, network, and hardware constraints apply?
4. For the primary control surface, does observed work require the strongest
   emphasis on project queues, repeatable flows, or access policy, and why?

## Evidence and privacy rules

- Assign pseudonymous session IDs such as `P01`; do not commit names, employers,
  contact details, internal URLs, repository names, credentials, source code, or
  customer data.
- Store consent records, raw notes, recordings, transcripts, and screenshots
  only in an approved encrypted location outside the repository checkout, with
  access limited to the study team. The ignored `/research-private/` path is
  defense in depth if raw material is placed in the checkout accidentally; it is
  not an approved storage location, and accidental material must be moved or
  deleted immediately.
- Recording is optional. Obtain separate explicit consent before recording and
  document the retention/deletion date. A participant who declines recording
  may still participate through contemporaneous structured notes.
- Stop capture immediately if a secret or restricted artifact appears. Remove
  it from notes and recordings; do not rely on later repository redaction.
- Publish only aggregated findings and short redacted paraphrases. Never commit
  raw or direct quotations, even when recording or quotation consent was given.
- Maintain finding-to-session provenance only in the private evidence matrix.
  The public synthesis uses coarse aggregate counts and evidence classes, never
  session identifiers, and records contradictory evidence and cohort
  limitations.
- Honor participant withdrawal and deletion requests according to the consent
  agreement before publishing or retaining a synthesis.

## Future field-study completion checklist

The public-source baseline and optional study kit complete the solo-maintainer
foundation deliverable, but they do not satisfy this future field-study
checklist. Recruitment has never started, so leave every item unchecked until
the referenced real evidence exists and has been reviewed.

- [ ] Five to eight eligible participants completed the protocol, including at
  least three eligible developers using managed macOS. Optional cross-platform
  mix shortfalls are documented and do not waive the managed-macOS minimum.
- [ ] Every session has a date, duration, eligibility record, consent scope,
  structured notes, and a resolvable private evidence reference.
- [ ] At least one real CI diagnosis was observed and documented through its
  actual outcome.
- [ ] At least one real approval-heavy task was observed and documented through
  approval, rejection, blockage, or verified effect.
- [ ] The four decision questions are answered from participant and observation
  evidence, including objections and counterexamples.
- [ ] The public synthesis reports theme counts, evidence type, contradictions,
  cohort limitations, and resulting product decisions without personal or
  employer-confidential data.
- [ ] `docs/research.md` and any affected product or roadmap claims are updated
  to distinguish validated findings from remaining assumptions.
