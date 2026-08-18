# Managed-environment interview and observation template

Copy this template to the approved encrypted research location outside the PAM
repository. Never commit a completed template. Use a pseudonymous session code,
write paraphrases rather than raw quotations, and omit sensitive content.

## Session metadata

- Session code (`P01`, `P02`, ...):
- Session month (avoid an identifying exact date when unnecessary):
- Researcher:
- Duration:
- Format (remote/in person):
- Role category and experience band:
- Primary OS category:
- Development environment category (managed device, VDI, remote host, other):
- Coding-agent status (usage cadence or employer-policy restriction):
- Policy context (broad category only):
- Workflow offered (CI diagnosis, approval-heavy task, both, other):

Do not record the participant's name, employer, team, repository, project,
account, hostname, or contact details here.

## Eligibility screener

- [ ] Adult professional developer.
- [ ] Works in a company-managed development environment.
- [ ] Uses at least one organization-controlled source-control, CI, ticketing,
      documentation, quality, access, or deployment system.
- [ ] Currently uses a coding agent for work, or can explain how employer policy
      prevents its use.
- [ ] Confirmed the interview and proposed observation are permitted by employer
      policy.
- [ ] Can discuss or demonstrate a sanitized real workflow without restricted
      information.
- [ ] Understands that participation does not authorize the researcher to access
      any system.

- Eligibility decision (eligible/ineligible):
- Generalized reason if ineligible:

Stop here if any required eligibility condition is not met.

## Consent record

- Protocol and consent version presented:
- Consent method (verbal, written, or approved electronic method):
- [ ] Purpose, format, duration, use of aggregate results, and confidentiality
      limits explained.
- [ ] Voluntary participation, question skipping, pausing, and stopping rights
      explained.
- [ ] Participant controls all tools and screens; researcher receives no access
      or credentials.
- [ ] Notes-only default explained and accepted.
- [ ] Public repository receives only deidentified aggregate paraphrases; no
      completed notes or raw quotations.
- [ ] Withdrawal cutoff stated: `YYYY-MM-DD`.
- [ ] Storage location and deletion deadline explained.
- [ ] Participant consented to the interview and observation.

Optional recording choices; leave unchecked unless the participant explicitly
opts in and organizational policy permits it:

- [ ] Audio recording permitted.
- [ ] Screen recording permitted.
- [ ] Video recording permitted.
- [ ] Automated transcription permitted using this approved service:

If no optional box is checked, make no recording.

## Context interview

Capture paraphrased answers, marking each as participant report rather than
observation.

1. What work do you own, and where do coding agents fit into it?
2. Which local and remote tools are involved in a typical development task?
3. What device, network, certificate, identity, or sandbox controls shape the
   workflow?
4. Where does context get lost across agents, sessions, tools, or handoffs?
5. What evidence do you need before trusting a diagnosis or completed action?
6. Which effects require approval, and who is allowed to approve them?
7. Describe a recent failure, delay, or repeated step that is representative but
   safe to discuss.

## Observation setup

- Workflow category: [ ] CI diagnosis [ ] approval-heavy task [ ] both [ ] other
- Mode: [ ] live direct observation [ ] participant-driven replay of a recent
  real case (supplemental only)
- [ ] Participant confirmed the workflow and artifacts are real, permitted, and
      sanitized.
- Task trigger and desired outcome:
- Starting state:
- Expected proof of success or useful diagnosis:
- Privacy preflight completed (notifications hidden, restricted tabs closed,
  sensitive values masked):
- Researcher reminder: ask the participant to think aloud about choices and
  information needs; do not direct the task or teach a preferred workflow.

A participant-driven replay may add supplemental context, but it cannot satisfy
either required direct-observation gate. The required CI diagnosis and
approval-heavy workflows must each be observed live. For a replay, leave the
gate checkboxes below unchecked and label its evidence as participant-reported
or supplemental rather than observed.

## Think-aloud workflow record

Use one row per meaningful transition. Paraphrase; never paste raw commands,
logs, tickets, URLs, source, screen text, or quotations.

| Step | Participant action or decision | Tool or context | Handoff | Wait, retry, or failure | Evidence used or produced | Authority or approval boundary | Observed outcome |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 |  |  |  |  |  |  |  |

### CI diagnosis coverage (live direct observation only)

- [ ] Located a real failing or previously failed run.
- [ ] Navigated from failure signal to relevant job or step.
- [ ] Selected diagnostic evidence and rejected noise.
- [ ] Formed or revised a diagnosis.
- [ ] Identified exact evidence needed to support the diagnosis.
- [ ] Reached a verified, unresolved, or blocked outcome.

Notes on missing coverage:

### Approval-heavy workflow coverage (live direct observation only)

- [ ] Identified the requested effect and why approval was required.
- [ ] Located the policy or authority boundary.
- [ ] Saw what information the approver received before deciding.
- [ ] Observed waiting, denial, expiry, escalation, or approval.
- [ ] Observed the effect or the reason it could not occur.
- [ ] Located verification or audit evidence after the decision.

Notes on missing coverage:

## Workflow outcome

- Solved:
- Changed:
- Verified:
- Unresolved:
- Blocked:
- Exact evidence type the participant trusted (describe, do not copy):
- Context or work likely to be lost before the next session:
- Manual repetition or avoidable tool switching:
- Observation versus participant explanation discrepancies:

## Product decision questions

1. Under what conditions, if any, would you accept a per-user local PAM daemon?
   Consider installation, resource use, updates, visibility, and control.
2. What audit material may PAM retain, at what detail, where, and for how long?
   What must be redacted, exported, or deletable?
3. Does company policy permit local model weights and inference? What approvals,
   storage rules, data boundaries, or hardware limits apply?
4. If the primary control surface emphasized one area, which should come first:
   queues, flows, or access policy? Rank them and explain the tradeoff.

Record paraphrased answer, conditions, confidence, and counterexample for each.

## Debrief and redaction

- What part of the workflow was most costly, risky, or difficult to verify?
- What did the observer misunderstand or miss?
- What should a useful tool preserve for the next developer or agent?
- [ ] Participant reviewed the session's broad summary.
- [ ] Participant identified material to redact or omit.
- [ ] Accidental restricted disclosures were removed; record only
      `restricted content omitted` where analytically necessary.
- [ ] Reported statements are distinguishable from directly observed behavior.
- [ ] No raw quotations, identifying details, or sensitive artifacts will enter
      git.
- [ ] Withdrawal cutoff reconfirmed.
- [ ] Raw-material deletion deadline recorded and no later than 30 days after
      synthesis finalization.

## Private synthesis handoff

- Deidentified evidence statements supported by this session:
- Counterevidence or contradictions:
- Workflow-map transitions contributed:
- Product assumptions validated, weakened, or left unknown:
- Follow-up permitted before withdrawal cutoff: [ ] yes [ ] no
