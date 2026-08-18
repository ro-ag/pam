# Participant consent and privacy protocol

This protocol applies to PAM interviews and workflow observations with
developers in company-managed environments. It does not replace an employer's
research, security, legal, or confidentiality requirements. A session proceeds
only when both the participant and their organization permit it.

## Study administration

Complete every field before recruitment:

- Responsible researcher: `UNRESOLVED`
- Study contact and withdrawal-request channel: `UNRESOLVED`
- Protocol and consent version: `UNRESOLVED`
- Effective date: `UNRESOLVED`
- Withdrawal cutoff rule: `UNRESOLVED` — define how the dated cutoff is
  calculated and communicated; it must not be later than incorporation into the
  finalized aggregate synthesis.

Recruitment must not start while any field remains unresolved. The participant
must receive the resolved study contact, protocol and consent version, effective
date, and dated withdrawal cutoff before consenting.

## Eligibility

A participant must:

- be an adult professional developer who regularly works in a company-managed
  development environment;
- use at least one organization-controlled source-control, CI, ticketing,
  documentation, quality, access, or deployment system;
- currently use a coding agent for work or be able to explain how employer
  policy prevents its use;
- be able to consent voluntarily without a manager present or exerting pressure;
- confirm that the proposed discussion and demonstration are permitted by their
  employer; and
- be able to discuss or demonstrate a sanitized real workflow without exposing
  restricted information.

The researcher screens for eligibility before scheduling. Eligibility never
authorizes access to an employer's systems or information.

## Voluntary consent

Before the session, the researcher explains the study purpose, session format,
expected duration, privacy protections, foreseeable confidentiality risks, and
how the results will be used. Participation is voluntary. The participant may
skip any question, pause the observation, hide any screen, or end the session
without giving a reason or incurring a penalty.

Consent to participate is distinct from consent to record. The researcher
records the participant's consent choice in the private session record before
collecting research data.

## Participant-controlled observation

The participant chooses a permitted, sanitized task and remains in control of
the keyboard, screen, accounts, and tools. The researcher observes and asks
questions but does not request credentials, operate the environment, approve an
effect, or ask the participant to bypass policy or obtain new access.

The participant should stop sharing before opening any restricted artifact.
The session pauses immediately if either person notices sensitive material.
Finishing a workflow is less important than respecting the participant's
security boundary.

## Confidentiality limits

Do not show, dictate, copy, or retain:

- passwords, tokens, keys, cookies, certificates, or other secrets;
- customer, employee, incident, or regulated data;
- proprietary source code, internal documentation, or unreleased designs;
- raw build logs, ticket bodies, repository URLs, hostnames, account names, or
  other organization-identifying details; or
- information whose disclosure is prohibited by policy, contract, or law.

The researcher captures workflow structure, decisions, delays, handoffs,
authority boundaries, and outcomes rather than sensitive content. If restricted
information is exposed accidentally, stop the session, remove it from notes and
recordings, and retain only the statement `restricted content omitted` when the
omission is analytically relevant.

Confidentiality cannot be guaranteed for information the participant chooses to
disclose outside this protocol. The PAM repository is public: it receives only
deidentified aggregate findings and paraphrases, never completed session notes,
participant identities, employer identities, or raw quotations.

## Notes and optional recording

Structured notes are the default and are identified only by a pseudonymous
session code such as `P01`. Audio, video, screen capture, or automated
transcription is off by default. Each recording mode requires a separate,
explicit opt-in; declining recording does not prevent participation.

Recordings and transcripts must not be sent to an external transcription,
analytics, or AI service without separate written participant consent and any
required organizational approval. Raw quotations are not committed to git,
even when recording was permitted.

## Withdrawal, redaction, and review

Before the session, the researcher states a dated withdrawal cutoff. The
default cutoff is the date the participant's deidentified findings are folded
into the finalized aggregate synthesis. Until that cutoff, the participant may
request withdrawal; the researcher then deletes their raw materials and removes
their evidence from the synthesis. After aggregation, a contribution may no
longer be separable, and the researcher explains that limit during consent.

Before synthesis, replace names and precise organizational details with broad
categories, remove accidental disclosures, and keep the identity-to-session
mapping separate from the research notes. At debrief, invite the participant to
identify anything else that should be redacted. When practical, offer them the
deidentified session summary for correction before the cutoff.

## Storage and deletion

Completed notes, consent records, recordings, transcripts, contact details, and
identity mappings stay outside the repository in an organization-approved,
encrypted research location with access limited to the study team. Contact
details and identity mappings are stored separately from session content. Do
not place raw research material in the checkout, an unapproved cloud service,
or a private connector merely because it is convenient.

Delete recordings, transcripts, consent-linked notes, identity mappings, and
other raw session material no later than 30 days after the aggregate synthesis
is finalized. Apply an earlier deletion deadline when the participant withdraws
or organizational policy requires one. Deidentified aggregate findings may
remain in the public repository.
