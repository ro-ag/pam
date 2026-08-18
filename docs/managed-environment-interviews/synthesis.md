# Managed-environment research synthesis

Status: **recruitment not started**

Last public-source review: 2026-08-18

This is a public-safe living report for research about professional developer
workflows involving coding agents in company-managed desktop environments. The
planned cohort is five to eight eligible managed-environment developers,
including at least three who work on managed macOS, with cross-platform
exposure and shortfalls documented. It currently contains only public signals
and study templates. It contains no participant, session, or company evidence.

## Evidence boundary

The current evidence base is limited to public issue reports, public community
discussions, and authoritative vendor documentation. Public reports show that a
person encountered or described a problem; they do not establish prevalence,
causality, or the experience of PAM's target population. Vendor documentation
establishes supported platform behavior, not that users experience a problem.

This report uses three evidence classes:

- **Reported observation:** a public author describes their own environment or
  an incident they investigated.
- **Documented capability:** an authoritative vendor describes supported
  behavior, requirements, or restrictions.
- **Product inference:** a hypothesis for PAM derived from one or both of the
  above. It remains unvalidated until participant evidence supports it.

Nothing in this report is an interview result. No public post is treated as an
interview, participant, or independent observation session. Qualitative
frequency below means recurrence within this bounded source set only; it is not
a population estimate.

## Ranked public signals

| Rank | Public signal | Severity | Recurrence in source set | Confidence | Direct evidence | Provisional PAM inference |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | Agent work can become invisible or impossible to resume across restarts and authentication events. | Critical | Recurrent | High | [S1], [S2] | Keep an authoritative project ledger and running/waiting/stopped state outside any agent UI or provider session. |
| 2 | Corporate proxy and certificate trust differs across the macOS Keychain and tool-specific runtimes. | Critical | Recurrent across tools | High | [S3], [S4] | Diagnose PAC, proxy, VPN, Keychain, and runtime trust stores without recommending disabled TLS verification. |
| 3 | Identity is a chain of local password, FileVault, IdP, VPN, token, and offline state rather than one login. | Critical | Recurrent | High | [S5], [S6] | Model authentication prerequisites, freshness, offline behavior, and repair paths explicitly. |
| 4 | Standard-user fleets turn helper tools and integrations into repeated or misplaced approval prompts. | High | Recurrent | High | [S7], [S8] | Broker narrowly scoped, time-bounded capabilities and retain approval receipts instead of relying on blanket elevation. |
| 5 | Device management can make an otherwise valid workflow unavailable by policy. | High | Documented capability | High | [S9] | Detect managed posture before proposing an action and distinguish policy denial from a product defect. |
| 6 | VPN or a general developer portal does not automatically solve internal-tool identity and workflow fit. | High | Multiple public examples | Medium-high | [S10], [S11] | Provide project-specific capability discovery and preflight rather than becoming another generic portal. |
| 7 | Visible activity and agent-authored summaries can omit the causal record needed to prove an outcome. | High | Emerging | High | [S12] | Capture tool inputs, approvals, outputs, verification, and source handles mechanically; report changed, verified, unresolved, and blocked separately. |

Severity is a product-risk judgment. Confidence reflects source specificity and
triangulation, not user-population certainty. All provisional PAM inferences
must be tested against counterevidence in the planned sessions.

## Source map

| ID | Kind | What the source directly supports |
| --- | --- | --- |
| [S1] | First-person GitHub issue | Codex on macOS can show stale or invisible active-turn state, failed cancellation, missing traces after restart, and duplicate recovery attempts: [openai/codex #24287](https://github.com/openai/codex/issues/24287). |
| [S2] | First-person GitHub issue | A ChatGPT Enterprise user on macOS reported that every existing and new Codex task failed to resume after reinstall and OAuth reauthentication: [openai/codex #14396](https://github.com/openai/codex/issues/14396). |
| [S3] | First-person GitHub issue | Copilot CLI failed behind corporate SSL inspection although the corporate CA was installed in the macOS System keychain because the runtime used another trust source: [github/copilot-cli #333](https://github.com/github/copilot-cli/issues/333). |
| [S4] | Public administrator discussion | Mac administrators describe configuring curl, Python, Node.js, Java, and other tools separately when applications do not use the system trust store: [r/macsysadmin](https://www.reddit.com/r/macsysadmin/comments/1h1swof/managing_system_certificates/). |
| [S5] | First-person administrator discussion | A managed-Mac deployment report describes Duo being unreachable at FileVault preboot and local credentials not following changed directory credentials after VPN connection: [r/macsysadmin](https://www.reddit.com/r/macsysadmin/comments/1rpzgzu/is_this_possible_where_to_start_fv_duo_mdm_ad/). |
| [S6] | Authoritative vendor documentation | Platform SSO behavior depends on the IdP extension; required live authentication can prevent offline login unless policy provides a grace period: [Apple Platform Deployment](https://support.apple.com/guide/deployment/platform-sso-for-macos-dep7bbb05313/web). |
| [S7] | First-person administrator discussion | Intune-installed Mac apps owned by root can later prompt standard users for administrator access to install or update helper tools: [r/sysadmin](https://www.reddit.com/r/sysadmin/comments/1ry1mqt/intune_mdm_app_deployment_for_macos_vs_helper/). |
| [S8] | First-person GitHub issue | One Xcode MCP integration prompted for tool access whenever Codex regained focus: [openai/codex #12108](https://github.com/openai/codex/issues/12108). |
| [S9] | Authoritative vendor documentation | Supervised device management can restrict apps and services, including Xcode coding-assistant external integrations: [Apple device-management restrictions](https://support.apple.com/guide/deployment/review-device-management-restrictions-dep739685973/web). |
| [S10] | First-person Stack Overflow question | SAML identity used for AWS Client VPN was not available to the internal application, raising the prospect of another sign-in: [Stack Overflow](https://stackoverflow.com/questions/70230093/how-to-get-clients-identity-in-an-app-running-in-vpc-accessed-via-awss-client). |
| [S11] | Public developer discussion | Experienced developers caution that an all-in-one internal developer portal is not itself evidence of productivity improvement and recommend solving specific existing workflows: [r/ExperiencedDevs](https://www.reddit.com/r/ExperiencedDevs/comments/1e5meor/promoted_in_charge_of_implementing_an_internal/). |
| [S12] | First-person GitHub issue | A Codex multi-agent report describes observable subagent results but missing exact dispatched instructions and follow-ups, leaving an incomplete causal record: [openai/codex #32753](https://github.com/openai/codex/issues/32753). |

## Opportunity map

These are hypotheses to test, not committed features.

### This week

- Test whether a provider-independent checkpoint can reconstruct goal,
  decisions, active work, blockers, and last verification after an agent
  restart.
- Define a read-only managed-environment preflight for proxy, VPN, identity,
  certificate, and policy state; verify that its report is useful and safe to
  share.
- Prototype one approval receipt that identifies caller, project, capability,
  resource, duration, decision, use, and expiry.
- Prepare the screener, consent language, and observation script required to
  recruit five to eight eligible managed-environment developers, including at
  least three on managed macOS, and document their cross-platform exposure and
  shortfalls.

### This quarter

- Compare trust diagnosis across macOS Keychain, Git, Node.js, Python, Java,
  Rust, container runtimes, and one corporate VPN or network agent.
- Test a project-scoped internal-capability catalog containing owner,
  connector, network and authentication prerequisites, and a tested support
  path.
- Measure approval prompts per completed outcome and whether grouping prompts
  at meaningful boundaries preserves user control.
- Validate the mechanical outcome record against developer, platform, and
  security review needs.

### Deeper research

- Compare MDM, endpoint-privilege-management, IdP, VPN, and certificate
  combinations without assuming one company's configuration is typical.
- Determine acceptable local retention, redaction, export, and deletion rules
  for agent evidence in regulated and non-regulated organizations.
- Test whether platform and security teams will approve a local daemon, local
  model use, and narrowly brokered corporate connectors.
- Study handoffs across developers, agents, help desk, platform engineering,
  and security when an operation remains blocked.

## Aggregate cohort and evidence

Eligibility requires that every participant meets all of these criteria:

- is an adult professional developer;
- currently works in a company-managed environment;
- can demonstrate a workflow involving at least one corporate tool or system;
- uses a coding agent in that workflow or is blocked from doing so by company
  policy;
- has employer permission to participate; and
- can present a sanitized workflow without exposing secrets, customer data, or
  confidential company information.

The cohort must contain five to eight eligible developers, at least three using
managed macOS. For every eligible participant, record experience with other
managed desktop platforms and the shortfalls they encountered, then report
only aggregate platform totals and themes here.

No recruitment or sessions have occurred. Current exact counts are therefore
zero.

### Cohort accounting

| Aggregate measure | Completion requirement | Current exact count |
| --- | --- | ---: |
| Recruited people | Report every recruited person | 0 |
| Eligible managed-environment developers completed | 5–8 | 0 |
| Eligible developers completed on managed macOS | At least 3 | 0 |
| Eligible developers completed on other managed desktop platforms | Report exact platform totals | 0 |
| Eligible developers with cross-platform exposure documented | Report for every eligible completion | 0 |
| Excluded people | Report every exclusion | 0 |
| Withdrawn people | Report every withdrawal | 0 |

### Aggregate evidence accounting

| Public signal | Directly observed support | Directly observed counterexample | Self-reported support | Self-reported counterexample | Study status |
| --- | ---: | ---: | ---: | ---: | --- |
| Continuity and resume failure | 0 | 0 | 0 | 0 | Not tested |
| Proxy and certificate trust fragmentation | 0 | 0 | 0 | 0 | Not tested |
| Identity-chain and offline-access failure | 0 | 0 | 0 | 0 | Not tested |
| Least-privilege approval friction | 0 | 0 | 0 | 0 | Not tested |
| Device-policy capability denial | 0 | 0 | 0 | 0 | Not tested |
| Internal-tool identity and workflow mismatch | 0 | 0 | 0 | 0 | Not tested |
| Incomplete causal or outcome record | 0 | 0 | 0 | 0 | Not tested |

Session-level matrices, profiles, notes, and evidence references remain private
and are stored outside this checkout. This public file contains aggregate
counts and non-identifying themes only. Never publish participant names,
employers, internal hostnames, repository names, secrets, customer data, or
confidential configuration here.

Operating-system versions, organization size, management-product families,
participant role, session setting, and rare intersections of cohort attributes
are private-only research fields. The public report may include only coarse
marginal totals that pass re-identification review; it must not publish
cross-tabulations or combinations that could single out a participant or
organization.

## As-is workflow-map templates

Fill these from direct observation. Preserve the participant's current process;
do not insert a PAM step into an as-is map.

A replay may supplement notes from a live observation, but it cannot satisfy
the live-observation requirement for either the real CI-diagnosis gate or the
approval- or network-gated-operation gate.

### Template A: diagnose a real CI failure

| Stage | Trigger or goal | Person or system | Exact action | Evidence available at that moment | Wait, failure, or repeated work | Handoff | Duration | Observed or self-reported | Counterexample or alternate path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Notice the failed check |  |  |  |  |  |  |  |  |  |
| Locate CI run and failure evidence |  |  |  |  |  |  |  |  |  |
| Establish access to required logs or tools |  |  |  |  |  |  |  |  |  |
| Reproduce or narrow the failure |  |  |  |  |  |  |  |  |  |
| Form and test a diagnosis |  |  |  |  |  |  |  |  |  |
| Apply or recommend the bounded fix |  |  |  |  |  |  |  |  |  |
| Verify with the relevant CI path |  |  |  |  |  |  |  |  |  |
| Record or hand off the result |  |  |  |  |  |  |  |  |  |

### Template B: complete an approval- or network-gated operation

| Stage | Trigger or goal | Person or system | Exact action | Evidence available at that moment | Wait, failure, or repeated work | Handoff | Duration | Observed or self-reported | Counterexample or alternate path |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Start operation |  |  |  |  |  |  |  |  |  |
| Establish network and identity |  |  |  |  |  |  |  |  |  |
| Request or obtain authority |  |  |  |  |  |  |  |  |  |
| Use the internal tool |  |  |  |  |  |  |  |  |  |
| Diagnose a denial or failure |  |  |  |  |  |  |  |  |  |
| Verify the outcome |  |  |  |  |  |  |  |  |  |
| Record or hand off the result |  |  |  |  |  |  |  |  |  |

## Evidence-quality requirements

### Exact counts

- Report the exact number of recruited, completed, excluded, and withdrawn
  participants; never write “several” or silently treat public authors as
  participants.
- In each private session record, count context reconstructions, sign-ins, VPN
  reconnects, certificate failures, approval prompts, tickets or human
  handoffs, repeated commands, verification events, and minutes spent waiting.
  Publish only aggregate integers, `0`, or `not observed`; do not substitute
  “often” or expose a re-identifying profile.
- Count confirming and disconfirming sessions separately for every ranked
  signal. Do not count multiple comments by one identifiable author as
  independent people.

### Counterevidence

- Ask how the workflow succeeds today, which controls are valuable, and when
  the reported problem does not occur.
- Record alternate explanations, configuration-specific causes, workarounds
  that are acceptable, and cases where PAM would add risk or another layer of
  friction.
- Preserve contradictory session evidence and revise rank, severity, and
  confidence instead of averaging it away.

### Limitations

- Separate directly observed behavior, participant recall, researcher
  interpretation, vendor-documented behavior, and product inference.
- Record recruitment channel, role mix, organization-size mix, device and OS
  versions, MDM/EPM/IdP/VPN families, session setting, missing artifacts, and
  researcher involvement in private research records only. Publish at most
  coarse marginal totals that pass re-identification review; keep roles,
  versions, management-product families, session settings, and rare
  intersections private.
- Treat public issue trackers and forums as failure-skewed discovery sources.
  Do not infer market size or prevalence from this report.
- Publish only redacted evidence that participants and their organizations are
  permitted to share.

## Completion gate

This study is not complete until all of the following are true:

- The report states an exact completed cohort of five to eight eligible
  managed-environment developers, including at least three on managed macOS.
- Cross-platform exposure and shortfalls are documented for every eligible
  participant and summarized only as aggregate platform totals and themes.
- At least one real CI diagnosis and one approval-heavy task have been observed
  live. A replay is supplemental evidence and cannot satisfy either gate.
- The public aggregate cohort and evidence tables contain exact counts that
  reconcile with the private session records, including recruitment,
  completion, exclusion, withdrawal, supporting evidence, and counterevidence.
- Both as-is workflow maps have been populated from observation and reviewed
  for researcher-added assumptions.
- Every ranked signal has confirming evidence, counterevidence, or an explicit
  “not tested” label, with severity and confidence recalculated from the study.
- Findings state limitations, identify configuration-specific results, and do
  not claim population prevalence from a small purposive sample.
- Product opportunities are supported by reviewed private session evidence and
  public aggregate counts rather than public anecdotes alone.
- A final public-safety review confirms that no participant, employer, internal
  system, credential, or confidential configuration can be identified.
- Session-level matrices and evidence references remain private outside this
  checkout; only non-identifying aggregate results appear in this report.

Until this gate is met, the status must remain **recruitment not started** or
**research in progress**, and every product conclusion remains provisional.

[S1]: https://github.com/openai/codex/issues/24287
[S2]: https://github.com/openai/codex/issues/14396
[S3]: https://github.com/github/copilot-cli/issues/333
[S4]: https://www.reddit.com/r/macsysadmin/comments/1h1swof/managing_system_certificates/
[S5]: https://www.reddit.com/r/macsysadmin/comments/1rpzgzu/is_this_possible_where_to_start_fv_duo_mdm_ad/
[S6]: https://support.apple.com/guide/deployment/platform-sso-for-macos-dep7bbb05313/web
[S7]: https://www.reddit.com/r/sysadmin/comments/1ry1mqt/intune_mdm_app_deployment_for_macos_vs_helper/
[S8]: https://github.com/openai/codex/issues/12108
[S9]: https://support.apple.com/guide/deployment/review-device-management-restrictions-dep739685973/web
[S10]: https://stackoverflow.com/questions/70230093/how-to-get-clients-identity-in-an-app-running-in-vpc-accessed-via-awss-client
[S11]: https://www.reddit.com/r/ExperiencedDevs/comments/1e5meor/promoted_in_charge_of_implementing_an_internal/
[S12]: https://github.com/openai/codex/issues/32753
