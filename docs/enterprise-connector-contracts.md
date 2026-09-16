# Enterprise connector contracts

This is the current bounded adapter contract, tracked by ptrack #128–132. Contract fixtures establish request construction, parsing, limits, and refusal behavior. They do **not** establish live compatibility with a company's installation. No live enterprise credentials were used during this implementation.

See [exact Sonar analysis](sonar-analysis.md), [Jenkins evidence](jenkins-investigation.md) and [cited document context](enterprise-context.md) for execution details.

## Deployment matrix

| Product | Configured base and authentication | Supported reads | Boundaries and unqualified variants |
| --- | --- | --- | --- |
| Jira Data Center | Installation base, including any context path; bearer personal access token from OS keychain | REST v2 search, issue detail, current-user verification | First search page only, at most 100 issues. Missing/inconsistent totals mean partial. Description text is bounded to 16 KiB. Jira Cloud and alternate auth modes are not this contract. |
| Confluence Cloud | Site wiki base, e.g. `https://company.atlassian.net/wiki/`; account email plus API token from OS keychain | v1 CQL content search/current-user verification; v2 page with storage body | Page IDs must match. Missing storage body is an error; body truncation is explicit at 64 KiB. `space_id` is an ID, not a space key. Data Center and OAuth/scoped-token gateway variants need separate qualification. |
| SharePoint 365 | Microsoft Graph v1.0 root, e.g. `https://graph.microsoft.com/v1.0/`; bearer Graph token from OS keychain | Site default-drive search, list metadata, explicit bounded text document reads, root-site verification | First page, at most 100 entries; nextLink/full page marked partial. Explicit drive selection requires site membership; text is capped at 64 KiB with exact-host download and metadata recheck. No Office/PDF parsing or arbitrary continuation following. Token acquisition/refresh and sovereign deployments are not live-qualified. |
| Jenkins | Installation base including context path; username plus API token from OS keychain | Top-level jobs, job builds, exact numeric build console and Pipeline investigation | Listing arrays are capped locally, full pages marked partial. Job listing is not recursive. Pipeline REST availability is confirmed by the user; exact stage/node evidence uses that API with honest missing-data limits. No script console or build-trigger operations. |
| GitHub | REST base (`https://api.github.com/`, or qualified Enterprise API base); bearer token from OS keychain | Workflow runs, exact run attempt/jobs, exact job log, user verification | Jobs pagination is attempt-bound, capped at 100 per call; incomplete pages cannot establish overall success. Hosted/Enterprise version variants need named smoke results. REST is the active connector backend; authenticated `gh` is not an automatic fallback. |
| SonarQube | Installation base; token as Basic username with empty password from OS keychain | Live project gate, exact CE/analysis gate and revision history, unresolved issues, credential verification | Branch and PR selectors are mutually exclusive. Live gates remain request-bound; exact analysis joins require CE identity, history revision and a GUI-owned repository mapping. PR history cannot establish revision with the current API. Issue filtering requires an advertised supported project-filter contract and matching returned project identities. Editions lacking requested selectors refuse rather than silently switch to main. |

Jira's REST v2 search is a Data Center contract with bounded pages. See the [official search reference](https://developer.atlassian.com/server/jira/platform/rest/v10000/api-group-search/).

Graph's drive search uses the selected site's default drive and supports paged results. The endpoint does **not** support the `Sites.Selected` application permission; do not advertise that permission mode or silently broaden tenant grants. Root-site verification can also fail for a token that only accesses another selected resource. See [Microsoft Graph drive search](https://learn.microsoft.com/en-us/graph/api/driveitem-search?view=graph-rest-1.0).

Jenkins exposes resource-specific remote APIs; PAM uses bounded read endpoints rather than an unrestricted API proxy. See [Jenkins Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/).

Confluence's page contract follows the [Cloud v2 page API](https://developer.atlassian.com/cloud/confluence/rest/v2/api-group-page/); CQL search remains a separate v1 operation. GitHub jobs use [attempt-specific endpoints](https://docs.github.com/en/rest/actions/workflow-jobs#list-jobs-for-a-workflow-run-attempt), with later pages requiring the caller to retain the attempt number.

Sonar issue reads first consult `/api/webservices/list` and require the advertised `components`, `resolved`, and `ps` parameters (plus any selected branch/PR parameter). This qualifies the 10.2+ project-filter contract rather than guessing an older parameter. Metadata stays under the normal 1 MiB JSON limit; oversized/unknown metadata refuses. Selected gate reads similarly check parameter support. This adds one bounded HTTP request to those operations. The implementation follows Sonar's [issue SearchAction](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/issue/ws/SearchAction.java) and [ProjectStatusAction](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/qualitygate/ws/ProjectStatusAction.java).

## Authority and transport

GUI administration grants exact repository/product scopes. Every operation rechecks those scopes, current configuration, expiry, and cumulative request budgets. A successful credential probe does not grant access to another target or prove a deployment's full compatibility.

HTTP requests use the [trusted OS transport](command-containment.md). Redirects, oversized responses, HTTP authentication failures, rate limits, and timeouts remain errors or explicit incomplete outcomes. Paging does not reset budgets. Returned continuation URLs are not authority to fetch arbitrary locations. No connector can mint grants or bypass OS-keychain storage.

The core does not invoke a vendor agent CLI or hosted model to troubleshoot. Local Git commands run under mandatory containment. [Guarded landing](guarded-landing.md) introduces typed Git push, GitHub PR/merge operations and private validation outputs under separate GUI policy; its full synchronization checkpoint is still pending. Ordinary connector access remains read-only. AWS CLI is currently refused before credential/process access, and a flow that names `connector: aws` is refused at validation with that blocker (`pam_flow::validate::AWS_BLOCKER`) rather than accepted and failed at run time; JFrog publishing is unsupported. Neither is silently substituted for one of the six required adapters.

## Live qualification procedure

Use an installation-specific record containing product/version/edition, base URL class, authentication mode, approved target, date, PAM commit, and redacted evidence IDs. Configure the target and credentials through the GUI. Run a read-only credential probe and a bounded known-target flow, then verify the returned identity and decisive fields against that exact target. Exercise expiry/denial and a partial result without broadening access. Record each operation as passed, failed, or not run; a product-wide green badge is insufficient.

Do not place tokens in shell arguments or fixture files. No live smoke should create tickets, modify pages, trigger jobs, push, merge, or publish. The current fixture results remain distinct from these future installation-specific records.
