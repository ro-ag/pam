# Enterprise connector contracts

This is the current bounded adapter contract, tracked by ptrack #128. Contract fixtures establish request construction, parsing, limits, and refusal behavior. They do **not** establish live compatibility with a company's installation. No live enterprise credentials were used during this implementation.

## Deployment matrix

| Product | Configured base and authentication | Supported reads | Boundaries and unqualified variants |
| --- | --- | --- | --- |
| Jira Data Center | Installation base, including any context path; bearer personal access token from OS keychain | REST v2 search, issue detail, current-user verification | First search page only, at most 100 issues. Missing/inconsistent totals mean partial. Description text is bounded to 16 KiB. Jira Cloud and alternate auth modes are not this contract. |
| Confluence Cloud | Site wiki base, e.g. `https://company.atlassian.net/wiki/`; account email plus API token from OS keychain | v1 CQL content search/current-user verification; v2 page with storage body | Page IDs must match. Missing storage body is an error; body truncation is explicit at 64 KiB. `space_id` is an ID, not a space key. Data Center and OAuth/scoped-token gateway variants need separate qualification. |
| SharePoint 365 | Microsoft Graph v1.0 root, e.g. `https://graph.microsoft.com/v1.0/`; bearer Graph token from OS keychain | Site default-drive search and list metadata, root-site verification | First page, at most 100 entries; nextLink/full page marked partial. No arbitrary document download, non-default drive selection, or continuation following. Token acquisition/refresh and sovereign deployments are not live-qualified. |
| Jenkins | Installation base including context path; username plus API token from OS keychain | Top-level jobs, job builds, exact numeric build console and Pipeline investigation | Listing arrays are capped locally, full pages marked partial. Job listing is not recursive. Pipeline REST availability is confirmed by the user; exact stage/node evidence uses that API with honest missing-data limits. No script console or build-trigger operations. |
| GitHub | REST base (`https://api.github.com/`, or qualified Enterprise API base); bearer token from OS keychain | Workflow runs, exact run attempt/jobs, exact job log, user verification | Jobs pagination is attempt-bound, capped at 100 per call; incomplete pages cannot establish overall success. Hosted/Enterprise version variants need named smoke results. REST is the active connector backend; authenticated `gh` is not an automatic fallback. |
| SonarQube | Installation base; token as Basic username with empty password from OS keychain | Project gate, unresolved issues, credential verification | Branch and PR selectors are mutually exclusive. Gate evidence is latest/request-bound until exact-analysis correlation is implemented. Issue filtering requires an advertised supported project-filter contract and matching returned project identities. Editions lacking requested selectors refuse rather than silently switch to main. |

Jira's REST v2 search is a Data Center contract with bounded pages. See the [official search reference](https://developer.atlassian.com/server/jira/platform/rest/v10000/api-group-search/).

Graph's drive search uses the selected site's default drive and supports paged results. The endpoint does **not** support the `Sites.Selected` application permission; do not advertise that permission mode or silently broaden tenant grants. Root-site verification can also fail for a token that only accesses another selected resource. See [Microsoft Graph drive search](https://learn.microsoft.com/en-us/graph/api/driveitem-search?view=graph-rest-1.0).

Jenkins exposes resource-specific remote APIs; PAM uses bounded read endpoints rather than an unrestricted API proxy. See [Jenkins Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/).

## Authority and transport

GUI administration grants exact repository/product scopes. Every operation rechecks those scopes, current configuration, expiry, and cumulative request budgets. A successful credential probe does not grant access to another target or prove a deployment's full compatibility.

HTTP requests use the [trusted OS transport](command-containment.md). Redirects, oversized responses, HTTP authentication failures, rate limits, and timeouts remain errors or explicit incomplete outcomes. Paging does not reset budgets. Returned continuation URLs are not authority to fetch arbitrary locations. No connector can mint grants or bypass OS-keychain storage.

The core does not invoke a vendor agent CLI or hosted model to troubleshoot. Local Git commands run under mandatory containment. Remote Git/gh operations, push, merge, and artifact-writing validation require the separately scoped landing work in #135. AWS CLI is currently refused before credential/process access; JFrog publishing is unsupported. Neither is silently substituted for one of the six required adapters.

## Live qualification procedure

Use an installation-specific record containing product/version/edition, base URL class, authentication mode, approved target, date, PAM commit, and redacted evidence IDs. Configure the target and credentials through the GUI. Run a read-only credential probe and a bounded known-target flow, then verify the returned identity and decisive fields against that exact target. Exercise expiry/denial and a partial result without broadening access. Record each operation as passed, failed, or not run; a product-wide green badge is insufficient.

Do not place tokens in shell arguments or fixture files. No live smoke should create tickets, modify pages, trigger jobs, push, merge, or publish. The current fixture results remain distinct from these future installation-specific records.
