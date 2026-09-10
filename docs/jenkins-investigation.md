# Investigate one Jenkins Pipeline build

Configure Jenkins in **Settings → Connectors**, including access to the
Pipeline REST API. Select **Jenkins build investigation** in Flows, or run:

```sh
pam flow run jenkins-build-investigation job=platform/nightly build=41 --json
```

The `jenkins.investigate` connector call takes a job path and explicit positive
build number. It reads core build status, Pipeline stages, stage child-node
observations, and selected node logs through the existing REST adapter. The
starter flow verifies only the core build's `SUCCESS` status; failed, unstable,
aborted, unknown, and running builds do not pass. Evidence is stored through
the existing `connector.result` path even when verification fails. No local
model is required. The raw `console` call remains available unchanged.

The report preserves node IDs, parents, timing, status, error objects, and
exact log excerpts. Failed/error node logs are prioritized, followed by other
statuses and successful nodes, within fixed limits. These are observations:
`FAILED` in wfapi can survive a caught error or successful retry. Successful
post actions cannot erase the failed build; aborted parallel branches and
skipped stages are not automatically the primary failure. Root-cause
attribution remains explicitly unresolved.

Limits: 24 stages, 128 child observations, 16 logs, 40 requests, 256 KiB per
response, 2 MiB aggregate charged response bytes, and 16 KiB retained text per
log. Requests share the step deadline. HTTP denial, missing endpoints, malformed
records, timeouts, and local/server omissions appear in `coverage.gaps` while
the acquired core build result remains intact. Core-status failure itself
fails the connector call. Server graph coverage is always unverified because
wfapi can silently limit child nodes.

The node-log API returns an annotated HTML tail. PAM stores it as untrusted
text, without rendering HTML or following returned links. Excerpt `start` and
exclusive `end` are UTF-8 byte offsets into the decoded API response's `text`
field, **not original console offsets**. `has_more` indicates omitted earlier
server content; local head/tail excerpts expose their omitted middle. The
endpoint and node ID identify each source. A log's reported `length` is kept
separately from its decoded byte count.

API semantics: [Pipeline REST API](https://github.com/jenkinsci/pipeline-stage-view-plugin/tree/master/rest-api),
[stage aggregation](https://github.com/jenkinsci/pipeline-stage-view-plugin/blob/master/rest-api/src/main/java/com/cloudbees/workflow/rest/external/StageNodeExt.java),
[node-log encoding and tail](https://github.com/jenkinsci/pipeline-stage-view-plugin/blob/master/rest-api/src/main/java/com/cloudbees/workflow/rest/external/FlowNodeLogExt.java).
