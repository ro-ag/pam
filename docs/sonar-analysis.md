# Exact Sonar analysis evidence

Use an explicit compute-engine task ID to retrieve a historical analysis. PAM
never substitutes the project's current gate for the requested analysis.

```sh
pam flow run sonar-analysis-evidence project=service ce_task=TASK_ID page=1 --json
```

This main-branch discovery flow observes the result. For revision verification,
configure a repository mapping under Sonar in GUI Settings, then use:

```sh
pam flow run revision-sonar-check project=service ce_task=TASK_ID branch=main repository=https://git.example/team/service.git commit=FULL_COMMIT page=1 --json
```

The mapping joins the configured Sonar server and exact project key to an HTTPS
repository URL. It is separate from connector access permissions: both are
required. Agents cannot create mappings through CLI or public IPC. Saves use a
version check so stale GUI forms cannot overwrite newer mappings. Server paths
are significant; changing a connector server does not transfer its mappings.

PAM freezes the mapping revision when the flow starts and checks it again after
collection, before publishing associated evidence. A changed mapping requires a
new request. Missing mappings do not prevent reading an already-authorized
historical gate, but they prevent revision verification.
Mapping validity is also checked before the final verdict. Durable results
describe the mapping snapshot at execution time; later correction does not
rewrite history. Retrieving historical evidence still requires current scope.

## Evidence chain and limits

PAM checks the exact compute task, project and requested selector. Pending,
running, failed and canceled compute tasks remain distinct. A successful task
must identify its analysis. PAM requests the gate by that analysis ID and joins
that exact ID to a bounded page of project analysis history to obtain the
reported revision. Page position, timestamps and latest-project status are
never identity evidence. If the analysis is absent from the selected page,
choose another explicit page; absence does not mean the gate passed.

Deployment capabilities are checked before using branch parameters. Pull-request
revision association remains unresolved where the history API has no supported
PR selector. No repository URL is inferred from project names or hostile logs.
Sonar revisions are scanner-reported: `sonar.scm.revision` can override them.
This is product-reported provenance, not attestation of the analyzed bytes.

Historical conditions retain metric, status, comparator, values and thresholds,
plus new-code period and ignored-condition information. `cayc_status_current`
is labeled separately because it reflects current configuration. Unknown or
missing gate information never becomes a passing gate. Full conditions remain
in retained evidence; compact summaries report omitted conditions explicitly.

The bounded operation performs at most four requests: capabilities, compute
status, one history page and the exact gate. History decoding is capped at 100
entries; unsupported, incomplete or oversized responses expose limitations.
Existing per-response, cumulative request/byte, scope and deadline checks apply.
No local model is needed for retrieval, association or gate comparison.

Implementation tasks: #131 exact analysis, #133 durable reconciliation. A watch
must distinguish compute progress from immutable completed analysis identity;
it must not blindly replay a changed association after restart.

Sources: [compute schema](https://github.com/SonarSource/sonarqube/blob/master/sonar-ws/src/main/protobuf/ws-ce.proto),
[historical gate implementation](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/qualitygate/ws/ProjectStatusAction.java),
[analysis history contract](https://github.com/SonarSource/sonarqube/blob/master/server/sonar-webserver-webapi/src/main/java/org/sonar/server/projectanalysis/ws/SearchAction.java),
[scanner analysis parameters](https://docs.sonarsource.com/sonarqube-server/9.9/analyzing-source-code/analysis-parameters).
