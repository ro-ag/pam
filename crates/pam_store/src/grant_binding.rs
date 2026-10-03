//! What a flow step's grant is bound to, and the reads and writes that keep
//! it so (migration 17).
//!
//! A `flow.step:<flow>/<step>` grant names a step; the binding says which
//! step it was: the step's effect digest, the gate class it was granted
//! under and the canonical repository the approval was given for. The
//! daemon's gate compares the binding with what is about to run; the store
//! only keeps it. A row without an effect digest is an unbound legacy grant
//! (written before the binding existed, or by a caller that names no step);
//! [`Store::bind_legacy_grant_audited`] binds it on first use.

use rusqlite::params;

use super::{AuditEntry, GrantRow, OwnedAudit, Store, StoreError, now_ts};
use crate::db::{Db, Row};

/// The capability prefix of a flow step's grant. The store knows it only to
/// scope revocations to one flow's tickets (`ADMISSION_STANDS`).
pub const FLOW_STEP_PREFIX: &str = "flow.step:";

/// The longest flow id a request row records (`request.flow_id`'s bound).
/// A longer `id` is no flow the library could hold; the row records none,
/// which a revocation of any flow's step grant voids.
const MAX_FLOW_ID_BYTES: usize = 256;

/// What a flow step's grant authorizes: one step, as it was defined when the
/// grant was made, in one repository (or, for a grant a human added by hand
/// for every repository, any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantBinding {
    /// The flow id.
    pub flow_id: String,
    /// The step id within the flow.
    pub step_id: String,
    /// SHA-256 (64 lower-case hex) of the step's effective definition.
    pub effect_digest: String,
    /// The gate class the step was granted under: `destructive` or
    /// `external`.
    pub effect_class: String,
    /// The canonical repository the grant is for; `None` for every
    /// repository.
    pub repository: Option<String>,
}

impl GrantBinding {
    /// The `grant.scope` a row with this binding carries: `repository` when
    /// it is bound to one, `global` when it is for every repository.
    #[must_use]
    pub fn scope(&self) -> &'static str {
        if self.repository.is_some() {
            SCOPE_REPOSITORY
        } else {
            "global"
        }
    }
}

/// `grant.scope` of a grant bound to one repository.
pub const SCOPE_REPOSITORY: &str = "repository";

/// The `grant` columns every grant read selects, in [`Store::grant_row`]'s
/// order.
pub(super) const GRANT_COLUMNS: &str = "id, capability, scope, granted_ts, revoked_ts, \
     flow_id, step_id, effect_digest, effect_class, repository, bound_ts";

/// The flow a request row records: the `id` argument of a `flow.run`, when
/// it is a string of a bounded length. Every other capability records none.
pub(super) fn flow_id_of(capability: &str, args_json: &str) -> Option<String> {
    if capability != "flow.run" {
        return None;
    }
    let args: serde_json::Value = serde_json::from_str(args_json).ok()?;
    args.get("id")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.is_empty() && id.len() <= MAX_FLOW_ID_BYTES)
        .map(str::to_owned)
}

impl Store {
    /// One `grant` row read with [`GRANT_COLUMNS`].
    pub(super) fn grant_row(row: &Row<'_>) -> Result<GrantRow, StoreError> {
        let flow_id: Option<String> = row.get(5)?;
        let step_id: Option<String> = row.get(6)?;
        let effect_digest: Option<String> = row.get(7)?;
        let effect_class: Option<String> = row.get(8)?;
        let binding = match (flow_id, step_id, effect_digest, effect_class) {
            (Some(flow_id), Some(step_id), Some(effect_digest), Some(effect_class)) => {
                Some(GrantBinding {
                    flow_id,
                    step_id,
                    effect_digest,
                    effect_class,
                    repository: row.get(9)?,
                })
            }
            _ => None,
        };
        Ok(GrantRow {
            id: row.get(0)?,
            capability: row.get(1)?,
            scope: row.get(2)?,
            granted_ts: row.get(3)?,
            revoked_ts: row.get(4)?,
            binding,
            bound_ts: row.get(10)?,
        })
    }

    /// Every active grant of `capability`, oldest first: one per repository
    /// it is bound to, plus any unbound legacy row.
    pub async fn active_grants(&self, capability: &str) -> Result<Vec<GrantRow>, StoreError> {
        let capability = capability.to_owned();
        self.run(move |conn| {
            let mut stmt = conn.prepare(&format!(
                "SELECT {GRANT_COLUMNS} FROM \"grant\"
                     WHERE capability = ?1 AND revoked_ts IS NULL ORDER BY id"
            ))?;
            let mut rows = stmt.query(params![capability])?;
            let mut out = Vec::new();
            while let Some(row) = rows.next()? {
                out.push(Self::grant_row(&row)?);
            }
            Ok(out)
        })
        .await
    }

    /// Binds the unbound legacy grant `grant_id` to `binding` and appends
    /// `audit` to `request_id`, in one transaction. False, with nothing
    /// written, when the row is no longer an active unbound grant (revoked,
    /// or bound by a concurrent first use).
    pub async fn bind_legacy_grant_audited(
        &self,
        request_id: &str,
        grant_id: i64,
        binding: &GrantBinding,
        audit: AuditEntry<'_>,
    ) -> Result<bool, StoreError> {
        let request_id = request_id.to_owned();
        let binding = binding.clone();
        let audit = OwnedAudit::new(audit);
        self.transact(move |conn| {
            let changed = conn.execute(
                "UPDATE \"grant\" SET flow_id = ?2, step_id = ?3, effect_digest = ?4,
                     effect_class = ?5, repository = ?6, bound_ts = ?7, scope = ?8
                 WHERE id = ?1 AND revoked_ts IS NULL AND effect_digest IS NULL",
                params![
                    grant_id,
                    binding.flow_id,
                    binding.step_id,
                    binding.effect_digest,
                    binding.effect_class,
                    binding.repository,
                    now_ts(),
                    binding.scope()
                ],
            )?;
            if changed == 0 {
                return Ok(false);
            }
            Self::insert_audit_row(conn, &request_id, audit.entry())?;
            Ok(true)
        })
        .await
    }

    /// The flow id recorded on request `id` at admission, when it has one.
    pub async fn request_flow_id(&self, id: &str) -> Result<Option<String>, StoreError> {
        let id = id.to_owned();
        self.run(move |conn| {
            let mut stmt = conn.prepare("SELECT flow_id FROM request WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            match rows.next()? {
                Some(row) => row.get(0),
                None => Ok(None),
            }
        })
        .await
    }

    /// How many revocations a `flow.run` of `flow_id` depends on: a
    /// revocation of `flow.run` itself or of one of that flow's step grants.
    /// The flow-scoped form of [`Self::grant_revocation_revision_for`]: a
    /// parked run stamps it, and another flow's revocation leaves it alone.
    pub async fn grant_revocation_revision_for_flow(
        &self,
        flow_id: &str,
    ) -> Result<i64, StoreError> {
        let prefix = format!("{FLOW_STEP_PREFIX}{flow_id}/");
        self.run(move |conn| {
            let mut stmt = conn.prepare(
                "SELECT COUNT(*) FROM \"grant\" g WHERE g.revoked_ts IS NOT NULL
                     AND (g.capability = 'flow.run'
                          OR substr(g.capability, 1, length(?1)) = ?1)",
            )?;
            let mut rows = stmt.query(params![prefix])?;
            let row = rows.next()?.ok_or_else(|| StoreError::NotFound {
                table: "grant",
                id: "flow revocation revision".into(),
            })?;
            row.get(0)
        })
        .await
    }

    /// Records `binding` for `capability` inside the caller's transaction —
    /// the remembered approval and the hand-added flow step grant. The
    /// active grant of the same repository (the same `None` for every
    /// repository) is re-pointed at the binding, else an active unbound
    /// legacy row is bound, else a new row is inserted. True when anything
    /// changed; false when the same binding is active already.
    ///
    /// Re-pointing rather than revoking keeps the tickets admitted under the
    /// old binding alive: each step is gated again when it runs, against the
    /// binding in force then, so nothing the old binding allowed outlives it.
    pub(super) fn bind_grant_rows(
        conn: Db<'_>,
        capability: &str,
        binding: &GrantBinding,
    ) -> Result<bool, StoreError> {
        let mut stmt = conn.prepare(
            "SELECT id, effect_digest, effect_class FROM \"grant\"
                 WHERE capability = ?1 AND revoked_ts IS NULL
                   AND (repository IS ?2 OR effect_digest IS NULL)
                 ORDER BY effect_digest IS NULL, id LIMIT 1",
        )?;
        let mut rows = stmt.query(params![capability, binding.repository])?;
        let found = match rows.next()? {
            Some(row) => Some((
                row.get::<i64>(0)?,
                row.get::<Option<String>>(1)?,
                row.get::<Option<String>>(2)?,
            )),
            None => None,
        };
        drop(rows);
        match found {
            Some((_, Some(digest), Some(class)))
                if digest == binding.effect_digest && class == binding.effect_class =>
            {
                Ok(false)
            }
            Some((id, _, _)) => {
                conn.execute(
                    "UPDATE \"grant\" SET flow_id = ?2, step_id = ?3, effect_digest = ?4,
                         effect_class = ?5, repository = ?6, bound_ts = ?7, scope = ?8
                     WHERE id = ?1",
                    params![
                        id,
                        binding.flow_id,
                        binding.step_id,
                        binding.effect_digest,
                        binding.effect_class,
                        binding.repository,
                        now_ts(),
                        binding.scope()
                    ],
                )?;
                Ok(true)
            }
            None => {
                let now = now_ts();
                conn.execute(
                    "INSERT INTO \"grant\" (capability, scope, granted_ts, flow_id, step_id,
                         effect_digest, effect_class, repository, bound_ts)
                     VALUES (?1, ?8, ?2, ?3, ?4, ?5, ?6, ?7, ?2)",
                    params![
                        capability,
                        now,
                        binding.flow_id,
                        binding.step_id,
                        binding.effect_digest,
                        binding.effect_class,
                        binding.repository,
                        binding.scope()
                    ],
                )?;
                Ok(true)
            }
        }
    }
}
