//! What a tier will actually do when a job asks for it, as one honest record per tier.
//!
//! A tier default is a persistent setting; whether it serves is decided at resolve time
//! by a chain of facts that can each fail independently: configured → installed →
//! verified → qualified → engine installed → ready. [`TierReadiness`] reports the first
//! rung that fails ([`Stage`]) with the same cause the job would be refused with, plus a
//! recovery line, so the GUI never invents readiness and never has to earn a refusal to
//! learn the rule. Residency (the engine currently holding the weights) is transient and
//! reported beside the stage, never as a stage: an unloaded ready model loads on its first
//! job. The daemon computes this ([`crate::model_service::ModelService::readiness`]) so
//! every surface reads the same verdict.

use pam_model::Qualification;
use pam_model::engine::EngineStatus;
use pam_model::registry::ModelEntry;
use serde::Serialize;

use crate::log_service::{
    CAUSE_MODEL_MISSING, CAUSE_MODEL_UNQUALIFIED, CAUSE_MODEL_UNVERIFIED, CAUSE_NO_DEFAULT,
};
use crate::model_service::{ModelService, ModelUnavailable, Tier};

/// [`Blocker::cause`] when the pinned engine is not installed.
pub const CAUSE_ENGINE_NOT_INSTALLED: &str = "engine_not_installed";

/// Recovery line for a tier nothing points at.
pub const RECOVERY_NO_DEFAULT: &str = "Point the tier at a qualified model under Settings > Models; until then every job \
     takes the deterministic path.";

/// Recovery line for a configured model whose file is gone.
pub const RECOVERY_MISSING: &str = "The configured file is not in the models directory: download it again from Models > \
     Downloads, or clear the tier under Settings > Models.";

/// Recovery line for an unverified model offered as a default.
pub const RECOVERY_UNVERIFIED: &str = "Tier defaults need a verified model: run Verify on the PAM GUI Models screen, \
     or download it from the catalog, which checks the digest.";

/// Recovery line for a verified but unqualified model offered as a default.
pub const RECOVERY_UNQUALIFIED: &str = "Tier defaults need a qualified model: one whose exact digest met the capability gates \
     on this engine and platform (see docs/benchmarks). Unqualified models still answer Try on \
     the PAM GUI Models screen.";

/// Recovery line for a ready model with no engine to run it.
pub const RECOVERY_ENGINE_NOT_INSTALLED: &str =
    "Install the llama.cpp engine from Models > Runtime; the model itself is ready.";

/// The first rung of the readiness chain that does not hold, or `Ready`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Nothing points at this tier (nor at its fallback).
    Unconfigured,
    /// The configured id names no file in the models directory.
    Missing,
    /// The file is there but no digest has been checked.
    Unverified,
    /// Verified, but no qualification record covers the digest on this target.
    Unqualified,
    /// The model would serve, but the pinned engine is not installed.
    EngineMissing,
    /// A job on this tier runs on this model.
    Ready,
}

/// Why the tier stops where it does, in the same words a job is refused with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Blocker {
    /// Stable cause, shared with the job-side refusal.
    pub cause: &'static str,
    /// The failure in words.
    pub detail: String,
    /// What a human does about it.
    pub recovery: &'static str,
}

/// One tier's verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TierReadiness {
    /// `light` or `heavy`.
    pub tier: &'static str,
    /// The id set on this tier itself, before any fallback.
    pub configured: Option<String>,
    /// The id the tier resolves to after fallback (`heavy` → `light`).
    pub model_id: Option<String>,
    /// True when `model_id` is borrowed from the light tier.
    pub fallback: bool,
    /// Where the chain stops.
    pub stage: Stage,
    /// Whether the engine holds `model_id` right now. Transient, and independent
    /// of `stage`: a Try can load an unqualified model, and a ready one is
    /// unloaded until its first job.
    pub resident: bool,
    /// The record that qualifies `model_id`, when one does.
    pub qualification: Option<Qualification>,
    /// Present exactly when `stage` is not `Ready`.
    pub blocker: Option<Blocker>,
}

impl ModelService {
    /// [`Self::readiness`] with the engine facts read now: for callers that
    /// need one tier's verdict outside a status read.
    pub async fn readiness_now(&self, tier: Tier) -> Result<TierReadiness, ModelUnavailable> {
        let engine = pam_model::engine::status(&self.engine_base());
        let resident = self.engine_server().and_then(|server| server.model());
        self.readiness(
            tier,
            &engine,
            resident.as_ref().map(|model| model.id.as_str()),
        )
        .await
    }

    /// The readiness of `tier`, given the engine's state and what it holds.
    ///
    /// Reads the settings and the registry; the engine facts are passed in so a
    /// status read computes them once for both tiers.
    pub async fn readiness(
        &self,
        tier: Tier,
        engine: &EngineStatus,
        resident_id: Option<&str>,
    ) -> Result<TierReadiness, ModelUnavailable> {
        let (light, heavy) = self.defaults().await?;
        let configured = match tier {
            Tier::Light => light.clone(),
            Tier::Heavy => heavy.clone(),
        };
        let (model_id, fallback) = match tier {
            Tier::Light => (light, false),
            Tier::Heavy => match heavy {
                Some(id) => (Some(id), false),
                None => (light, true),
            },
        };

        let mut readiness = TierReadiness {
            tier: tier.as_str(),
            configured,
            model_id: model_id.clone(),
            fallback,
            stage: Stage::Unconfigured,
            resident: false,
            qualification: None,
            blocker: None,
        };
        let Some(id) = model_id else {
            readiness.blocker = Some(Blocker {
                cause: CAUSE_NO_DEFAULT,
                detail: format!("no default model for tier {}", tier.as_str()),
                recovery: RECOVERY_NO_DEFAULT,
            });
            return Ok(readiness);
        };
        readiness.resident = resident_id == Some(id.as_str());

        let Some(entry) = self.find(&id).await? else {
            readiness.stage = Stage::Missing;
            readiness.blocker = Some(Blocker {
                cause: CAUSE_MODEL_MISSING,
                detail: format!("default model {id} is not installed"),
                recovery: RECOVERY_MISSING,
            });
            return Ok(readiness);
        };
        readiness.qualification = entry.qualification;
        if let Some((stage, blocker)) = admission_blocker(&entry) {
            readiness.stage = stage;
            readiness.blocker = Some(blocker);
            return Ok(readiness);
        }
        if !engine.installed {
            readiness.stage = Stage::EngineMissing;
            readiness.blocker = Some(Blocker {
                cause: CAUSE_ENGINE_NOT_INSTALLED,
                detail: format!(
                    "the llama.cpp engine {} is not installed{}",
                    engine.expected_tag,
                    engine
                        .cause
                        .as_deref()
                        .map(|cause| format!(" ({cause})"))
                        .unwrap_or_default()
                ),
                recovery: RECOVERY_ENGINE_NOT_INSTALLED,
            });
            return Ok(readiness);
        }
        readiness.stage = Stage::Ready;
        Ok(readiness)
    }
}

/// The stage and blocker [`ModelService::admit`] would refuse `entry` with, if any.
///
/// One place turns the admission error into words, so the admin op and the
/// readiness record cannot drift apart.
#[must_use]
pub fn admission_blocker(entry: &ModelEntry) -> Option<(Stage, Blocker)> {
    match ModelService::admit(entry) {
        Ok(()) => None,
        Err(ModelUnavailable::Unverified(id)) => Some((
            Stage::Unverified,
            Blocker {
                cause: CAUSE_MODEL_UNVERIFIED,
                detail: format!(
                    "{id} has no verified digest; unverified models prove the wiring and never \
                     serve a job"
                ),
                recovery: RECOVERY_UNVERIFIED,
            },
        )),
        Err(_) => Some((
            Stage::Unqualified,
            Blocker {
                cause: CAUSE_MODEL_UNQUALIFIED,
                detail: format!(
                    "{} is verified but no qualification record covers its digest on this \
                     platform; it proves the wiring and never serves a job",
                    entry.id
                ),
                recovery: RECOVERY_UNQUALIFIED,
            },
        )),
    }
}
