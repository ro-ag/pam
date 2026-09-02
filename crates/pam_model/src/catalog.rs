//! The models PAM offers to download, with the numbers that make the offer
//! honest.
//!
//! # Why a static list
//!
//! A catalog fetched from the network would be one more thing that can be
//! down, one more thing that can lie, and one more thing to authenticate.
//! This one is compiled in: four entries, each with the exact byte count and
//! SHA-256 digest of the file it names, taken from the Hugging Face LFS
//! metadata. The download layer verifies against these numbers rather than
//! against anything the server says about itself, so a mirror, a proxy, or a
//! bad day at the CDN cannot hand PAM a different file than the one the
//! human chose.
//!
//! Growing the catalog is a code change with a review. That is the point.
//!
//! # One engine class
//!
//! Every entry is Qwen3-Coder-30B-A3B-Instruct — a mixture of experts with
//! roughly 3B parameters active per token, which is what makes a 30B model
//! answer at a usable speed on a laptop. The entries differ only in
//! quantization, and each one clears
//! [`MODEL_FLOOR_BYTES`](crate::registry::MODEL_FLOOR_BYTES); a unit test
//! enforces that, because a catalog entry that could not serve a job would
//! be an invitation to a download that ends in a refusal.
//!
//! Only K-quants and `Q8_0` are listed. The repository also publishes IQ and
//! UD variants, and they are smaller — but candle's quantized kernels do not
//! cover those formats, so offering one would mean a model that downloads
//! and then fails to load.
//!
//! # RAM
//!
//! [`Preset::min_host_ram_bytes`] is what the host needs, not what the file
//! weighs: weights, KV cache, and the rest of the machine's working set.
//! The GUI hides entries that do not fit rather than disabling them —
//! a greyed-out row the human can never use is noise.

/// A model PAM knows how to fetch, down to the byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Preset {
    /// Stable identifier used by `admin.models.download`; lowercase, no
    /// spaces. Never reused for different weights.
    pub id: &'static str,
    /// What the GUI shows a human.
    pub label: &'static str,
    /// Directory under the models dir, and the first half of the model id.
    pub vendor: &'static str,
    /// File name on disk, which is also the file name at the source.
    pub file_name: &'static str,
    /// Direct download URL.
    pub url: &'static str,
    /// Exact size. The download refuses anything else.
    pub size_bytes: u64,
    /// Exact SHA-256, lowercase hex. The download refuses anything else.
    pub sha256: &'static str,
    /// SPDX-style licence identifier.
    pub license_id: &'static str,
    /// Where a human can read that licence.
    pub license_url: &'static str,
    /// Quantization label, matching what the GGUF header reports.
    pub quant: &'static str,
    /// Parameter shape, for the card.
    pub params_label: &'static str,
    /// Host RAM this model needs to run — not the file size.
    pub min_host_ram_bytes: u64,
}

impl Preset {
    /// Whether a machine with `total_ram_bytes` of memory can run this
    /// model.
    #[must_use]
    pub fn fits_host(&self, total_ram_bytes: u64) -> bool {
        total_ram_bytes >= self.min_host_ram_bytes
    }

    /// The registry id this preset installs as: `<vendor>/<file stem>`.
    ///
    /// Downloads and scans have to agree on this string, so it is derived
    /// the same way in both places rather than stored twice.
    #[must_use]
    pub fn model_id(&self) -> String {
        let stem = self
            .file_name
            .strip_suffix(".gguf")
            .unwrap_or(self.file_name);
        format!("{}/{stem}", self.vendor)
    }
}

/// Where every entry below is fetched from.
///
/// Each [`Preset::url`] is this prefix plus the file name, spelled out in
/// full because a `const` cannot `format!`. A unit test holds the two
/// halves together.
pub const QWEN_BASE_URL: &str =
    "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/";

/// Licence text for every entry below.
const QWEN_LICENSE_URL: &str =
    "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/blob/main/LICENSE";

/// One decimal gigabyte, the unit the RAM figures are quoted in.
const GB: u64 = 1_000_000_000;

/// Everything PAM offers to download.
///
/// Sizes and digests are the Hugging Face LFS `oid` and `size` for each
/// file; they are verified after transfer, so a wrong number here is a
/// failed download, not a bad model.
pub const CATALOG: &[Preset] = &[
    Preset {
        id: "qwen3-coder-30b-a3b-q4_k_m",
        label: "Qwen3-Coder 30B-A3B · Q4_K_M",
        vendor: "qwen",
        file_name: "Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
        url: "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/Qwen3-Coder-30B-A3B-Instruct-Q4_K_M.gguf",
        size_bytes: 18_556_689_568,
        sha256: "fadc3e5f8d42bf7e894a785b05082e47daee4df26680389817e2093056f088ad",
        license_id: "apache-2.0",
        license_url: QWEN_LICENSE_URL,
        quant: "Q4_K_M",
        params_label: "30B-A3B (MoE)",
        min_host_ram_bytes: 32 * GB,
    },
    Preset {
        id: "qwen3-coder-30b-a3b-q5_k_m",
        label: "Qwen3-Coder 30B-A3B · Q5_K_M",
        vendor: "qwen",
        file_name: "Qwen3-Coder-30B-A3B-Instruct-Q5_K_M.gguf",
        url: "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/Qwen3-Coder-30B-A3B-Instruct-Q5_K_M.gguf",
        size_bytes: 21_725_584_544,
        sha256: "4b78837bbec5ee248e4a5642bf608b6793721af41b92589e40c8da0bce58b907",
        license_id: "apache-2.0",
        license_url: QWEN_LICENSE_URL,
        quant: "Q5_K_M",
        params_label: "30B-A3B (MoE)",
        min_host_ram_bytes: 32 * GB,
    },
    Preset {
        id: "qwen3-coder-30b-a3b-q6_k",
        label: "Qwen3-Coder 30B-A3B · Q6_K",
        vendor: "qwen",
        file_name: "Qwen3-Coder-30B-A3B-Instruct-Q6_K.gguf",
        url: "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/Qwen3-Coder-30B-A3B-Instruct-Q6_K.gguf",
        size_bytes: 25_092_535_456,
        sha256: "100b5121d09553fb1af3b873b21fb3ec3da5c306fc5cb09bd338c48e21b10875",
        license_id: "apache-2.0",
        license_url: QWEN_LICENSE_URL,
        quant: "Q6_K",
        params_label: "30B-A3B (MoE)",
        min_host_ram_bytes: 48 * GB,
    },
    Preset {
        id: "qwen3-coder-30b-a3b-q8_0",
        label: "Qwen3-Coder 30B-A3B · Q8_0",
        vendor: "qwen",
        file_name: "Qwen3-Coder-30B-A3B-Instruct-Q8_0.gguf",
        url: "https://huggingface.co/unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF/resolve/main/Qwen3-Coder-30B-A3B-Instruct-Q8_0.gguf",
        size_bytes: 32_483_935_392,
        sha256: "4ff1cff607804037bf6d2168249c570baa4e1621292b159c0e06591e0d7c3066",
        license_id: "apache-2.0",
        license_url: QWEN_LICENSE_URL,
        quant: "Q8_0",
        params_label: "30B-A3B (MoE)",
        min_host_ram_bytes: 64 * GB,
    },
];

/// Looks a preset up by [`Preset::id`].
#[must_use]
pub fn find_preset(id: &str) -> Option<&'static Preset> {
    CATALOG.iter().find(|preset| preset.id == id)
}
