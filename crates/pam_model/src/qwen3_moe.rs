//! Adapted from candle-transformers 0.9.2 `models/quantized_qwen3_moe.rs`
//! (Apache-2.0, Hugging Face). PAM adds KV-cache reset and a portable
//! quantized sparse-expert adapter: upstream's fused GGUF `MoE` kernel only
//! supports CUDA, while PAM ships CPU and Metal backends.

// Three pedantic lints are waived for the whole vendored module rather than
// at each site. Every other one this file used to trip has been fixed in the
// code; these three are upstream's shape, not upstream's sloppiness, and
// rewriting them would make the next upstream diff unreadable for no
// behavioural gain:
//
// - `too_many_arguments`: upstream carries this same allow inline on
//   `QuantizedAttention::new`, which takes the nine dimensions a GGUF
//   attention block is described by. Hoisted here so the module has no
//   `#[allow]` sprinkled through its body.
// - `struct_field_names`: `Mlp`'s fields are named after the GGUF tensors
//   they hold (`ffn_gate`/`ffn_down`/`ffn_up`, the feed-forward triple), and
//   a shared prefix is the point.
// - `too_many_lines`: `from_gguf` is one flat read of a model header, 131
//   lines of `md_get` in the order the format lists them. Splitting it would
//   scatter that order across helpers.
// - `similar_names` and `many_single_char_names`: `wq`/`wk`/`wv`, `bq`/`bk`/
//   `bv`, `q`/`k`/`v`, `b`/`l` are the letters attention is written in, here
//   and in the paper and in every other implementation. Renaming them to
//   satisfy an edit-distance heuristic would make the code harder to read
//   against the reference, not easier.
#![allow(
    clippy::too_many_arguments,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use crate::sparse_moe::{SparseMoe, split_expert_tensors};
use candle_core::quantized::gguf_file;
use candle_core::{DType, Device, Result, Tensor};
use candle_nn::Linear;
use candle_nn::kv_cache::ConcatKvCache;
use candle_nn::{Embedding, Module};
use candle_transformers::fused_moe::MoeCfg;
use candle_transformers::models::quantized_qwen3::{Gguf, RotaryEmbedding};
use candle_transformers::models::with_tracing::QMatMul;
use candle_transformers::quantized_nn::RmsNorm;
use candle_transformers::utils::repeat_kv;
use std::sync::Arc;
#[derive(Debug, Clone)]
struct Mlp {
    feed_forward_w1: QMatMul,
    feed_forward_w2: QMatMul,
    feed_forward_w3: QMatMul,
}

impl Module for Mlp {
    fn forward(&self, xs: &Tensor) -> Result<Tensor> {
        let w1 = self.feed_forward_w1.forward(xs)?;
        let w3 = self.feed_forward_w3.forward(xs)?;
        self.feed_forward_w2
            .forward(&(candle_nn::ops::silu(&w1)? * w3)?)
    }
}

enum MoeOrMlp {
    FusedMoe(SparseMoe),
    Mlp(Mlp),
}

impl MoeOrMlp {
    fn forward(&self, xs: &Tensor, _is_prefill: bool) -> Result<Tensor> {
        match self {
            Self::Mlp(m) => m.forward(xs),
            Self::FusedMoe(m) => m.forward(xs),
        }
    }
}

pub struct QuantizedAttention {
    attention_wq: QMatMul,
    attention_wk: QMatMul,
    attention_wv: QMatMul,
    attention_bq: Option<Tensor>,
    attention_bk: Option<Tensor>,
    attention_bv: Option<Tensor>,
    attention_wo: QMatMul,
    q_norm: Option<RmsNorm>,
    k_norm: Option<RmsNorm>,
    n_head: usize,
    n_kv_head: usize,
    head_dim: usize,
    num_kv_groups: usize,
    rotary_emb: Arc<RotaryEmbedding>,
    dtype: DType,
    kv_cache: ConcatKvCache,
}

impl QuantizedAttention {
    pub fn new<R: std::io::Seek + std::io::Read>(
        gg: &mut Gguf<R>,
        prefix: &str,
        dtype: DType,
        num_heads: usize,
        num_kv_heads: usize,
        head_dim: usize,
        rms_norm_eps: f64,
        device: &Device,
        rotary_emb: Arc<RotaryEmbedding>,
    ) -> Result<Self> {
        let num_kv_groups = num_heads / num_kv_heads;
        let attention_wq = gg.qmatmul(&format!("{prefix}.attn_q.weight"))?;
        let attention_wk = gg.qmatmul(&format!("{prefix}.attn_k.weight"))?;
        let attention_wv = gg.qmatmul(&format!("{prefix}.attn_v.weight"))?;

        let attention_bq = gg.tensor(&format!("{prefix}.attn_q.bias"));
        let attention_bk = gg.tensor(&format!("{prefix}.attn_k.bias"));
        let attention_bv = gg.tensor(&format!("{prefix}.attn_v.bias"));

        let attention_bq = if let Ok(attention_bq) = attention_bq {
            Some(attention_bq.dequantize(device)?.to_dtype(DType::F32)?)
        } else {
            None
        };

        let attention_bk = if let Ok(attention_bk) = attention_bk {
            Some(attention_bk.dequantize(device)?.to_dtype(DType::F32)?)
        } else {
            None
        };

        let attention_bv = if let Ok(attention_bv) = attention_bv {
            Some(attention_bv.dequantize(device)?.to_dtype(DType::F32)?)
        } else {
            None
        };

        let attention_wo = gg.qmatmul(&format!("{prefix}.attn_output.weight"))?;
        let q_norm = Some(gg.rms_norm(&format!("{prefix}.attn_q_norm.weight"), rms_norm_eps)?);
        let k_norm = Some(gg.rms_norm(&format!("{prefix}.attn_k_norm.weight"), rms_norm_eps)?);
        let kv_cache = ConcatKvCache::new(2);
        Ok(QuantizedAttention {
            attention_wq,
            attention_wk,
            attention_wv,
            attention_bq,
            attention_bk,
            attention_bv,
            attention_wo,
            q_norm,
            k_norm,
            n_head: num_heads,
            n_kv_head: num_kv_heads,
            head_dim,
            num_kv_groups,
            rotary_emb,
            dtype,
            kv_cache,
        })
    }

    pub fn forward(
        &mut self,
        x: &Tensor,
        mask: Option<&Tensor>,
        input_pos: usize,
    ) -> Result<Tensor> {
        let (b, seq_len, _) = x.dims3()?;
        let in_dtype = x.dtype();
        let q = self.attention_wq.forward(x)?;
        let k = self.attention_wk.forward(x)?;
        let v = self.attention_wv.forward(x)?;

        let q = if let Some(bq) = &self.attention_bq {
            q.broadcast_add(bq)?
        } else {
            q
        };

        let k = if let Some(bk) = &self.attention_bk {
            k.broadcast_add(bk)?
        } else {
            k
        };

        let v = if let Some(bv) = &self.attention_bv {
            v.broadcast_add(bv)?
        } else {
            v
        };

        let q = q
            .reshape((1, seq_len, self.n_head, self.head_dim))?
            .transpose(1, 2)?
            .contiguous()?;
        let k = k
            .reshape((1, seq_len, self.n_kv_head, self.head_dim))?
            .transpose(1, 2)?
            .contiguous()?;
        let v = v
            .reshape((1, seq_len, self.n_kv_head, self.head_dim))?
            .transpose(1, 2)?
            .contiguous()?;

        let (q, k) = if let (Some(q_norm), Some(k_norm)) = (&self.q_norm, &self.k_norm) {
            // Per‑head RMSNorm in qwen3
            let q_flat = q.flatten(0, 2)?; // (B*H, L, D) -> (BHL, D) after transpose later
            let k_flat = k.flatten(0, 2)?;

            // q_norm and k_norm weights stored in f32 format in qwen3 gguf
            let q_flat = q_norm.forward(&q_flat)?;
            let k_flat = k_norm.forward(&k_flat)?;

            let q = q_flat.reshape((1, self.n_head, seq_len, self.head_dim))?;
            let k = k_flat.reshape((1, self.n_kv_head, seq_len, self.head_dim))?;

            (q, k)
        } else {
            (q, k)
        };

        let (q, k, v) = (
            q.to_dtype(self.dtype)?,
            k.to_dtype(self.dtype)?,
            v.to_dtype(self.dtype)?,
        );

        let (q, k) = self.rotary_emb.apply(&q, &k, input_pos)?;

        let (k, v) = self.kv_cache.append(&k, &v)?;

        let k = repeat_kv(k, self.num_kv_groups)?.contiguous()?;
        let v = repeat_kv(v, self.num_kv_groups)?.contiguous()?;

        let scale = 1.0 / f64::from(u32::try_from(self.head_dim).unwrap_or(u32::MAX)).sqrt();
        let mut scores = (q.matmul(&k.transpose(2, 3)?)? * scale)?;

        if let Some(m) = mask {
            let m_dtype = m.dtype();
            let scores_dtype = scores.dtype();
            let mask = if m_dtype == scores_dtype {
                m.clone()
            } else {
                m.to_dtype(scores_dtype)?
            };
            scores = scores.broadcast_add(&mask)?;
        }

        let probs = candle_nn::ops::softmax_last_dim(&scores)?;
        let ctx = probs.matmul(&v)?; // (B, H, L, D)
        let reshaped_ctx =
            ctx.transpose(1, 2)?
                .reshape((b, seq_len, self.n_head * self.head_dim))?;

        self.attention_wo.forward(&reshaped_ctx.to_dtype(in_dtype)?)
    }

    /// PAM addition: empties this block's keys and values.
    fn clear_kv_cache(&mut self) {
        self.kv_cache.reset();
    }
}

struct LayerWeights {
    self_attn: QuantizedAttention,
    attention_norm: RmsNorm,
    mlp: MoeOrMlp,
    ffn_norm: RmsNorm,
}

impl LayerWeights {
    fn forward_attn(&mut self, x: &Tensor, mask: Option<&Tensor>, offset: usize) -> Result<Tensor> {
        self.self_attn.forward(x, mask, offset)
    }

    /// PAM addition: empties this layer's attention cache.
    fn clear_kv_cache(&mut self) {
        self.self_attn.clear_kv_cache();
    }
}

pub struct GGUFQWenMoE {
    tok_embeddings: Embedding,
    layers: Vec<LayerWeights>,
    norm: RmsNorm,
    output: QMatMul,
    dtype: DType,
    device: Device,
}

impl GGUFQWenMoE {
    pub fn from_gguf<R: std::io::Seek + std::io::Read>(
        mut ct: gguf_file::Content,
        reader: &mut R,
        device: &Device,
        dtype: DType,
    ) -> Result<Self> {
        split_expert_tensors(&mut ct)?;
        let mut gg = Gguf::new(ct, reader, device.clone());
        let md_get = |s: &str| match gg.metadata().get(s) {
            None => candle_core::bail!("cannot find {s} in metadata"),
            Some(v) => Ok(v),
        };
        let arch = md_get("general.architecture")?.to_string()?;

        let head_count =
            md_get(format!("{arch}.attention.head_count").as_str())?.to_u32()? as usize;
        let head_count_kv =
            md_get(format!("{arch}.attention.head_count_kv").as_str())?.to_u32()? as usize;

        let head_dim = md_get(format!("{arch}.attention.key_length").as_str());
        let embedding_length =
            md_get(format!("{arch}.embedding_length").as_str())?.to_u32()? as usize;
        let head_dim = if let Ok(head_dim) = head_dim {
            head_dim.to_u32()? as usize
        } else {
            embedding_length / head_count
        };
        let context_length = md_get(format!("{arch}.context_length").as_str())?.to_u32()? as usize;
        let block_count = md_get(format!("{arch}.block_count").as_str())?.to_u32()? as usize;
        let rms_norm_eps = f64::from(
            md_get(format!("{arch}.attention.layer_norm_rms_epsilon").as_str())?.to_f32()?,
        );
        let rope_freq_base = md_get(format!("{arch}.rope.freq_base").as_str())
            .and_then(gguf_file::Value::to_f32)
            .unwrap_or(10000f32);
        let expert_shared_feed_forward_length =
            md_get(format!("{arch}.expert_shared_feed_forward_length").as_str());
        let shared_expert_intermediate_size = match expert_shared_feed_forward_length {
            Ok(length) => {
                if length.to_u32()? > 0 {
                    Some(length.to_u32()? as usize)
                } else {
                    None
                }
            }
            _ => None,
        };

        let moe_cfg = MoeCfg {
            moe_intermediate_size: md_get(format!("{arch}.expert_feed_forward_length").as_str())?
                .to_u32()? as usize,
            num_experts: md_get(format!("{arch}.expert_count").as_str())?.to_u32()? as usize,
            norm_topk_prob: shared_expert_intermediate_size.is_none(),
            num_experts_per_tok: md_get(format!("{arch}.expert_used_count").as_str())?.to_u32()?
                as usize,
            hidden_size: head_dim,
            act: candle_nn::Activation::Silu,
            decoder_sparse_step: None,
        };

        let tok_embeddings = gg.tensor("token_embd.weight")?;
        let tok_embeddings = tok_embeddings.dequantize(device)?;
        let norm = gg.rms_norm("output_norm.weight", rms_norm_eps)?;
        let output = match gg.qmatmul("output.weight") {
            Ok(v) => v,
            _ => {
                // use tie_word_embeddings
                gg.qmatmul("token_embd.weight")?
            }
        };

        let rotary_emb = Arc::new(RotaryEmbedding::new(
            dtype,
            head_dim,
            context_length,
            f64::from(rope_freq_base),
            device,
        )?);
        let mut layers = Vec::with_capacity(block_count);
        for layer_idx in 0..block_count {
            let prefix = format!("blk.{layer_idx}");
            let mlp = if moe_cfg.num_experts > 0
                && (layer_idx + 1) % moe_cfg.decoder_sparse_step.unwrap_or(1) == 0
            {
                let gate_ws = gg
                    .tensor(&format!("{prefix}.ffn_gate_inp.weight"))?
                    .dequantize(device)?
                    .to_dtype(DType::F32)?;
                let gate = Linear::new(gate_ws, None);
                let moe = SparseMoe::load(
                    &mut gg,
                    &prefix,
                    gate,
                    moe_cfg.num_experts,
                    moe_cfg.num_experts_per_tok,
                    moe_cfg.norm_topk_prob,
                )?;

                MoeOrMlp::FusedMoe(moe)
            } else {
                let mlp = {
                    let feed_forward_w1 = gg.qmatmul(&format!("{prefix}.ffn_gate.weight"))?;
                    let feed_forward_w2 = gg.qmatmul(&format!("{prefix}.ffn_down.weight"))?;
                    let feed_forward_w3 = gg.qmatmul(&format!("{prefix}.ffn_up.weight"))?;
                    Mlp {
                        feed_forward_w1,
                        feed_forward_w2,
                        feed_forward_w3,
                    }
                };
                MoeOrMlp::Mlp(mlp)
            };

            let attention_norm =
                gg.rms_norm(&format!("{prefix}.attn_norm.weight"), rms_norm_eps)?;
            let ffn_norm = gg.rms_norm(&format!("{prefix}.ffn_norm.weight"), rms_norm_eps)?;

            let self_attn = QuantizedAttention::new(
                &mut gg,
                &prefix,
                dtype,
                head_count,
                head_count_kv,
                head_dim,
                rms_norm_eps,
                device,
                rotary_emb.clone(),
            )?;
            layers.push(LayerWeights {
                self_attn,
                attention_norm,
                mlp,
                ffn_norm,
            });
        }

        Ok(Self {
            tok_embeddings: Embedding::new(tok_embeddings, embedding_length),
            layers,
            norm,
            output,
            dtype,
            device: device.clone(),
        })
    }

    fn causal_mask(
        &self,
        b: usize,
        tgt: usize,
        offset: usize,
        sw: Option<usize>,
    ) -> Result<Tensor> {
        let minf = f32::NEG_INFINITY;
        let mask: Vec<_> = (0..tgt)
            .flat_map(|i| {
                (0..(tgt + offset)).map(move |j| {
                    let past_ok = j <= i + offset;
                    let sw_ok = match sw {
                        Some(w) => (i + offset).saturating_sub(j) <= w,
                        None => true,
                    };
                    if past_ok && sw_ok { 0. } else { minf }
                })
            })
            .collect();
        Tensor::from_slice(&mask, (b, 1, tgt, tgt + offset), &self.device)?.to_dtype(self.dtype)
    }

    pub fn forward(&mut self, x: &Tensor, offset: usize) -> Result<Tensor> {
        let mut xs = self.tok_embeddings.forward(x)?;
        let (b, l) = x.dims2()?;

        let causal_mask = if l == 1 {
            None
        } else {
            Some(self.causal_mask(b, l, offset, None)?)
        };

        for layer in &mut self.layers {
            let x = xs;
            let residual = &x;

            let x = layer.attention_norm.forward(&x)?;
            let attn = layer.forward_attn(&x, causal_mask.as_ref(), offset)?;
            let x = (attn + residual)?;

            // MLP
            let residual = &x;
            let x = layer.ffn_norm.forward(&x)?;
            let x = layer.mlp.forward(&x, causal_mask.is_some())?;
            let x = (x + residual)?;
            xs = x;
        }

        let xs = xs.narrow(1, l - 1, 1)?;
        let xs = self.norm.forward(&xs)?;
        self.output.forward(&xs)?.to_dtype(DType::F32)?.squeeze(1)
    }

    /// PAM addition, mirroring `quantized_qwen3::ModelWeights::clear_kv_cache`:
    /// empties every layer's `ConcatKvCache` so the next `forward` at offset 0
    /// starts from nothing.
    ///
    /// Upstream 0.9.2 has no equivalent and keeps `layers` private, so without
    /// this the only way to reach an empty cache is to rebuild the whole model
    /// from its file.
    pub fn clear_kv_cache(&mut self) {
        for layer in &mut self.layers {
            layer.clear_kv_cache();
        }
    }
}
