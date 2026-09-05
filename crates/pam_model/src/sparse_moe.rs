//! Portable GGUF `MoE` using ordinary quantized CPU/Metal matrix multiplication.
//! Experts stay quantized; only routed activations and router scores are dense.
use candle_core::quantized::gguf_file::{Content, TensorInfo};
use candle_core::{DType, Result, Tensor};
use candle_nn::{Linear, Module};
use candle_transformers::models::quantized_qwen3::Gguf;
use candle_transformers::models::with_tracing::QMatMul;
use std::io::{Read, Seek};

/// Replace packed expert metadata with views into the same file. Loading each
/// view avoids a second whole-layer allocation or dequantizing all experts.
pub(crate) fn split_expert_tensors(content: &mut Content) -> Result<()> {
    let names: Vec<_> = content
        .tensor_infos
        .keys()
        .filter(|name| {
            [
                "ffn_gate_exps.weight",
                "ffn_up_exps.weight",
                "ffn_down_exps.weight",
            ]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        })
        .cloned()
        .collect();
    for name in names {
        let info = &content.tensor_infos[&name];
        let (experts, rows, cols) = info.shape.dims3()?;
        let elements = rows
            .checked_mul(cols)
            .ok_or_else(|| candle_core::Error::Msg("expert shape overflow".into()))?;
        let block = info.ggml_dtype.block_size();
        if experts == 0 || rows == 0 || cols == 0 || !cols.is_multiple_of(block) {
            candle_core::bail!("invalid quantized expert dimensions for {name}");
        }
        let bytes = elements
            .checked_div(block)
            .and_then(|v| v.checked_mul(info.ggml_dtype.type_size()))
            .ok_or_else(|| candle_core::Error::Msg("expert size overflow".into()))?;
        experts
            .checked_mul(bytes)
            .and_then(|v| u64::try_from(v).ok())
            .and_then(|v| info.offset.checked_add(v))
            .ok_or_else(|| candle_core::Error::Msg("expert extent overflow".into()))?;
        let dtype = info.ggml_dtype;
        let offset = info.offset;
        for expert in 0..experts {
            let relative = expert
                .checked_mul(bytes)
                .and_then(|v| u64::try_from(v).ok())
                .and_then(|v| offset.checked_add(v))
                .ok_or_else(|| candle_core::Error::Msg("expert offset overflow".into()))?;
            content.tensor_infos.insert(
                format!("{name}.expert.{expert}"),
                TensorInfo {
                    ggml_dtype: dtype,
                    shape: (rows, cols).into(),
                    offset: relative,
                },
            );
        }
        content.tensor_infos.remove(&name);
    }
    Ok(())
}

pub(crate) struct Expert {
    pub(crate) gate: QMatMul,
    pub(crate) up: QMatMul,
    pub(crate) down: QMatMul,
}

pub(crate) struct SparseMoe {
    pub(crate) router: Linear,
    pub(crate) experts: Vec<Expert>,
    pub(crate) top_k: usize,
    pub(crate) normalize: bool,
}

impl SparseMoe {
    pub(crate) fn load<R: Read + Seek>(
        gg: &mut Gguf<R>,
        prefix: &str,
        router: Linear,
        count: usize,
        top_k: usize,
        normalize: bool,
    ) -> Result<Self> {
        if top_k == 0 || top_k > count || router.weight().dim(0)? != count {
            candle_core::bail!("invalid MoE expert count or routing top-k");
        }
        let mut experts = Vec::with_capacity(count);
        for i in 0..count {
            experts.push(Expert {
                gate: gg.qmatmul(&format!("{prefix}.ffn_gate_exps.weight.expert.{i}"))?,
                up: gg.qmatmul(&format!("{prefix}.ffn_up_exps.weight.expert.{i}"))?,
                down: gg.qmatmul(&format!("{prefix}.ffn_down_exps.weight.expert.{i}"))?,
            });
        }
        Ok(Self {
            router,
            experts,
            top_k,
            normalize,
        })
    }

    pub(crate) fn forward(&self, input: &Tensor) -> Result<Tensor> {
        let (batch, sequence, hidden) = input.dims3()?;
        if self.top_k == 0 || self.top_k > self.experts.len() {
            candle_core::bail!("invalid MoE routing top-k");
        }
        let xs = input.reshape(((), hidden))?.to_dtype(DType::F32)?;
        let scores =
            candle_nn::ops::softmax_last_dim(&self.router.forward(&xs)?)?.to_vec2::<f32>()?;
        let mut assignments = vec![Vec::new(); self.experts.len()];
        for (token, row) in scores.iter().enumerate() {
            if row.len() != self.experts.len() || row.iter().any(|v| !v.is_finite()) {
                candle_core::bail!("invalid MoE router scores");
            }
            let mut ranked: Vec<_> = row.iter().copied().enumerate().collect();
            ranked.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
            let selected = &ranked[..self.top_k];
            let norm = if self.normalize {
                selected.iter().map(|v| v.1).sum()
            } else {
                1.0
            };
            for &(expert, weight) in selected {
                assignments[expert].push((
                    u32::try_from(token).map_err(candle_core::Error::wrap)?,
                    weight / norm,
                ));
            }
        }
        let mut output = Tensor::zeros(xs.shape(), DType::F32, xs.device())?;
        for (expert, routed) in self.experts.iter().zip(assignments) {
            if routed.is_empty() {
                continue;
            }
            let indices = Tensor::new(routed.iter().map(|v| v.0).collect::<Vec<_>>(), xs.device())?;
            let weights = Tensor::new(routed.iter().map(|v| v.1).collect::<Vec<_>>(), xs.device())?
                .unsqueeze(1)?;
            let selected = xs.index_select(&indices, 0)?;
            let gate = candle_nn::ops::silu(&expert.gate.forward(&selected)?)?;
            let up = expert.up.forward(&selected)?;
            let result = expert
                .down
                .forward(&(gate * up)?)?
                .broadcast_mul(&weights)?;
            output = output.index_add(&indices, &result, 0)?;
        }
        output
            .reshape((batch, sequence, hidden))?
            .to_dtype(input.dtype())
    }
}
