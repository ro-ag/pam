use crate::sparse_moe::{Expert, SparseMoe, split_expert_tensors};
use candle_core::quantized::{GgmlDType, QTensor, gguf_file};
use candle_core::{DType, Device, Tensor};
use candle_nn::Linear;
use candle_transformers::models::with_tracing::QMatMul;
use std::io::Cursor;
use std::sync::Arc;

fn matrix(scale: f32, width: usize, dtype: GgmlDType, device: &Device) -> QMatMul {
    let values: Vec<_> = (0..width * width)
        .map(|i| if i / width == i % width { scale } else { 0.0 })
        .collect();
    // Quantize on CPU, then load the exact same blocks onto the tested backend.
    let tensor = Tensor::from_vec(values, (width, width), &Device::Cpu).unwrap();
    let quantized = QTensor::quantize(&tensor, dtype).unwrap();
    let storage =
        candle_core::quantized::QStorage::from_data(quantized.data().unwrap(), device, dtype)
            .unwrap();
    QMatMul::from_weights(Arc::new(QTensor::new(storage, (width, width)).unwrap())).unwrap()
}

fn reference_check(device: &Device, normalize: bool, unequal: bool, dtype: GgmlDType) {
    let width = dtype.block_size();
    let mut router = vec![0.0f32; 3 * width];
    if unequal {
        router[0] = 2.0;
        router[width] = -2.0;
    }
    let model = SparseMoe {
        router: Linear::new(Tensor::from_vec(router, (3, width), device).unwrap(), None),
        experts: [1.0, 3.0, 9.0]
            .into_iter()
            .map(|scale| Expert {
                gate: matrix(1.0, width, dtype, device),
                up: matrix(1.0, width, dtype, device),
                down: matrix(scale, width, dtype, device),
            })
            .collect(),
        top_k: 2,
        normalize,
    };
    let values: Vec<_> = (0..2 * width)
        .map(|i| if i < width { 0.5f32 } else { -0.25 })
        .collect();
    let input = Tensor::from_vec(values.clone(), (1, 2, width), device).unwrap();
    let output = model
        .forward(&input)
        .unwrap()
        .flatten_all()
        .unwrap()
        .to_vec1::<f32>()
        .unwrap();
    for (actual, x) in output.iter().zip(values) {
        let factor = if unequal {
            let winner = if x > 0.0 { 1.0 } else { 3.0 };
            let e = (2.0 * x.abs()).exp();
            let denominator = if normalize {
                e + 1.0
            } else {
                e + 1.0 + 1.0 / e
            };
            (winner * e + 9.0) / denominator
        } else if normalize {
            2.0
        } else {
            4.0 / 3.0
        };
        let expected = factor * x * x / (1.0 + (-x).exp());
        assert!(
            (actual - expected).abs() < 0.02,
            "{dtype:?} {actual} != {expected}"
        );
    }
    assert_eq!(
        model
            .forward(&input.narrow(1, 0, 1).unwrap())
            .unwrap()
            .dims(),
        &[1, 1, width]
    );
}

fn backend_reference_checks(device: &Device) {
    for dtype in [
        GgmlDType::Q8_0,
        GgmlDType::Q4K,
        GgmlDType::Q5K,
        GgmlDType::Q6K,
    ] {
        for normalize in [false, true] {
            for unequal in [false, true] {
                reference_check(device, normalize, unequal, dtype);
            }
        }
    }
}

#[test]
fn cpu_quantized_experts_match_scalar_reference() {
    backend_reference_checks(&Device::Cpu);
}

#[cfg(target_os = "macos")]
#[test]
fn metal_quantized_experts_match_scalar_reference() {
    let device = Device::new_metal(0).expect("Metal backend validation requires a Metal device");
    backend_reference_checks(&device);
}

#[test]
fn split_expert_views_preserve_quantized_bytes() {
    let source = Tensor::from_vec(
        (0..2048)
            .map(|i| if i < 1024 { 1.0f32 } else { 2.0 })
            .collect::<Vec<_>>(),
        (2, 32, 32),
        &Device::Cpu,
    )
    .unwrap();
    let quantized = QTensor::quantize(&source, GgmlDType::Q8_0).unwrap();
    let mut file = Cursor::new(Vec::new());
    gguf_file::write(
        &mut file,
        &[],
        &[("blk.0.ffn_gate_exps.weight", &quantized)],
    )
    .unwrap();
    file.set_position(0);
    let mut content = gguf_file::Content::read(&mut file).unwrap();
    split_expert_tensors(&mut content).unwrap();
    assert_eq!(content.tensor_infos.len(), 2);
    for expert in 0..2 {
        let tensor = content
            .tensor(
                &mut file,
                &format!("blk.0.ffn_gate_exps.weight.expert.{expert}"),
                &Device::Cpu,
            )
            .unwrap();
        assert_eq!(tensor.dtype(), GgmlDType::Q8_0);
        assert_eq!(tensor.shape().dims(), &[32, 32]);
        let first = tensor
            .dequantize(&Device::Cpu)
            .unwrap()
            .flatten_all()
            .unwrap()
            .to_vec1::<f32>()
            .unwrap()[0];
        assert!((first - if expert == 0 { 1.0 } else { 2.0 }).abs() < 0.01);
    }
    content.tensor_infos.insert(
        "bad.ffn_gate_exps.weight".into(),
        gguf_file::TensorInfo {
            ggml_dtype: GgmlDType::Q8_0,
            shape: (2, 32, 3).into(),
            offset: 0,
        },
    );
    assert!(split_expert_tensors(&mut content).is_err());
    let invalid = content
        .tensor_infos
        .get_mut("bad.ffn_gate_exps.weight")
        .unwrap();
    invalid.shape = (2, 32, 32).into();
    invalid.offset = u64::MAX;
    assert!(split_expert_tensors(&mut content).is_err());
}

#[test]
fn invalid_top_k_is_rejected() {
    let model = SparseMoe {
        router: Linear::new(
            Tensor::zeros((1, 32), DType::F32, &Device::Cpu).unwrap(),
            None,
        ),
        experts: Vec::new(),
        top_k: 1,
        normalize: true,
    };
    assert!(
        model
            .forward(&Tensor::zeros((1, 1, 32), DType::F32, &Device::Cpu).unwrap())
            .is_err()
    );
}
