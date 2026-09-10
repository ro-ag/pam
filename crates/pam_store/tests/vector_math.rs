//! Public SQL regressions for PAM's pure-Rust `turso_core` vector kernels.
//! Dot distance is the negated dot product; L2 is Euclidean, not squared.
//! Zero/NaN cosine semantics follow `SimSIMD`'s scalar normalization contract.
use turso::{Builder, Connection, Value};

async fn scalar(connection: &Connection, sql: &str) -> Value {
    let mut rows = connection.query(sql, ()).await.expect(sql);
    rows.next()
        .await
        .expect(sql)
        .expect("one scalar row")
        .get_value(0)
        .unwrap()
}

fn close(actual: &Value, expected: f64) {
    let Value::Real(actual) = actual else {
        panic!("expected real scalar, got {actual:?}");
    };
    let tolerance = 1e-6 * expected.abs().max(1.0);
    assert!(
        (actual - expected).abs() <= tolerance,
        "expected {expected}, got {actual}"
    );
}

async fn rejects(connection: &Connection, sql: &str, detail: &str) {
    let error = match connection.query(sql, ()).await {
        Err(error) => error,
        Ok(mut rows) => rows
            .next()
            .await
            .expect_err("invalid vector must not become a distance"),
    };
    assert!(error.to_string().contains(detail), "{sql}: {error}");
}

#[tokio::test]
async fn dense_distances_keep_sign_scale_and_geometric_conventions() {
    let db = Builder::new_local(":memory:").build().await.unwrap();
    let connection = db.connect().unwrap();
    for vector in ["vector32", "vector64"] {
        for (metric, left, right, expected) in [
            ("dot", "[1,2]", "[2,4]", -10.0),
            ("dot", "[1,2]", "[-1,-2]", 5.0),
            ("l2", "[1,2]", "[4,6]", 5.0),
            ("l2", "[1,2]", "[1,2]", 0.0),
            ("cos", "[1,2]", "[1,2]", 0.0),
            ("cos", "[1,2]", "[-1,-2]", 2.0),
            ("cos", "[1,0]", "[0,1]", 1.0),
            ("cos", "[1,2]", "[2,4]", 0.0),
        ] {
            close(
                &scalar(
                    &connection,
                    &format!(
                        "SELECT vector_distance_{metric}({vector}('{left}'), {vector}('{right}'))"
                    ),
                )
                .await,
                expected,
            );
        }
    }
}

#[tokio::test]
async fn empty_and_zero_vectors_preserve_native_cosine_contract() {
    let db = Builder::new_local(":memory:").build().await.unwrap();
    let connection = db.connect().unwrap();
    for vector in ["vector32", "vector64"] {
        for metric in ["dot", "l2", "cos"] {
            close(
                &scalar(
                    &connection,
                    &format!("SELECT vector_distance_{metric}({vector}('[]'), {vector}('[]'))"),
                )
                .await,
                0.0,
            );
            close(
                &scalar(
                    &connection,
                    &format!(
                        "SELECT vector_distance_{metric}({vector}('[0,0]'), {vector}('[0,0]'))"
                    ),
                )
                .await,
                0.0,
            );
        }
        for (left, right) in [("[0,0]", "[1,2]"), ("[1,2]", "[0,0]")] {
            close(
                &scalar(
                    &connection,
                    &format!("SELECT vector_distance_cos({vector}('{left}'), {vector}('{right}'))"),
                )
                .await,
                1.0,
            );
        }
    }
}

#[tokio::test]
async fn mismatched_types_dimensions_and_nonfinite_text_are_rejected() {
    let db = Builder::new_local(":memory:").build().await.unwrap();
    let connection = db.connect().unwrap();
    for metric in ["dot", "l2", "cos"] {
        rejects(
            &connection,
            &format!("SELECT vector_distance_{metric}(vector32('[1]'), vector32('[1,2]'))"),
            "same dimensions",
        )
        .await;
        rejects(
            &connection,
            &format!("SELECT vector_distance_{metric}(vector32('[1]'), vector64('[1]'))"),
            "same type",
        )
        .await;
    }
    for vector in ["vector32", "vector64"] {
        for text in ["[NaN]", "[inf]", "[-inf]", "[1e400]"] {
            rejects(
                &connection,
                &format!("SELECT {vector}('{text}')"),
                "Invalid vector value",
            )
            .await;
        }
    }
}

#[tokio::test]
async fn extreme_finite_values_keep_documented_accumulation_behavior() {
    let db = Builder::new_local(":memory:").build().await.unwrap();
    let connection = db.connect().unwrap();
    close(
        &scalar(
            &connection,
            "SELECT vector_distance_dot(vector32('[1e20]'),vector32('[1e20]'))",
        )
        .await,
        -1e40,
    );
    close(
        &scalar(
            &connection,
            "SELECT vector_distance_dot(vector64('[1e150]'),vector64('[1e150]'))",
        )
        .await,
        -1e300,
    );
    close(
        &scalar(
            &connection,
            "SELECT vector_distance_l2(vector64('[1e150]'),vector64('[0]'))",
        )
        .await,
        1e150,
    );
    // f32 L2 retains upstream Rust/scalar f32 accumulation, including overflow.
    assert_eq!(
        scalar(
            &connection,
            "SELECT vector_distance_l2(vector32('[1e20]'),vector32('[0]'))"
        )
        .await,
        Value::Real(f64::INFINITY)
    );
    for (vector, values) in [("vector32", "[1e15,1e15]"), ("vector64", "[1e150,1e150]")] {
        close(
            &scalar(
                &connection,
                &format!("SELECT vector_distance_cos({vector}('{values}'),{vector}('{values}'))"),
            )
            .await,
            0.0,
        );
    }
}

#[tokio::test]
async fn binary_nonfinite_vectors_preserve_sql_null_and_infinity_behavior() {
    let db = Builder::new_local(":memory:").build().await.unwrap();
    let connection = db.connect().unwrap();
    // f32 dense blobs have only little-endian values; f64 appends type byte 2.
    let f64_blob = |value: f64| {
        let mut bytes = value.to_le_bytes().to_vec();
        bytes.push(2);
        bytes
    };
    for (nan, infinity, one) in [
        (
            f32::NAN.to_le_bytes().to_vec(),
            f32::INFINITY.to_le_bytes().to_vec(),
            1.0_f32.to_le_bytes().to_vec(),
        ),
        (f64_blob(f64::NAN), f64_blob(f64::INFINITY), f64_blob(1.0)),
    ] {
        let nan = hex::encode(nan);
        let infinity = hex::encode(infinity);
        let one = hex::encode(one);
        for metric in ["dot", "l2"] {
            assert_eq!(
                scalar(
                    &connection,
                    &format!("SELECT vector_distance_{metric}(x'{nan}',x'{one}')")
                )
                .await,
                Value::Null
            );
        }
        close(
            &scalar(
                &connection,
                &format!("SELECT vector_distance_cos(x'{nan}',x'{one}')"),
            )
            .await,
            0.0,
        );
        close(
            &scalar(
                &connection,
                &format!("SELECT vector_distance_cos(x'{infinity}',x'{one}')"),
            )
            .await,
            0.0,
        );
        assert_eq!(
            scalar(
                &connection,
                &format!("SELECT vector_distance_dot(x'{infinity}',x'{one}')")
            )
            .await,
            Value::Real(f64::NEG_INFINITY)
        );
        assert_eq!(
            scalar(
                &connection,
                &format!("SELECT vector_distance_l2(x'{infinity}',x'{one}')")
            )
            .await,
            Value::Real(f64::INFINITY)
        );
        assert_eq!(
            scalar(
                &connection,
                &format!("SELECT vector_distance_l2(x'{infinity}',x'{infinity}')")
            )
            .await,
            Value::Null
        );
    }
}
