//! A transport that answers from a script and records what it was asked.
//!
//! Available inside this crate's own tests, and to anyone who turns on the
//! `testing` feature — the daemon's flow tests drive whole connector steps
//! through it without a network.
//!
//! ```
//! use pam_connectors::testing::FakeTransport;
//!
//! let transport = FakeTransport::new().json(200, r#"{"login":"octocat"}"#);
//! assert!(transport.requests().is_empty());
//! ```

use std::sync::Mutex;

use crate::{HttpRequest, HttpResponse, HttpTransport, TransportError};

/// A scripted [`HttpTransport`].
///
/// Answers are handed out in the order they were queued; a call made after
/// the script runs out fails with a [`TransportError::Network`] naming the
/// URL, which reads much better in a test than a panic.
#[derive(Debug, Default)]
pub struct FakeTransport {
    answers: Mutex<Vec<Result<HttpResponse, TransportError>>>,
    seen: Mutex<Vec<HttpRequest>>,
}

impl FakeTransport {
    /// An empty script.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Queues one response.
    #[must_use]
    pub fn response(self, response: HttpResponse) -> Self {
        self.answers
            .lock()
            .expect("the fake transport's lock is never poisoned")
            .push(Ok(response));
        self
    }

    /// Queues a JSON answer with the given status.
    #[must_use]
    pub fn json(self, status: u16, body: &str) -> Self {
        self.response(HttpResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
        })
    }

    /// Queues an answer with explicit headers — a rate-limit budget, a
    /// `Location`, a `Retry-After`.
    #[must_use]
    pub fn with_headers(self, status: u16, headers: &[(&str, &str)], body: &str) -> Self {
        self.response(HttpResponse {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        })
    }

    /// Queues a raw body — a log, or something that is not JSON at all.
    #[must_use]
    pub fn bytes(self, status: u16, body: Vec<u8>) -> Self {
        self.response(HttpResponse {
            status,
            headers: Vec::new(),
            body,
        })
    }

    /// Queues a transport failure.
    #[must_use]
    pub fn failure(self, error: TransportError) -> Self {
        self.answers
            .lock()
            .expect("the fake transport's lock is never poisoned")
            .push(Err(error));
        self
    }

    /// Every request made so far, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.seen
            .lock()
            .expect("the fake transport's lock is never poisoned")
            .clone()
    }

    /// The URL of the `index`-th request, for a one-line assertion.
    ///
    /// # Panics
    ///
    /// If fewer than `index + 1` requests were made.
    #[must_use]
    pub fn url(&self, index: usize) -> String {
        self.requests()[index].url.to_string()
    }

    /// The value of a header on the `index`-th request.
    ///
    /// # Panics
    ///
    /// If fewer than `index + 1` requests were made.
    #[must_use]
    pub fn header(&self, index: usize, name: &str) -> Option<String> {
        self.requests()[index]
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}

impl HttpTransport for FakeTransport {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
        _deadline: std::time::Instant,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + 'a>>
    {
        let url = request.url.to_string();
        self.seen
            .lock()
            .expect("the fake transport's lock is never poisoned")
            .push(request);
        let mut answers = self
            .answers
            .lock()
            .expect("the fake transport's lock is never poisoned");
        let answer = if answers.is_empty() {
            Err(TransportError::Network(format!(
                "the fake transport has no scripted answer for {url}"
            )))
        } else {
            answers.remove(0)
        };
        Box::pin(async move { answer })
    }
}
