use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::Instant,
};

#[cfg(any(target_os = "macos", test))]
use pam_model::CancellationSignal;
#[cfg(target_os = "macos")]
use pam_model::ModelRuntime;
use pam_model::{CancellationToken, RuntimeError, RuntimeRequest, RuntimeResponse};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

#[cfg(any(target_os = "macos", test))]
const MODEL_QUEUE_CAPACITY: usize = 1;

#[cfg(any(target_os = "macos", test))]
pub(super) trait ModelGenerator: Send + Sync {
    fn generate(
        &self,
        request: RuntimeRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeError>;
}

#[cfg(target_os = "macos")]
impl ModelGenerator for dyn ModelRuntime {
    fn generate(
        &self,
        request: RuntimeRequest,
        cancellation: CancellationToken,
    ) -> Result<RuntimeResponse, RuntimeError> {
        ModelRuntime::generate(self, request, cancellation)
    }
}

#[derive(Clone)]
pub(crate) struct ModelService {
    sender: mpsc::Sender<ModelCommand>,
}

pub(crate) struct ModelWorker {
    sender: mpsc::Sender<ModelCommand>,
    shutdown: CancellationToken,
    active: Arc<Mutex<Option<CancellationToken>>>,
    join: Option<JoinHandle<()>>,
}

enum ModelCommand {
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    Infer {
        request: RuntimeRequest,
        cancellation: CancellationToken,
        response: oneshot::Sender<Result<RuntimeResponse, RuntimeError>>,
    },
    Shutdown,
}

#[derive(Debug)]
pub(crate) enum ModelServiceError {
    Busy,
    DeadlineExceeded,
    Runtime(RuntimeError),
    Unavailable,
}

impl fmt::Display for ModelServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("the embedded model worker is busy"),
            Self::DeadlineExceeded => formatter.write_str("embedded model inference timed out"),
            Self::Runtime(_) => formatter.write_str("embedded model inference failed"),
            Self::Unavailable => formatter.write_str("the embedded model worker is unavailable"),
        }
    }
}

impl Error for ModelServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Busy | Self::DeadlineExceeded | Self::Unavailable => None,
        }
    }
}

impl ModelService {
    #[cfg(target_os = "macos")]
    pub(crate) fn start(runtime: Arc<dyn ModelRuntime>) -> (Self, ModelWorker) {
        Self::start_generator(runtime)
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn start_generator<G>(runtime: Arc<G>) -> (Self, ModelWorker)
    where
        G: ModelGenerator + ?Sized + 'static,
    {
        let (sender, receiver) = mpsc::channel(MODEL_QUEUE_CAPACITY);
        let shutdown = CancellationToken::default();
        let active = Arc::new(Mutex::new(None));
        let join = tokio::spawn(run_worker(
            runtime,
            receiver,
            shutdown.clone(),
            Arc::clone(&active),
        ));
        (
            Self {
                sender: sender.clone(),
            },
            ModelWorker {
                sender,
                shutdown,
                active,
                join: Some(join),
            },
        )
    }

    pub(crate) async fn infer(
        &self,
        request: RuntimeRequest,
        deadline: Instant,
    ) -> Result<RuntimeResponse, ModelServiceError> {
        let cancellation = CancellationToken::default();
        let cancel_on_drop = CancelOnDrop(cancellation.clone());
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(ModelCommand::Infer {
                request,
                cancellation,
                response,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => ModelServiceError::Busy,
                mpsc::error::TrySendError::Closed(_) => ModelServiceError::Unavailable,
            })?;
        let deadline = tokio::time::Instant::from_std(deadline);
        let result = tokio::select! {
            response = receiver => response
                .map_err(|_| ModelServiceError::Unavailable)?
                .map_err(ModelServiceError::Runtime),
            () = tokio::time::sleep_until(deadline) => Err(ModelServiceError::DeadlineExceeded),
        };
        drop(cancel_on_drop);
        result
    }
}

impl ModelWorker {
    pub(crate) async fn shutdown(mut self) {
        self.cancel_active();
        let _ = self.sender.send(ModelCommand::Shutdown).await;
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }

    fn cancel_active(&self) {
        self.shutdown.cancel();
        if let Ok(active) = self.active.lock()
            && let Some(cancellation) = active.as_ref()
        {
            cancellation.cancel();
        }
    }
}

impl Drop for ModelWorker {
    fn drop(&mut self) {
        self.cancel_active();
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[cfg(any(target_os = "macos", test))]
async fn run_worker<G>(
    runtime: Arc<G>,
    mut receiver: mpsc::Receiver<ModelCommand>,
    shutdown: CancellationToken,
    active: Arc<Mutex<Option<CancellationToken>>>,
) where
    G: ModelGenerator + ?Sized + 'static,
{
    while let Some(command) = receiver.recv().await {
        if shutdown.is_cancelled() {
            reject_command(command);
            while let Ok(command) = receiver.try_recv() {
                reject_command(command);
            }
            break;
        }
        match command {
            ModelCommand::Infer {
                request,
                cancellation,
                response,
            } => {
                if let Ok(mut current) = active.lock() {
                    *current = Some(cancellation.clone());
                } else {
                    let _ = response.send(Err(RuntimeError::Unavailable));
                    continue;
                }
                let inference_runtime = Arc::clone(&runtime);
                let result = tokio::task::spawn_blocking(move || {
                    inference_runtime.generate(request, cancellation)
                })
                .await
                .unwrap_or(Err(RuntimeError::Unavailable));
                if let Ok(mut current) = active.lock() {
                    *current = None;
                }
                let _ = response.send(result);
            }
            ModelCommand::Shutdown => break,
        }
    }
}

#[cfg(any(target_os = "macos", test))]
fn reject_command(command: ModelCommand) {
    if let ModelCommand::Infer { response, .. } = command {
        let _ = response.send(Err(RuntimeError::Cancelled));
    }
}
