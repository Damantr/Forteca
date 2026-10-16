use crate::modsecurity::{
    engine::{self, ModSecurity},
    inspect_headers,
    rules::{self, Rules},
    transaction::{Transaction, WafDecision},
};
use tokio::sync::{broadcast::Receiver, mpsc, oneshot};

pub struct WafRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(Vec<u8>, Vec<u8>)>,
}

pub struct WafJob {
    request: WafRequest,
    reply: oneshot::Sender<Result<WafDecision, String>>,
}

#[derive(Clone)]
pub struct WafClient {
    sender: mpsc::Sender<WafJob>,
}

impl WafClient {
    pub fn start() -> Result<Self, String> {
        let (sender, mut reciver) = mpsc::channel::<WafJob>(256);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        std::thread::spawn(move || {
            let init = (|| -> Result<_, String> {
                let engine = ModSecurity::new()?;
                let mut rules = Rules::new()?;

                rules.add_file("src/rules/modsecurity.conf")?;
                rules.add_file("src/rules/custom.conf")?;

                Ok((engine, rules))
            })();

            match init {
                Ok((engine, rules)) => {
                    let _ = ready_tx.send(Ok(()));

                    while let Some(job) = reciver.blocking_recv() {
                        let request = job.request;

                        let result = inspect_headers(
                            &engine,
                            &rules,
                            &request.method,
                            &request.uri,
                            &request.version,
                            &request.headers,
                        );

                        let _ = job.reply.send(result);
                    }
                }
                Err(error) => {
                    let _ = ready_tx.send(Err(error));
                }
            }
        });

        ready_rx.recv().map_err(|e| e.to_string())??;

        Ok(Self { sender })
    }
    pub async fn inspect(&self, request: WafRequest) -> Result<WafDecision, String> {
        let (reply_tx, reply_rx) = oneshot::channel();

        self.sender
            .send(WafJob {
                request,
                reply: reply_tx,
            })
            .await
            .map_err(|e| e.to_string())?;

        reply_rx.await.map_err(|e| e.to_string())?
    }
}
