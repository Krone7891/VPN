//! Fliessband fuer eine Verbindung: TLS/WebSocket laufen in eigenen Tasks, getrennt von Verschluesselung (AEAD)
//! und TUN. So arbeiten je Richtung zwei Kerne gleichzeitig (z. B. Kern 1 verschluesselt das naechste Buendel,
//! waehrend Kern 2 das vorige per TLS verschickt). Wartende Nachrichten werden gesammelt und mit einem einzigen
//! flush verschickt (weniger Systemaufrufe, groessere TLS-Pakete).

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

/// Task, der beim Wegwerfen beendet wird
pub struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sende-Stufe. Liefert den Eingang und den Grund, falls das Senden scheiterte.
pub fn writer<S>(mut sink: S, tiefe: usize) -> (mpsc::Sender<Vec<u8>>, Arc<Mutex<String>>, Task)
where
    S: Sink<Message> + Unpin + Send + 'static,
    S::Error: std::fmt::Display,
{
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(tiefe);
    let fehler = Arc::new(Mutex::new(String::new()));
    let f = fehler.clone();
    let t = tokio::spawn(async move {
        let r: Result<(), String> = async {
            let txt = |e: S::Error| e.to_string();
            while let Some(b) = rx.recv().await {
                sink.feed(Message::Binary(b.into())).await.map_err(txt)?;
                // was schon wartet, gleich mitnehmen (ein flush fuer alle)
                for _ in 0..32 {
                    match rx.try_recv() {
                        Ok(b) => sink.feed(Message::Binary(b.into())).await.map_err(txt)?,
                        Err(_) => break,
                    }
                }
                sink.flush().await.map_err(txt)?;
            }
            Ok(())
        }
        .await;
        if let Err(e) = r {
            *f.lock().unwrap() = e;
        }
        let _ = sink.close().await;
    });
    (tx, fehler, Task(t))
}

/// was die Empfangs-Stufe liefert
pub enum Rein {
    Daten(Vec<u8>),
    /// Gegenseite hat ordentlich beendet
    Ende,
    Fehler(String),
}

/// Empfangs-Stufe: liest WebSocket-Nachrichten (TLS entschluesseln) und reicht Binaerdaten weiter.
pub fn reader<St, E>(mut stream: St, tiefe: usize) -> (mpsc::Receiver<Rein>, Task)
where
    St: Stream<Item = Result<Message, E>> + Unpin + Send + 'static,
    E: std::fmt::Display,
{
    let (tx, rx) = mpsc::channel::<Rein>(tiefe);
    let t = tokio::spawn(async move {
        loop {
            let r = match stream.next().await {
                Some(Ok(Message::Binary(b))) => Rein::Daten(b.into()),
                Some(Ok(Message::Close(_))) | None => Rein::Ende,
                Some(Ok(_)) => continue,
                Some(Err(e)) => Rein::Fehler(e.to_string()),
            };
            let schluss = !matches!(r, Rein::Daten(_));
            if tx.send(r).await.is_err() || schluss {
                return;
            }
        }
    });
    (rx, Task(t))
}
