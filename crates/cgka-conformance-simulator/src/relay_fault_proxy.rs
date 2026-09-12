//! Real socket interruption in front of the harness-owned loopback relay.
//! All advertised relay URLs use this gate, so reconnect/discovery cannot bypass it.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

enum Command {
    SetAvailable(bool, oneshot::Sender<u64>),
}

pub(crate) struct RelayFaultProxy {
    address: SocketAddr,
    commands: mpsc::UnboundedSender<Command>,
    task: JoinHandle<()>,
    rejected: Arc<AtomicU64>,
}

struct ActiveConnection(Arc<AtomicU64>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// Restores the listener even when an interrupted scenario future is cancelled.
struct RestoreAvailability(mpsc::UnboundedSender<Command>);

impl Drop for RestoreAvailability {
    fn drop(&mut self) {
        let (reply, _) = oneshot::channel();
        let _ = self.0.send(Command::SetAvailable(true, reply));
    }
}

impl RelayFaultProxy {
    pub(crate) async fn start(upstream: SocketAddr) -> io::Result<Self> {
        if !upstream.ip().is_loopback() {
            return Err(io::Error::other(
                "relay fault proxy requires a loopback upstream",
            ));
        }
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (commands, mut receiver) = mpsc::unbounded_channel();
        let active = Arc::new(AtomicU64::new(0));
        let rejected = Arc::new(AtomicU64::new(0));
        let rejected_task = rejected.clone();
        let task = tokio::spawn(async move {
            let mut available = true;
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    command = receiver.recv() => {
                        let Some(Command::SetAvailable(next, reply)) = command else { break };
                        available = next;
                        let closed = if available { 0 } else { active.load(Ordering::SeqCst) };
                        if !available {
                            sessions.abort_all();
                            while sessions.join_next().await.is_some() {}
                        }
                        let _ = reply.send(closed);
                    }
                    Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
                    accepted = listener.accept() => {
                        let Ok((mut downstream, _)) = accepted else { break };
                        if !available {
                            rejected_task.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        let active = active.clone();
                        sessions.spawn(async move {
                            // The exact harness-owned address is pinned above; no DNS or external dial.
                            let Ok(Ok(mut upstream)) = tokio::time::timeout(
                                Duration::from_secs(5), TcpStream::connect(upstream),
                            ).await else { return };
                            active.fetch_add(1, Ordering::SeqCst);
                            let _active = ActiveConnection(active);
                            let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
                        });
                    }
                }
            }
            sessions.abort_all();
            while sessions.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            commands,
            task,
            rejected,
        })
    }

    pub(crate) fn url(&self) -> String {
        format!("ws://{}/", self.address)
    }

    async fn set_available(&self, available: bool) -> io::Result<u64> {
        let (reply, received) = oneshot::channel();
        self.commands
            .send(Command::SetAvailable(available, reply))
            .map_err(|_| io::Error::other("relay fault proxy stopped"))?;
        received
            .await
            .map_err(|_| io::Error::other("relay fault proxy stopped"))
    }

    /// Returns the number of established connections actually cut and new
    /// connections rejected during the outage. Participants remain running.
    pub(crate) async fn interrupt(&self, duration: Duration) -> io::Result<(u64, u64)> {
        let restore = RestoreAvailability(self.commands.clone());
        let before = self.rejected.load(Ordering::SeqCst);
        let closed = self.set_available(false).await?;
        tokio::time::sleep(duration).await;
        self.set_available(true).await?;
        drop(restore);
        Ok((
            closed,
            self.rejected.load(Ordering::SeqCst).saturating_sub(before),
        ))
    }
}

impl Drop for RelayFaultProxy {
    fn drop(&mut self) {
        self.task.abort(); // Dropping the listener task also aborts its JoinSet.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn interruption_closes_live_sockets_and_restores_new_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    Ok((mut stream, _)) = listener.accept() => {
                        tasks.spawn(async move {
                            let (mut reader, mut writer) = stream.split();
                            let _ = tokio::io::copy(&mut reader, &mut writer).await;
                        });
                    }
                    Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        let proxy = RelayFaultProxy::start(upstream).await.unwrap();
        let mut first = TcpStream::connect(proxy.address).await.unwrap();
        first.write_all(b"a").await.unwrap();
        assert_eq!(first.read_u8().await.unwrap(), b'a');
        let (closed, _) = proxy.interrupt(Duration::from_millis(20)).await.unwrap();
        assert_eq!(closed, 1);
        assert!(
            tokio::time::timeout(Duration::from_secs(1), first.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        let mut second = TcpStream::connect(proxy.address).await.unwrap();
        second.write_all(b"b").await.unwrap();
        assert_eq!(second.read_u8().await.unwrap(), b'b');

        // A cancellation must not strand subsequent scenarios behind an outage.
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                proxy.interrupt(Duration::from_secs(30)),
            )
            .await
            .is_err()
        );
        let mut third = TcpStream::connect(proxy.address).await.unwrap();
        third.write_all(b"c").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), third.read_u8())
                .await
                .unwrap()
                .unwrap(),
            b'c'
        );

        proxy.set_available(false).await.unwrap();
        let mut rejected = TcpStream::connect(proxy.address).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), rejected.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        assert_eq!(proxy.rejected.load(Ordering::SeqCst), 1);
        proxy.set_available(true).await.unwrap();
        echo.abort();
    }
}
