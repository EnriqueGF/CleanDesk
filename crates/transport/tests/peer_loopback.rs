//! In-process WebRTC loopback: two `PeerConnection`s connect to each other with
//! no signaling server, exchanging offer/answer and trickling ICE candidates
//! directly, then a `Channel::Control` payload is sent A -> B and asserted at B.
//!
//! Host candidates over loopback let this connect even offline. If it proves
//! flaky in a constrained CI/sandbox (no usable UDP sockets, firewalled
//! loopback), gate it with `#[ignore]` — the serde test and compilation remain
//! the hard guarantees.

use bytes::Bytes;
use cleandesk_proto::message::SignalPayload;
use cleandesk_transport::{Channel, IceConfig, PeerConnection};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Forward every trickled ICE candidate from `rx` into `dst`.
fn spawn_forward(mut rx: mpsc::Receiver<SignalPayload>, dst: Arc<PeerConnection>) {
    tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if let SignalPayload::IceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
            } = payload
            {
                let _ = dst.add_ice_candidate(candidate, sdp_mid, sdp_mline_index).await;
            }
        }
    });
}

/// Send with a short retry window: once both peers report `Connected`, the
/// offerer's channel is open, but the answerer's matching channel may take a
/// moment to finish its DCEP open. Retrying absorbs that race.
async fn send_with_retry(pc: &PeerConnection, ch: Channel, data: Bytes) -> anyhow::Result<()> {
    let mut last_err = None;
    for _ in 0..50 {
        match pc.send(ch, data.clone()).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("send failed with no error recorded")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_offer_answer_trickle_and_send() -> anyhow::Result<()> {
    // A = offerer (creates the four data channels), B = answerer.
    let a = PeerConnection::new(IceConfig::default(), true).await?;
    let mut b = PeerConnection::new(IceConfig::default(), false).await?;

    // Take the single-shot receivers before sharing the connections into tasks.
    let mut b_incoming = b.incoming()?;
    let a_ice = a.ice_candidates()?;
    let b_ice = b.ice_candidates()?;

    // 1) SDP offer/answer exchange (relayed here by direct function calls).
    let offer = a.create_offer().await?;
    b.set_remote_description(offer, true).await?;
    let answer = b.create_answer().await?;
    a.set_remote_description(answer, false).await?;

    // Share the peers with the ICE-forwarding tasks.
    let a = Arc::new(a);
    let b = Arc::new(b);

    // 2) Trickle ICE both ways. Both remote descriptions are set, so
    //    `add_ice_candidate` will accept the candidates.
    spawn_forward(a_ice, b.clone());
    spawn_forward(b_ice, a.clone());

    // 3) Wait for both peers to reach the Connected state.
    tokio::time::timeout(Duration::from_secs(20), async {
        a.wait_connected().await?;
        b.wait_connected().await?;
        anyhow::Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for peers to connect"))??;

    // 4) Send a control payload A -> B and assert B receives it.
    let payload = Bytes::from_static(b"hola-cleandesk");
    send_with_retry(&a, Channel::Control, payload.clone()).await?;

    let (ch, data) = tokio::time::timeout(Duration::from_secs(5), b_incoming.recv())
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for inbound control message"))?
        .expect("incoming stream closed before a message arrived");

    assert_eq!(ch, Channel::Control);
    assert_eq!(&data[..], &payload[..]);

    assert!(tokio::time::timeout(Duration::from_millis(50), a.wait_closed()).await.is_err(), "live peer must not be reported closed");
    a.close().await?;
    tokio::time::timeout(Duration::from_secs(2), a.wait_closed()).await
        .expect("close notification must arrive even with the incoming receiver still held");
    b.close().await?;
    Ok(())
}
