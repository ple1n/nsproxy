use anyhow::Result;
use futures::stream::{AbortHandle, Abortable};
use std::sync::Mutex;
use std::{future::Future, time::Duration};
use tokio::runtime::Runtime;
use tokio::task::JoinSet;

use crate::aok;
pub fn block_on<F: Future + Send>(future: F) -> Result<F::Output>
where
    F::Output: Send,
{
    block_on_2(future, false)
}

static ASYNCRT: Mutex<Option<Runtime>> = Mutex::new(None);

pub fn block_on_2<K: Send, F: Future<Output = K> + Send>(
    future: F,
    multi: bool,
) -> Result<F::Output> {
    let mut rt = ASYNCRT.try_lock().expect("RT locked");
    if rt.is_none() {
        let mut rtb = if multi {
            tokio::runtime::Builder::new_multi_thread()
        } else {
            tokio::runtime::Builder::new_current_thread()
        };
        rtb.enable_all();
        *rt = Some(rtb.build()?);
    }
    let rt = rt.as_mut().unwrap();
    // TODO: run the tun2proxy in ANOTHER process. so it can be killed, to release the lock
    Ok(rt.block_on(future))
}

#[test]
fn consec() -> Result<()> {
    block_on_2(
        async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("1")
        },
        false,
    )?;
    block_on_2(async { println!("2") }, false)?;

    aok!()
}

#[test]
fn create() -> Result<()> {
    let mut rt = tokio::runtime::Builder::new_current_thread();
    rt.enable_all().build()?.block_on(async {
        println!("built rt");
    });

    block_on_2(
        async {
            tokio::time::sleep(Duration::from_secs(2)).await;
            println!("1")
        },
        true,
    )?;
    block_on_2(async { println!("2") }, false)?;

    aok!()
}
