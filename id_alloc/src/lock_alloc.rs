use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicU32, AtomicUsize, Ordering},
        Arc,
    },
};

use opool::{Pool, PoolAllocator};

use crate::{IPOps, Ipv4A};

/// Alloc IPs by Lock pool
///

pub struct Allocator<IP: IPOps> {
    interval: IP,
    counter: AtomicU32,
}

impl<IP: IPOps> PoolAllocator<IP> for Allocator<IP> {
    fn allocate(&self) -> IP {
        IP::cast(&self.interval, self.counter.fetch_add(1, Ordering::SeqCst).into())
    }
}

#[derive(Clone)]
pub struct Alloc<IP: IPOps> {
    pub pool: Arc<Pool<Allocator<IP>, IP>>,
    pub interval: IP,
}

impl<IP: IPOps> Alloc<IP> {
    pub fn init(interval: IP, cap: usize) -> Self {
        Self {
            pool: Arc::new(Pool::new_prefilled(
                cap,
                Allocator {
                    interval: interval.clone(),
                    counter: Default::default(),
                },
            )),
            interval,
        }
    }
}
