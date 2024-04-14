use std::net::ToSocketAddrs;

use anyhow::Context;
use evenio::component::Component;
use rayon_local::RayonLocal;

use crate::net::Server;

#[derive(Component)]
pub struct Networking {
    rayon_local: RayonLocal<Server>,
}

impl Networking {
    /// Creates a new [`Self`] with the given compression level.
    pub fn new(address: impl ToSocketAddrs) -> anyhow::Result<Self> {
        // FIXME: Do something similar to std's TcpListener
        let address = address
            .to_socket_addrs()
            .context("Resolve address")?
            .next()
            .context("Get address")?;

        Ok(Self {
            rayon_local: RayonLocal::init_with(|| Server::new(address))?,
        })
    }

    /// Get thread local [`Server`]
    pub fn get(&self) -> &Server {
        self.rayon_local.get_rayon_local()
    }

    /// Returns a reference to an [`Server`] usually local to a rayon thread based on a
    /// round robin policy.
    /// This is so that requests can evenly be spread out across threads.
    pub fn get_round_robin(&mut self) -> &mut Server {
        self.rayon_local.get_local_round_robin()
    }

    /// Get mutable access to all thread-local [`Server`]s
    pub fn get_all(&mut self) -> &mut [Server] {
        self.rayon_local.get_all_locals()
    }
}
