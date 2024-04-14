use evenio::{event::Receiver, fetch::Single};
use rayon::iter::{IntoParallelRefMutIterator, ParallelIterator};
use tracing::{info, instrument};

use crate::{net::ServerEvent, singleton::networking::Networking, DoIoUring};

// #[instrument(skip_all, level = "trace")]
pub fn handle_io_uring_completions(
    _: Receiver<DoIoUring>,
    mut networking: Single<&mut Networking>,
    // global: Single<&Global>,
    // id_lookup: Single<&PlayerIdLookup>,
    // mut fetcher: Fetcher<(EntityId, &mut Player, &mut FullEntityPose)>,
    // lookup: Single<&PlayerUuidLookup>,
    // mut sender: IngressSender,
) {
    networking.get_all().par_iter_mut().map(|server| {
        server.fetch_new_events();

        server.handle_events(|event| match event {
            ServerEvent::AddPlayer { fd } => {
                info!("got a player with fd {}", fd.0);
            }
            ServerEvent::RemovePlayer { fd } => {
                info!("removed a player with fd {}", fd.0);
            }
            ServerEvent::Receive { fd, buffer } => todo!(),
        })
    });
}

// #[instrument(skip_all, level = "trace")]
pub fn submit_io_uring_events(_: Receiver<DoIoUring>, mut networking: Single<&mut Networking>) {
    networking.get_all().par_iter_mut().for_each(|server| {
        server.submit_events();
    });
}
