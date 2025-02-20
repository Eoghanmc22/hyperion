use evenio::prelude::*;
use tracing::instrument;
use valence_protocol::VarInt;

use crate::{singleton::encoder::Broadcast, KillAllEntities, MinecraftEntity, Player};

#[instrument(skip_all)]
pub fn kill_all(
    _r: ReceiverMut<KillAllEntities>,
    entities: Fetcher<(EntityId, &MinecraftEntity, Not<&Player>)>,
    broadcast: Single<&mut Broadcast>,
    mut s: Sender<Despawn>,
) {
    let ids = entities.iter().map(|(id, ..)| id).collect::<Vec<_>>();

    #[expect(clippy::cast_possible_wrap, reason = "wrapping is ok in this case")]
    let entity_ids = ids.iter().map(|id| VarInt(id.index().0 as i32)).collect();

    let despawn_packet = valence_protocol::packets::play::EntitiesDestroyS2c { entity_ids };

    broadcast
        .0
        .get_round_robin()
        .append_packet(&despawn_packet)
        .unwrap();

    for id in ids {
        s.send(Despawn(id));
    }
}
