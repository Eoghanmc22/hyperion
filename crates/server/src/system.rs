mod clean_up_io;
mod egress_broadcast;
mod egress_local;
mod entity_detect_collisions;
mod entity_move_logic;
mod ingress;
mod init_entity;
mod init_player;
mod keep_alive;
mod kill_all;
mod pkt_hand_swing;
mod player_join_world;
mod player_kick;
mod rebuild_player_location;
mod reset_bounding_boxes;
mod stats_message;
mod update_time;

pub use clean_up_io::clean_up_io;
pub use egress_broadcast::egress_broadcast;
pub use egress_local::egress_local;
pub use entity_detect_collisions::entity_detect_collisions;
pub use entity_move_logic::entity_move_logic;
use evenio::event::Sender;
pub use ingress::ingress;
pub use init_entity::init_entity as entity_spawn;
pub use init_player::init_player;
pub use keep_alive::keep_alive;
pub use kill_all::kill_all;
pub use pkt_hand_swing::pkt_hand_swing;
pub use player_join_world::player_join_world;
pub use player_kick::player_kick;
pub use rebuild_player_location::rebuild_player_location;
pub use reset_bounding_boxes::reset_bounding_boxes;
pub use stats_message::stats_message;
pub use update_time::update_time;

use crate::{InitEntity, KickPlayer, KillAllEntities, SwingArm};

pub type IngressSender<'a> = Sender<'a, (KickPlayer, InitEntity, KillAllEntities, SwingArm)>;
