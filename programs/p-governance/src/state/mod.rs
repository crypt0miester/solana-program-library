//! Program accounts

use pinocchio_utils_macro::define_is_enum_trait;

pub mod enums;
pub mod governance;
pub mod legacy;
pub mod native_treasury;
pub mod program_metadata;
pub mod proposal;
pub mod proposal_deposit;
pub mod proposal_transaction;
pub mod proposal_transaction_buffer;
pub mod proposal_versioned_transaction;
pub mod realm;
pub mod realm_config;
pub mod required_signatory;
pub mod signatory_record;
pub mod token_owner_record;
pub mod vote_record;
pub mod p_bpf_loader_upgradeable;
pub mod p_address_lookup_table;

define_is_enum_trait!();