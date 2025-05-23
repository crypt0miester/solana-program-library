#![allow(clippy::arithmetic_side_effects)]
#![deny(missing_docs)]
//! A Governance program for the Solana blockchain.

pub mod addins;
pub mod entrypoint;
pub mod error;
pub mod instruction;
pub mod processor;
pub mod state;
pub mod tools;
use core::mem::MaybeUninit;

/// Seed prefix for Governance  PDAs
/// Note: This prefix is used for the initial set of PDAs and shouldn't be used
/// for any new accounts All new PDAs should use a unique prefix to guarantee
/// uniqueness for each account
pub const PROGRAM_AUTHORITY_SEED: &[u8] = b"governance";



const UNINIT_BYTE: MaybeUninit<u8> = MaybeUninit::<u8>::uninit();

#[inline(always)]
fn write_bytes(destination: &mut [MaybeUninit<u8>], source: &[u8]) {
    for (d, s) in destination.iter_mut().zip(source.iter()) {
        d.write(*s);
    }
}