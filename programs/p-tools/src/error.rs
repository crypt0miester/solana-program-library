//! Error types

use {
    num_derive::FromPrimitive,
    num_traits::FromPrimitive,
    pinocchio::program_error::ProgramError,
    pinocchio_log::log,
    thiserror::Error,
};

/// Errors that may be returned by the GovernanceTools
#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum GovernanceToolsError {
    /// Account already initialized
    #[error("Account already initialized")]
    AccountAlreadyInitialized = 1100,

    /// Account doesn't exist
    #[error("Account doesn't exist")]
    AccountDoesNotExist, // 1101

    /// Invalid account owner
    #[error("Invalid account owner")]
    InvalidAccountOwner, // 1102

    /// Invalid account type
    #[error("Invalid account type")]
    InvalidAccountType,

    /// Invalid new account size
    #[error("Invalid new account size")]
    InvalidNewAccountSize,
}

pub trait DecodeError<E> {
    fn decode_custom_error_to_enum(custom: u32) -> Option<E>
    where
        E: FromPrimitive,
    {
        E::from_u32(custom)
    }
    fn type_of() -> &'static str;
}

pub trait PrintProgramError {
    fn print<E>(&self)
    where
        E: 'static + std::error::Error + DecodeError<E> + PrintProgramError + FromPrimitive;
}

impl PrintProgramError for GovernanceToolsError {
    fn print<E>(&self) {
        log!("GOVERNANCE-TOOLS-ERROR: {}", self.to_string().as_str());
    }
}

impl From<GovernanceToolsError> for ProgramError {
    fn from(e: GovernanceToolsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

impl<T> DecodeError<T> for GovernanceToolsError {
    fn type_of() -> &'static str {
        "Governance Tools Error"
    }
}
