use std::fmt;

use serde::{Deserialize, Serialize};

pub const MAX_CALLER_CREDENTIAL_LENGTH: usize = 256;

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CallerCredential(String);

impl CallerCredential {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.0.is_empty() && self.0.len() <= MAX_CALLER_CREDENTIAL_LENGTH
    }
}

impl fmt::Debug for CallerCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

macro_rules! identifier {
    ($name:ident) => {
        #[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            #[must_use]
            pub fn new(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self::new(value)
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self::new(value)
            }
        }
    };
}

identifier!(CallerId);
identifier!(ApprovalId);
identifier!(GrantId);
identifier!(IdempotencyKey);
identifier!(ProjectId);
identifier!(RequestId);
