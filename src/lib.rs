#[cfg(not(feature = "wasi_support"))]
mod unix;

#[cfg(not(feature = "wasi_support"))]
pub use unix::*;

#[cfg(feature = "wasi_support")]
mod wasi;

#[cfg(feature = "wasi_support")]
pub use wasi::*;
