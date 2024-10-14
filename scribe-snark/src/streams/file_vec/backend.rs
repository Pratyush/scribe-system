#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::AVec;
#[cfg(target_os = "linux")]
pub use linux::InnerFile;

#[cfg(not(target_os = "linux"))]
mod default;
#[cfg(not(target_os = "linux"))]
pub use default::AVec;
#[cfg(not(target_os = "linux"))]
pub use default::InnerFile;
