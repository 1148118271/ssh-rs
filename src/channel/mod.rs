mod backend;
mod local;

pub(crate) use backend::Channel as BackendChannel;
pub use backend::ChannelExec as BackendExec;
pub use backend::ChannelScp as BackendScp;
pub use backend::ChannelShell as BackendShell;

pub(crate) use local::Channel as LocalChannel;
pub use local::ChannelExec as LocalExec;
pub use local::ChannelScp as LocalScp;
