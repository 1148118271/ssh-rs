mod backend;
mod local;

pub(crate) use backend::Channel as BackendChannel;
pub use backend::{ChannelBroker, ExecBroker, ScpBroker, ShellBrocker};

pub(crate) use local::Channel as LocalChannel;
pub use local::ChannelExec as LocalExec;
pub use local::ChannelScp as LocalScp;
pub use local::ChannelShell as LocalShell;
