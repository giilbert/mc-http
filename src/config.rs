use std::{collections::HashMap, path::PathBuf, sync::Arc};

use anyhow::Context;
use arc_swap::{ArcSwap, Guard};
use notify::{
    RecursiveMode, Watcher,
    event::{AccessKind, AccessMode},
};

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct Config {
    data: Arc<ArcSwap<ConfigData>>,
    _watcher: Arc<notify::RecommendedWatcher>,
}

impl Config {
    /// Get a reference to the current configuration data.
    pub fn data(&self) -> Guard<Arc<ConfigData>> {
        self.data.load()
    }
}

#[derive(serde::Deserialize, Debug)]
pub struct ConfigData {
    /// Port which the proxy listens on
    pub port: u16,
    /// Default server address to forward to.
    pub default: Arc<str>,
    /// Mapping from hostname to Minecraft server address.
    ///
    /// If the hostname is not mapped to or if the handshake is unrecognized, the proxy will forward
    /// it to the `default` server.
    pub servers: HashMap<String, Arc<str>>,
}

impl Config {
    /// Load configuration from the given path.
    pub fn load(path: &PathBuf) -> anyhow::Result<Self> {
        let data = Arc::new(ArcSwap::from_pointee(
            toml::from_str(&std::fs::read_to_string(&path).context("failed to read config.toml")?)
                .context("failed to parse config.toml")?,
        ));

        let path_clone = path.clone();
        let data_clone = data.clone();
        let mut notify =
            notify::recommended_watcher(move |ev: Result<notify::Event, notify::Error>| {
                let ev = match ev {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::error!("error watching config file: {:?}", e);
                        return;
                    }
                };

                if let notify::EventKind::Access(AccessKind::Close(AccessMode::Write)) = ev.kind {
                    tracing::info!("detected change to config file, reloading...");
                    match std::fs::read_to_string(&path_clone)
                        .context("failed to read config.toml")
                        .and_then(|s| toml::from_str(&s).context("failed to parse config.toml"))
                    {
                        Ok(new_data) => {
                            tracing::info!("successfully reloaded config file: {:?}", new_data);
                            data_clone.store(Arc::new(new_data));
                        }
                        Err(e) => {
                            tracing::error!("failed to reload config file: {:?}", e);
                        }
                    }
                }
            })
            .context("failed to create file watcher")?;

        notify
            .watch(path, RecursiveMode::NonRecursive)
            .context("failed to watch config file")?;

        tracing::info!("watching config file for changes: {:?}", path);

        Ok(Config {
            data,
            _watcher: Arc::new(notify),
        })
    }
}
