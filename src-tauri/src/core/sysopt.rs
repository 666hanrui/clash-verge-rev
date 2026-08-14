use crate::{
    config::{Config, IVerge},
    singleton,
};
use anyhow::Result;
use clash_verge_logging::{Type, logging};
use parking_lot::RwLock;
use scopeguard::defer;
use smartstring::alias::String;
use std::{
    process::Command,
    string::String as StdString,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use sysproxy::{Autoproxy, GuardMonitor, GuardType, Sysproxy};
use tokio::sync::Mutex as TokioMutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyApplyStep {
    Sysproxy,
    Autoproxy,
}

const fn proxy_apply_steps(sys_enabled: bool, auto_enabled: bool) -> [ProxyApplyStep; 2] {
    // Disabling PAC clears WinINET proxy flags on Windows, so pure global
    // proxy mode must clear PAC before enabling Sysproxy.
    if sys_enabled && !auto_enabled {
        [ProxyApplyStep::Autoproxy, ProxyApplyStep::Sysproxy]
    } else {
        [ProxyApplyStep::Sysproxy, ProxyApplyStep::Autoproxy]
    }
}

pub struct Sysopt {
    update_lock: TokioMutex<()>,
    reset_sysproxy: AtomicBool,
    inner_proxy: Arc<RwLock<(Sysproxy, Autoproxy)>>,
    guard: Arc<RwLock<GuardMonitor>>,
}

impl Default for Sysopt {
    fn default() -> Self {
        Self {
            update_lock: TokioMutex::new(()),
            reset_sysproxy: AtomicBool::new(false),
            inner_proxy: Arc::new(RwLock::new((Sysproxy::default(), Autoproxy::default()))),
            guard: Arc::new(RwLock::new(GuardMonitor::new(GuardType::None, Duration::from_secs(30)))),
        }
    }
}

#[cfg(target_os = "windows")]
static DEFAULT_BYPASS: &str = "localhost;127.*;192.168.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;<local>";
#[cfg(target_os = "linux")]
static DEFAULT_BYPASS: &str = "localhost,127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,::1";
#[cfg(target_os = "macos")]
static DEFAULT_BYPASS: &str =
    "127.0.0.1,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,*.crashlytics.com,<local>";

async fn get_bypass() -> String {
    let verge = Config::verge().await.latest_arc();
    let use_default = verge.use_default_bypass.unwrap_or(true);
    let custom_bypass = verge.system_proxy_bypass.as_deref().unwrap_or("");

    if custom_bypass.is_empty() {
        DEFAULT_BYPASS.into()
    } else if use_default {
        format!("{DEFAULT_BYPASS},{custom_bypass}").into()
    } else {
        custom_bypass.into()
    }
}

#[cfg(target_os = "macos")]
fn shell_single_quote(value: &str) -> StdString {
    format!("'{}'", value.replace('\'', r"'\\''"))
}

#[cfg(target_os = "macos")]
fn escape_osascript_double_quoted_string(value: &str) -> StdString {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// `networksetup` changes require administrator rights on current macOS
/// versions. Resolve the active service first, then request authorization once
/// for the complete update instead of exposing its raw permission error to the
/// user (or asking once for every HTTP/SOCKS/PAC command).
#[cfg(target_os = "macos")]
fn active_network_service() -> Result<StdString> {
    let route = Command::new("/sbin/route").args(["-n", "get", "default"]).output()?;
    let route_output = StdString::from_utf8_lossy(&route.stdout);
    let route_device = route_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface: "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    // A local TUN/VPN becomes the default route on macOS. It has no
    // `networksetup` service of its own, so select the first physical network
    // interface reported by scutil instead (for example en0 / Wi-Fi).
    let device = match route_device.filter(|value| !value.starts_with("utun")) {
        Some(device) => device,
        None => {
            let nwi = Command::new("/usr/sbin/scutil").arg("--nwi").output()?;
            let nwi_output = StdString::from_utf8_lossy(&nwi.stdout);
            nwi_output
                .lines()
                .find_map(|line| line.trim().strip_prefix("Network interfaces: "))
                .and_then(|interfaces| {
                    interfaces
                        .split_whitespace()
                        .find(|interface| !interface.starts_with("utun"))
                })
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("无法识别当前物理网络接口"))?
        }
    };

    let services = Command::new("/usr/sbin/networksetup")
        .arg("-listnetworkserviceorder")
        .output()?;
    let service_output = StdString::from_utf8_lossy(&services.stdout);
    let lines = service_output.lines().collect::<Vec<_>>();
    let marker = format!("Device: {device})");

    for (index, line) in lines.iter().enumerate() {
        if !line.contains(&marker) {
            continue;
        }
        if let Some(name) = lines[..index].iter().rev().find_map(|candidate| {
            let candidate = candidate.trim();
            if !candidate.starts_with('(') || candidate.starts_with("(Hardware Port:") {
                return None;
            }
            candidate
                .find(')')
                .map(|end| candidate[end + 1..].trim())
                .filter(|name| !name.is_empty())
                .map(str::to_owned)
        }) {
            return Ok(name);
        }
    }

    Err(anyhow::anyhow!("无法找到默认网络接口 {device} 对应的网络服务"))
}

#[cfg(target_os = "macos")]
fn apply_macos_proxy_with_authorization(sys: &Sysproxy, auto: &Autoproxy) -> Result<()> {
    let service = active_network_service()?;
    let setup = "/usr/sbin/networksetup";
    let mut commands: Vec<StdString> = Vec::new();
    let mut push = |args: Vec<StdString>| {
        commands.push(
            std::iter::once(StdString::from(setup))
                .chain(args)
                .map(|value| shell_single_quote(&value))
                .collect::<Vec<_>>()
                .join(" "),
        );
    };

    push(vec![
        "-setautoproxyurl".into(),
        service.clone(),
        if auto.url.is_empty() {
            "".into()
        } else {
            auto.url.clone()
        },
    ]);
    push(vec![
        "-setautoproxystate".into(),
        service.clone(),
        if auto.enable { "on".into() } else { "off".into() },
    ]);
    for (set_command, state_command) in [
        ("-setsocksfirewallproxy", "-setsocksfirewallproxystate"),
        ("-setsecurewebproxy", "-setsecurewebproxystate"),
        ("-setwebproxy", "-setwebproxystate"),
    ] {
        push(vec![
            set_command.into(),
            service.clone(),
            sys.host.to_string(),
            sys.port.to_string(),
        ]);
        push(vec![
            state_command.into(),
            service.clone(),
            if sys.enable { "on".into() } else { "off".into() },
        ]);
    }
    let mut bypass: Vec<StdString> = vec!["-setproxybypassdomains".into(), service];
    bypass.extend(
        sys.bypass
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
    );
    push(bypass);

    let shell = escape_osascript_double_quoted_string(&commands.join("; "));
    let prompt =
        escape_osascript_double_quoted_string("Clash Hev needs administrator permission to update the system proxy");
    let script = format!(r#"do shell script "{shell}" with administrator privileges with prompt "{prompt}""#,);
    let output = Command::new("/usr/bin/osascript").args(["-e", &script]).output()?;
    if output.status.success() {
        return Ok(());
    }
    let detail = StdString::from_utf8_lossy(&output.stderr).trim().to_owned();
    anyhow::bail!("系统代理授权未完成: {detail}")
}

singleton!(Sysopt, SYSOPT);

impl Sysopt {
    fn new() -> Self {
        Self::default()
    }

    fn access_guard(&self) -> Arc<RwLock<GuardMonitor>> {
        Arc::clone(&self.guard)
    }

    pub async fn refresh_guard(&self) {
        logging!(info, Type::Core, "Refreshing system proxy guard...");
        let verge = Config::verge().await.latest_arc();
        if !verge.enable_system_proxy.unwrap_or_default() {
            logging!(info, Type::Core, "System proxy is disabled.");
            self.access_guard().write().stop();
            return;
        }
        if !verge.enable_proxy_guard.unwrap_or_default() {
            logging!(info, Type::Core, "System proxy guard is disabled.");
            self.access_guard().write().stop();
            return;
        }
        logging!(
            info,
            Type::Core,
            "Updating system proxy with duration: {} seconds",
            verge.proxy_guard_duration.unwrap_or(30)
        );
        {
            let guard = self.access_guard();
            guard
                .write()
                .set_interval(Duration::from_secs(verge.proxy_guard_duration.unwrap_or(30)));
        }
        logging!(info, Type::Core, "Starting system proxy guard...");
        {
            let guard = self.access_guard();
            guard.write().start();
        }
    }

    /// Wait for any in-progress `update_sysproxy` to finish, so that a
    /// subsequent read of OS-level sysproxy state sees a fully applied
    /// configuration instead of a partially-applied one (e.g. SOCKS already
    /// disabled but HTTP still enabled mid-transition).
    pub async fn wait_idle(&self) {
        let _ = self.update_lock.lock().await;
    }

    /// init the sysproxy
    pub async fn update_sysproxy(&self) -> Result<()> {
        let _lock = self.update_lock.lock().await;

        let verge = Config::verge().await.latest_arc();
        let default_port = Config::clash().await.latest_arc().get_mixed_port();
        let selected_listener = verge.system_proxy_listener.as_deref().and_then(|name| {
            verge.multi_proxy_listeners.as_ref().and_then(|listeners| {
                listeners.iter().find(|listener| {
                    listener.name == name
                        && listener.enabled.unwrap_or(true)
                        && matches!(listener.r#type.as_str(), "mixed" | "http")
                })
            })
        });
        let port = selected_listener
            .map(|listener| listener.port)
            .or(verge.verge_mixed_port)
            .unwrap_or(default_port);
        let proxy_host = selected_listener
            .and_then(|listener| listener.listen.as_deref())
            .or(verge.proxy_host.as_deref())
            .unwrap_or("127.0.0.1");
        let pac_port = IVerge::get_singleton_port();
        // 先 await, 避免持有锁导致的 Send 问题
        let bypass = get_bypass().await;

        let (sys_enable, pac_enable, proxy_host, proxy_guard) = (
            verge.enable_system_proxy.unwrap_or_default(),
            verge.proxy_auto_config.unwrap_or_default(),
            proxy_host,
            verge.enable_proxy_guard.unwrap_or_default(),
        );

        let (sys, auto, guard_type) = {
            let (sys, auto) = &mut *self.inner_proxy.write();
            sys.host = proxy_host.into();
            sys.port = port;
            sys.bypass = bypass.into();
            auto.url = format!("http://{proxy_host}:{pac_port}/commands/pac");

            // `enable_system_proxy` is the master switch.
            // When disabled, force clear both global proxy and PAC at OS level.
            let guard_type = if !sys_enable {
                sys.enable = false;
                auto.enable = false;
                GuardType::None
            } else if pac_enable {
                sys.enable = false;
                auto.enable = true;
                if proxy_guard {
                    GuardType::Autoproxy(auto.clone())
                } else {
                    GuardType::None
                }
            } else {
                sys.enable = true;
                auto.enable = false;
                if proxy_guard {
                    GuardType::Sysproxy(sys.clone())
                } else {
                    GuardType::None
                }
            };

            (sys.clone(), auto.clone(), guard_type)
        };

        self.access_guard().write().set_guard_type(guard_type);

        let apply_steps = proxy_apply_steps(sys.enable, auto.enable);

        tokio::task::spawn_blocking(move || -> Result<()> {
            let apply_result = (|| -> sysproxy::Result<()> {
                for step in apply_steps {
                    match step {
                        ProxyApplyStep::Autoproxy => auto.set_auto_proxy()?,
                        ProxyApplyStep::Sysproxy => sys.set_system_proxy()?,
                    }
                }
                Ok(())
            })();

            #[cfg(target_os = "macos")]
            if sys_enable
                && matches!(
                    apply_result,
                    Err(sysproxy::Error::RequiresAdminPrivileges | sysproxy::Error::NetworkInterface)
                )
            {
                return apply_macos_proxy_with_authorization(&sys, &auto);
            }

            apply_result.map_err(Into::into)
        })
        .await??;

        Ok(())
    }

    /// reset the sysproxy
    pub async fn reset_sysproxy(&self) -> Result<()> {
        if self
            .reset_sysproxy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Ok(());
        }
        defer! {
            self.reset_sysproxy.store(false, Ordering::SeqCst);
        }

        // close proxy guard
        self.access_guard().write().set_guard_type(GuardType::None);

        // 直接关闭所有代理
        let (sys, auto) = {
            let (sys, auto) = &mut *self.inner_proxy.write();
            sys.enable = false;
            auto.enable = false;
            (sys.clone(), auto.clone())
        };

        tokio::task::spawn_blocking(move || -> Result<()> {
            sys.set_system_proxy()?;
            auto.set_auto_proxy()?;
            Ok(())
        })
        .await??;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxyApplyStep, proxy_apply_steps};

    #[test]
    fn pure_sysproxy_mode_clears_pac_before_enabling_global_proxy() {
        assert_eq!(
            proxy_apply_steps(true, false),
            [ProxyApplyStep::Autoproxy, ProxyApplyStep::Sysproxy]
        );
    }

    #[test]
    fn pac_mode_clears_global_proxy_before_enabling_pac() {
        assert_eq!(
            proxy_apply_steps(false, true),
            [ProxyApplyStep::Sysproxy, ProxyApplyStep::Autoproxy]
        );
    }

    #[test]
    fn disabled_mode_clears_global_proxy_before_pac() {
        assert_eq!(
            proxy_apply_steps(false, false),
            [ProxyApplyStep::Sysproxy, ProxyApplyStep::Autoproxy]
        );
    }
}
