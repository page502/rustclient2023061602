use std::{
    collections::HashMap,
    iter::FromIterator,
    process::Child,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;
#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
    static ref CHILDREN : Children = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        #[cfg(feature = "appimage")]
        let prefix = std::env::var("APPDIR").unwrap_or("".to_string());
        #[cfg(not(feature = "appimage"))]
        let prefix = "".to_string();
        #[cfg(feature = "flatpak")]
        let dir = "/app";
        #[cfg(not(feature = "flatpak"))]
        let dir = "/usr";
        sciter::set_library(&(prefix + dir + "/lib/rustdesk/libsciter-gtk.so")).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    #[cfg(all(windows, not(feature = "inline")))]
    unsafe {
        winapi::um::shellscalingapi::SetProcessDpiAwareness(2);
    }
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        let children: Children = Default::default();
        std::thread::spawn(move || check_zombie(children));
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let cmd = iter.next().unwrap().clone();
        let id = iter.next().unwrap().clone();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> = serde_json::from_str(&get_options()).unwrap();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_rdp_service_open(&self) -> bool {
        is_rdp_service_open()
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.0);
        v.push(x.1);
        v.push(x.3);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers()
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(id)
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_rdp_service_open();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

pub fn check_zombie(children: Children) {
    let mut deads = Vec::new();
    loop {
        let mut lock = children.lock().unwrap();
        let mut n = 0;
        for (id, c) in lock.1.iter_mut() {
            if let Ok(Some(_)) = c.try_wait() {
                deads.push(id.clone());
                n += 1;
            }
        }
        for ref id in deads.drain(..) {
            lock.1.remove(id);
        }
        if n > 0 {
            lock.0 = true;
        }
        drop(lock);
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[inline]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
