use std::{
    collections::HashMap,
    iter::FromIterator,
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

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
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
        std::thread::spawn(move || check_zombie());
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
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
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
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
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
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
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
        let peers: Vec<Value> = PeerConfig::peers(None)
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
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
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
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
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
        fn get_login_device_info();
        fn support_remove_wallpaper();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
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
