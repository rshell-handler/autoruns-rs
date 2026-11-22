#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use std::collections::BTreeMap;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegEnumValueW, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_SET_VALUE, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
    Everything,
    Logon,
    Explorer,
    InternetExplorer,
    ScheduledTasks,
    Services,
    Drivers,
    Codecs,
    BootExecute,
    ImageHijacks,
    AppInit,
    KnownDlls,
    Winlogon,
    WinsockProviders,
    PrintMonitors,
    LsaProviders,
    NetworkProviders,
    Wmi,
    Office,
}

impl Category {
    fn label(&self) -> &'static str {
        match self {
            Category::Everything => "Everything",
            Category::Logon => "Logon",
            Category::Explorer => "Explorer",
            Category::InternetExplorer => "Internet Explorer",
            Category::ScheduledTasks => "Scheduled Tasks",
            Category::Services => "Services",
            Category::Drivers => "Drivers",
            Category::Codecs => "Codecs",
            Category::BootExecute => "Boot Execute",
            Category::ImageHijacks => "Image Hijacks",
            Category::AppInit => "AppInit",
            Category::KnownDlls => "Known DLLs",
            Category::Winlogon => "Winlogon",
            Category::WinsockProviders => "Winsock Providers",
            Category::PrintMonitors => "Print Monitors",
            Category::LsaProviders => "LSA Providers",
            Category::NetworkProviders => "Network Providers",
            Category::Wmi => "WMI",
            Category::Office => "Office",
        }
    }

    fn top_row() -> &'static [Category] {
        &[
            Category::AppInit,
            Category::KnownDlls,
            Category::Winlogon,
            Category::WinsockProviders,
            Category::PrintMonitors,
            Category::LsaProviders,
            Category::NetworkProviders,
            Category::Wmi,
            Category::Office,
        ]
    }

    fn bottom_row() -> &'static [Category] {
        &[
            Category::Everything,
            Category::Logon,
            Category::Explorer,
            Category::InternetExplorer,
            Category::ScheduledTasks,
            Category::Services,
            Category::Drivers,
            Category::Codecs,
            Category::BootExecute,
            Category::ImageHijacks,
        ]
    }
}

#[derive(Clone, PartialEq, Eq)]
enum SourceKind {
    RegistryValue {
        is_hkcu: bool,
        subkey: String,
        value_name: String,
        reg_type: u32,
        supports_disable: bool,
    },
    StartupFile {
        dir: PathBuf,
        file_name: String,
    },
    Service {
        service_name: String,
        orig_start: u32,
    },
    ScheduledTask {
        xml_path: PathBuf,
    },
    ReadOnly,
}

#[derive(Clone)]
struct AutorunItem {
    enabled: bool,
    category: Category,
    entry_name: String,
    location: String,
    description: String,
    publisher: String,
    image_path: String,
    timestamp: String,
    file_exists: bool,
    is_microsoft: bool,
    source: SourceKind,
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn expand_env_vars(s: &str) -> String {
    let mut result = s.to_string();
    for (k, v) in env::vars() {
        let pattern = format!("%{}%", k);
        if result.to_lowercase().contains(&pattern.to_lowercase()) {
            result = result.replace(&pattern, &v);
            result = result.replace(&pattern.to_uppercase(), &v);
            result = result.replace(&pattern.to_lowercase(), &v);
        }
    }
    result
}

fn extract_exe_path(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    let expanded = if trimmed.contains('%') {
        expand_env_vars(trimmed)
    } else {
        trimmed.to_string()
    };

    let path_str = if let Some(stripped) = expanded.strip_prefix('"') {
        stripped.split('"').next().unwrap_or("")
    } else {
        let low = expanded.to_lowercase();
        if let Some(idx) = low.find(".exe") {
            &expanded[..idx + 4]
        } else if let Some(idx) = low.find(".sys") {
            &expanded[..idx + 4]
        } else if let Some(idx) = low.find(".dll") {
            &expanded[..idx + 4]
        } else if let Some(idx) = low.find(".cpl") {
            &expanded[..idx + 4]
        } else {
            expanded.split_whitespace().next().unwrap_or("")
        }
    };

    let clean = path_str
        .trim_start_matches(r"\??\")
        .trim_start_matches(r"\SystemRoot\");
    let low_path = path_str.to_lowercase();
    let low_clean = clean.to_lowercase();

    if low_path.starts_with(r"\systemroot\") || low_clean.starts_with(r"system32\") || low_clean.starts_with(r"syswow64\") {
        let win_dir = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        PathBuf::from(win_dir).join(clean)
    } else if !clean.contains('\\') && !clean.is_empty() {
        let win_dir = env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        let sys32 = PathBuf::from(&win_dir).join("System32").join(clean);
        if sys32.exists() {
            sys32
        } else {
            PathBuf::from(clean)
        }
    } else {
        PathBuf::from(clean)
    }
}

fn get_file_metadata(path: &Path) -> (bool, String, String, String) {
    if !path.exists() || path.is_dir() {
        return (false, String::new(), String::new(), String::new());
    }

    let timestamp = fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| format_unix_timestamp(d.as_secs()))
        .unwrap_or_default();

    let path_w = to_wide(&path.to_string_lossy());
    let mut dummy = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(path_w.as_ptr()), Some(&mut dummy)) };
    if size == 0 {
        return (true, String::new(), String::new(), timestamp);
    }

    let mut buffer = vec![0u8; size as usize];
    let ok = unsafe {
        GetFileVersionInfoW(
            PCWSTR(path_w.as_ptr()),
            0,
            size,
            buffer.as_mut_ptr() as *mut c_void,
        )
    };
    if ok.is_err() {
        return (true, String::new(), String::new(), timestamp);
    }

    let mut trans_ptr: *mut c_void = std::ptr::null_mut();
    let mut trans_len = 0u32;
    let trans_sub = to_wide(r"\VarFileInfo\Translation");

    let mut lang_codes = vec![(0x0409u16, 0x04B0u16), (0x0419u16, 0x04B0u16), (0x0409u16, 0x04E4u16)];
    if unsafe {
        VerQueryValueW(
            buffer.as_ptr() as *const c_void,
            PCWSTR(trans_sub.as_ptr()),
            &mut trans_ptr,
            &mut trans_len,
        )
    }
    .as_bool()
        && trans_len >= 4
        && !trans_ptr.is_null()
    {
        let pair = unsafe { std::slice::from_raw_parts(trans_ptr as *const u16, 2) };
        lang_codes.insert(0, (pair[0], pair[1]));
    }

    let mut description = String::new();
    let mut publisher = String::new();

    for (lang, cp) in lang_codes {
        if description.is_empty() {
            let sub = format!(r"\StringFileInfo\{:04x}{:04x}\FileDescription", lang, cp);
            if let Some(s) = query_version_string(&buffer, &sub) {
                description = s;
            }
        }
        if publisher.is_empty() {
            let sub = format!(r"\StringFileInfo\{:04x}{:04x}\CompanyName", lang, cp);
            if let Some(s) = query_version_string(&buffer, &sub) {
                publisher = s;
            }
        }
        if !description.is_empty() && !publisher.is_empty() {
            break;
        }
    }

    (true, description, publisher, timestamp)
}

fn query_version_string(buffer: &[u8], sub_block: &str) -> Option<String> {
    let sub_w = to_wide(sub_block);
    let mut val_ptr: *mut c_void = std::ptr::null_mut();
    let mut val_len = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            buffer.as_ptr() as *const c_void,
            PCWSTR(sub_w.as_ptr()),
            &mut val_ptr,
            &mut val_len,
        )
    };
    if ok.as_bool() && val_len > 1 && !val_ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(val_ptr as *const u16, val_len as usize) };
        let s = String::from_utf16_lossy(slice)
            .trim_end_matches('\0')
            .trim()
            .to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    None
}

fn format_unix_timestamp(secs: u64) -> String {
    let days = secs / 86400;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;

    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:02}.{:02}.{:04} {:02}:{:02}", d, m, year, hour, min)
}

fn check_is_microsoft(path: &Path, publisher: &str, name: &str) -> bool {
    let pub_low = publisher.to_lowercase();
    if pub_low.contains("microsoft") {
        return true;
    }
    let p_low = path.to_string_lossy().to_lowercase();
    let n_low = name.to_lowercase();
    (publisher.is_empty()
        && (p_low.contains(r"\windows\system32\")
            || p_low.contains(r"\windows\syswow64\")
            || p_low.contains(r"\windows\winsxs\")))
        || n_low.starts_with("microsoft")
}

fn build_item(
    enabled: bool,
    category: Category,
    entry_name: String,
    location: String,
    image_path: String,
    source: SourceKind,
) -> AutorunItem {
    let exe_path = extract_exe_path(&image_path);
    let (file_exists, description, publisher, timestamp) = get_file_metadata(&exe_path);
    let is_microsoft = check_is_microsoft(&exe_path, &publisher, &entry_name);

    AutorunItem {
        enabled,
        category,
        entry_name,
        location,
        description,
        publisher,
        image_path,
        timestamp,
        file_exists,
        is_microsoft,
        source,
    }
}

fn scan_registry_values(
    is_hkcu: bool,
    subkey: &str,
    enabled: bool,
    category: Category,
    supports_disable: bool,
    items: &mut Vec<AutorunItem>,
) {
    let root = if is_hkcu {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let root_prefix = if is_hkcu { "HKCU" } else { "HKLM" };
    let target_subkey = if enabled {
        subkey.to_string()
    } else {
        format!(r"{}\AutorunsDisabled", subkey)
    };

    let subkey_wide = to_wide(&target_subkey);
    let mut hkey = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(subkey_wide.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    }
    .is_err()
    {
        return;
    }

    let mut index = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let mut data_buf = [0u8; 4096];
        let mut data_len = data_buf.len() as u32;
        let mut reg_type = 0u32;

        let res = unsafe {
            RegEnumValueW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                Some(&mut reg_type),
                Some(data_buf.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if res.is_err() {
            break;
        }
        index += 1;

        let val_type = REG_VALUE_TYPE(reg_type);
        if val_type == REG_SZ || val_type == REG_EXPAND_SZ || val_type == REG_MULTI_SZ {
            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let u16_slice: Vec<u16> = data_buf[..data_len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let raw_str = String::from_utf16_lossy(&u16_slice)
                .trim_end_matches('\0')
                .replace('\0', " ");
            if raw_str.trim().is_empty() {
                continue;
            }

            let display_name = if name.is_empty() {
                "(Default)".to_string()
            } else {
                name.clone()
            };

            let src = if supports_disable {
                SourceKind::RegistryValue {
                    is_hkcu,
                    subkey: subkey.to_string(),
                    value_name: name,
                    reg_type,
                    supports_disable: true,
                }
            } else {
                SourceKind::ReadOnly
            };

            items.push(build_item(
                enabled,
                category,
                display_name,
                format!(r"{}\{}", root_prefix, subkey),
                raw_str,
                src,
            ));
        }
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn scan_clsid_subkeys(is_hkcu: bool, subkey: &str, category: Category, items: &mut Vec<AutorunItem>) {
    let root = if is_hkcu {
        HKEY_CURRENT_USER
    } else {
        HKEY_LOCAL_MACHINE
    };
    let root_prefix = if is_hkcu { "HKCU" } else { "HKLM" };
    let sub_w = to_wide(subkey);
    let mut hkey = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            root,
            PCWSTR(sub_w.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    }
    .is_err()
    {
        return;
    }

    let mut index = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let res = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        };
        if res.is_err() {
            break;
        }
        index += 1;

        let key_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let item_sub = format!(r"{}\{}", subkey, key_name);
        let item_w = to_wide(&item_sub);
        let mut ihkey = HKEY::default();
        let mut clsid = if key_name.starts_with('{') {
            key_name.clone()
        } else {
            String::new()
        };

        if unsafe {
            RegOpenKeyExW(
                root,
                PCWSTR(item_w.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut ihkey,
            )
        }
        .is_ok()
        {
            if clsid.is_empty() {
                if let Some(def) = read_reg_string(ihkey, "") {
                    if def.starts_with('{') {
                        clsid = def;
                    }
                }
            }
            unsafe {
                let _ = RegCloseKey(ihkey);
            }
        }

        if clsid.is_empty() {
            continue;
        }

        let dll_path = resolve_clsid(&clsid).unwrap_or_else(|| clsid.clone());
        items.push(build_item(
            true,
            category,
            key_name,
            format!(r"{}\{}", root_prefix, subkey),
            dll_path,
            SourceKind::ReadOnly,
        ));
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn resolve_clsid(clsid: &str) -> Option<String> {
    for path in [
        format!(r"SOFTWARE\Classes\CLSID\{}\InprocServer32", clsid),
        format!(r"SOFTWARE\Classes\WOW6432Node\CLSID\{}\InprocServer32", clsid),
    ] {
        let w = to_wide(&path);
        let mut hkey = HKEY::default();
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(w.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut hkey,
            )
        }
        .is_ok()
        {
            let val = read_reg_string(hkey, "");
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            if val.is_some() {
                return val;
            }
        }
    }
    None
}

fn scan_startup_dir(dir: &Path, label: &str, items: &mut Vec<AutorunItem>) {
    for (sub, enabled) in [(dir.to_path_buf(), true), (dir.join("AutorunsDisabled"), false)] {
        if let Ok(entries) = fs::read_dir(&sub) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    continue;
                }
                if let Some(fname) = path.file_name().and_then(|n| n.to_str()) {
                    if fname.eq_ignore_ascii_case("desktop.ini") {
                        continue;
                    }
                    items.push(build_item(
                        enabled,
                        Category::Logon,
                        fname.to_string(),
                        label.to_string(),
                        path.display().to_string(),
                        SourceKind::StartupFile {
                            dir: dir.to_path_buf(),
                            file_name: fname.to_string(),
                        },
                    ));
                }
            }
        }
    }
}

fn read_reg_dword(hkey: HKEY, name: &str) -> Option<u32> {
    let name_w = to_wide(name);
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    let mut rtype = REG_VALUE_TYPE::default();
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut rtype),
            Some(&mut data as *mut u32 as *mut u8),
            Some(&mut size),
        )
    };
    if res.is_ok() && rtype == REG_DWORD {
        Some(data)
    } else {
        None
    }
}

fn read_reg_string(hkey: HKEY, name: &str) -> Option<String> {
    let name_w = to_wide(name);
    let mut buf = [0u8; 2048];
    let mut size = buf.len() as u32;
    let mut rtype = REG_VALUE_TYPE::default();
    let res = unsafe {
        RegQueryValueExW(
            hkey,
            PCWSTR(name_w.as_ptr()),
            None,
            Some(&mut rtype),
            Some(buf.as_mut_ptr()),
            Some(&mut size),
        )
    };
    if res.is_ok() && (rtype == REG_SZ || rtype == REG_EXPAND_SZ) {
        let u16_slice: Vec<u16> = buf[..size as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(
            String::from_utf16_lossy(&u16_slice)
                .trim_end_matches('\0')
                .to_string(),
        )
    } else {
        None
    }
}

fn scan_services_and_drivers(items: &mut Vec<AutorunItem>) {
    let base = r"SYSTEM\CurrentControlSet\Services";
    let base_w = to_wide(base);
    let mut hkey = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(base_w.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    }
    .is_err()
    {
        return;
    }

    let mut index = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        let res = unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        };
        if res.is_err() {
            break;
        }
        index += 1;

        let svc_name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let svc_path = format!(r"{}\{}", base, svc_name);
        let svc_w = to_wide(&svc_path);
        let mut shkey = HKEY::default();
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(svc_w.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut shkey,
            )
        }
        .is_err()
        {
            continue;
        }

        let start = read_reg_dword(shkey, "Start").unwrap_or(4);
        let svc_type = read_reg_dword(shkey, "Type").unwrap_or(0);
        let image_path = read_reg_string(shkey, "ImagePath").unwrap_or_default();
        let display_name = read_reg_string(shkey, "DisplayName").unwrap_or_else(|| svc_name.clone());
        let orig_start = read_reg_dword(shkey, "AutorunsOrigStart");

        unsafe {
            let _ = RegCloseKey(shkey);
        }

        if image_path.is_empty() {
            continue;
        }

        let (enabled, saved_start) = if start <= 2 {
            (true, start)
        } else if start == 4 && orig_start.is_some() {
            (false, orig_start.unwrap())
        } else {
            continue;
        };

        let is_driver = (svc_type & 0x01) != 0 || (svc_type & 0x02) != 0;
        let category = if is_driver {
            Category::Drivers
        } else {
            Category::Services
        };

        let mut item = build_item(
            enabled,
            category,
            svc_name.clone(),
            format!(r"HKLM\{}", base),
            image_path.clone(),
            SourceKind::Service {
                service_name: svc_name,
                orig_start: saved_start,
            },
        );
        if item.description.is_empty() && !display_name.starts_with('@') {
            item.description = display_name;
        }
        if image_path.to_lowercase().contains("svchost.exe") {
            item.is_microsoft = true;
        }
        items.push(item);
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn scan_image_hijacks(items: &mut Vec<AutorunItem>) {
    let base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    let base_w = to_wide(base);
    let mut hkey = HKEY::default();
    if unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(base_w.as_ptr()),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    }
    .is_err()
    {
        return;
    }

    let mut index = 0;
    loop {
        let mut name_buf = [0u16; 256];
        let mut name_len = name_buf.len() as u32;
        if unsafe {
            RegEnumKeyExW(
                hkey,
                index,
                PWSTR(name_buf.as_mut_ptr()),
                &mut name_len,
                None,
                PWSTR::null(),
                None,
                None,
            )
        }
        .is_err()
        {
            break;
        }
        index += 1;

        let target_exe = String::from_utf16_lossy(&name_buf[..name_len as usize]);
        let sub = format!(r"{}\{}", base, target_exe);
        let sub_w = to_wide(&sub);
        let mut shkey = HKEY::default();
        if unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                PCWSTR(sub_w.as_ptr()),
                0,
                KEY_READ | KEY_WOW64_64KEY,
                &mut shkey,
            )
        }
        .is_ok()
        {
            if let Some(debugger) = read_reg_string(shkey, "Debugger") {
                if !debugger.trim().is_empty() {
                    items.push(build_item(
                        true,
                        Category::ImageHijacks,
                        target_exe,
                        format!(r"HKLM\{}", base),
                        debugger,
                        SourceKind::ReadOnly,
                    ));
                }
            }
            unsafe {
                let _ = RegCloseKey(shkey);
            }
        }
    }
    unsafe {
        let _ = RegCloseKey(hkey);
    }
}

fn scan_tasks_recursive(dir: &Path, base: &Path, items: &mut Vec<AutorunItem>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan_tasks_recursive(&path, base, items);
        } else if path.is_file() {
            let content = if let Ok(bytes) = fs::read(&path) {
                if bytes.starts_with(&[0xFF, 0xFE]) {
                    let u16s: Vec<u16> = bytes[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    String::from_utf16_lossy(&u16s)
                } else {
                    String::from_utf8_lossy(&bytes).to_string()
                }
            } else {
                continue;
            };

            if let Some(start) = content.find("<Command>") {
                if let Some(end) = content[start..].find("</Command>") {
                    let cmd = content[start + 9..start + end].trim().to_string();
                    let enabled = !content.contains("<Enabled>false</Enabled>");
                    let rel = path.strip_prefix(base).unwrap_or(&path);
                    let rel_str = rel.display().to_string();
                    let is_ms_path = rel_str.starts_with("Microsoft\\");

                    let mut item = build_item(
                        enabled,
                        Category::ScheduledTasks,
                        rel_str,
                        "Task Scheduler".to_string(),
                        cmd,
                        SourceKind::ScheduledTask { xml_path: path },
                    );
                    if is_ms_path {
                        item.is_microsoft = true;
                    }
                    items.push(item);
                }
            }
        }
    }
}

fn collect_all() -> Vec<AutorunItem> {
    let mut items = Vec::new();

    // 1. Logon
    let logon_keys = [
        (true, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (true, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (false, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (false, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
        (true, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    ];
    for (is_hkcu, subkey) in logon_keys {
        scan_registry_values(is_hkcu, subkey, true, Category::Logon, true, &mut items);
        scan_registry_values(is_hkcu, subkey, false, Category::Logon, true, &mut items);
    }

    if let Ok(appdata) = env::var("APPDATA") {
        let p = PathBuf::from(appdata).join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        scan_startup_dir(&p, "User Startup Folder", &mut items);
    }
    if let Ok(progdata) = env::var("ProgramData") {
        let p = PathBuf::from(progdata).join(r"Microsoft\Windows\Start Menu\Programs\StartUp");
        scan_startup_dir(&p, "Common Startup Folder", &mut items);
    }

    // 2. Explorer
    scan_clsid_subkeys(
        false,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
        Category::Explorer,
        &mut items,
    );
    scan_clsid_subkeys(
        false,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
        Category::Explorer,
        &mut items,
    );
    scan_registry_values(
        false,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        true,
        Category::Explorer,
        false,
        &mut items,
    );

    // 3. Internet Explorer
    scan_clsid_subkeys(
        false,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects",
        Category::InternetExplorer,
        &mut items,
    );

    // 4. Services & Drivers
    scan_services_and_drivers(&mut items);

    // 5. Codecs
    scan_registry_values(
        false,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Drivers32",
        true,
        Category::Codecs,
        false,
        &mut items,
    );

    // 6. Boot Execute
    scan_registry_values(
        false,
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        true,
        Category::BootExecute,
        false,
        &mut items,
    );

    // 7. Image Hijacks
    scan_image_hijacks(&mut items);

    // 8. AppInit
    scan_registry_values(
        false,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
        true,
        Category::AppInit,
        false,
        &mut items,
    );
    scan_registry_values(
        false,
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        true,
        Category::AppInit,
        false,
        &mut items,
    );

    // 9. Known DLLs
    scan_registry_values(
        false,
        r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
        true,
        Category::KnownDlls,
        false,
        &mut items,
    );

    // 10. Winlogon
    scan_registry_values(
        false,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        true,
        Category::Winlogon,
        false,
        &mut items,
    );
    scan_clsid_subkeys(
        false,
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify",
        Category::Winlogon,
        &mut items,
    );

    // 11. Winsock Providers
    scan_clsid_subkeys(
        false,
        r"SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries",
        Category::WinsockProviders,
        &mut items,
    );

    // 12. Print Monitors
    scan_clsid_subkeys(
        false,
        r"SYSTEM\CurrentControlSet\Control\Print\Monitors",
        Category::PrintMonitors,
        &mut items,
    );

    // 13. LSA Providers
    scan_registry_values(
        false,
        r"SYSTEM\CurrentControlSet\Control\Lsa",
        true,
        Category::LsaProviders,
        false,
        &mut items,
    );

    // 14. Network Providers
    scan_registry_values(
        false,
        r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order",
        true,
        Category::NetworkProviders,
        false,
        &mut items,
    );

    // 15. Office Addins
    scan_clsid_subkeys(
        true,
        r"Software\Microsoft\Office\Word\Addins",
        Category::Office,
        &mut items,
    );
    scan_clsid_subkeys(
        true,
        r"Software\Microsoft\Office\Excel\Addins",
        Category::Office,
        &mut items,
    );
    scan_clsid_subkeys(
        false,
        r"SOFTWARE\Microsoft\Office\Word\Addins",
        Category::Office,
        &mut items,
    );

    // 16. Scheduled Tasks
    let tasks_dir = Path::new(r"C:\Windows\System32\Tasks");
    scan_tasks_recursive(tasks_dir, tasks_dir, &mut items);

    items
}

fn toggle_item(item: &mut AutorunItem) -> Result<(), String> {
    let target_enabled = !item.enabled;
    match &item.source {
        SourceKind::RegistryValue {
            is_hkcu,
            subkey,
            value_name,
            reg_type,
            supports_disable: true,
        } => {
            let root = if *is_hkcu {
                HKEY_CURRENT_USER
            } else {
                HKEY_LOCAL_MACHINE
            };
            let (from_sub, to_sub) = if target_enabled {
                (format!(r"{}\AutorunsDisabled", subkey), subkey.clone())
            } else {
                (subkey.clone(), format!(r"{}\AutorunsDisabled", subkey))
            };

            let to_w = to_wide(&to_sub);
            let mut h_to = HKEY::default();
            if unsafe {
                RegCreateKeyExW(
                    root,
                    PCWSTR(to_w.as_ptr()),
                    0,
                    PCWSTR::null(),
                    REG_OPTION_NON_VOLATILE,
                    KEY_WRITE | KEY_WOW64_64KEY,
                    None,
                    &mut h_to,
                    None,
                )
            }
            .is_err()
            {
                return Err("Нет прав на запись в реестр (запусти от администратора)".into());
            }

            let val_w = to_wide(value_name);
            let data_w = to_wide(&item.image_path);
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(data_w.as_ptr() as *const u8, data_w.len() * 2)
            };

            let set_res = unsafe {
                RegSetValueExW(
                    h_to,
                    PCWSTR(val_w.as_ptr()),
                    0,
                    REG_VALUE_TYPE(*reg_type),
                    Some(bytes),
                )
            };
            unsafe {
                let _ = RegCloseKey(h_to);
            }
            if set_res.is_err() {
                return Err("Не удалось записать значение в реестр".into());
            }

            let from_w = to_wide(&from_sub);
            let mut h_from = HKEY::default();
            if unsafe {
                RegOpenKeyExW(
                    root,
                    PCWSTR(from_w.as_ptr()),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut h_from,
                )
            }
            .is_ok()
            {
                unsafe {
                    let _ = RegDeleteValueW(h_from, PCWSTR(val_w.as_ptr()));
                    let _ = RegCloseKey(h_from);
                }
            }
            item.enabled = target_enabled;
            Ok(())
        }
        SourceKind::StartupFile { dir, file_name } => {
            let disabled_dir = dir.join("AutorunsDisabled");
            let (src, dst) = if target_enabled {
                (disabled_dir.join(file_name), dir.join(file_name))
            } else {
                let _ = fs::create_dir_all(&disabled_dir);
                (dir.join(file_name), disabled_dir.join(file_name))
            };
            fs::rename(&src, &dst).map_err(|e| format!("Ошибка перемещения: {}", e))?;
            item.image_path = dst.display().to_string();
            item.enabled = target_enabled;
            Ok(())
        }
        SourceKind::Service {
            service_name,
            orig_start,
        } => {
            let svc_path = format!(r"SYSTEM\CurrentControlSet\Services\{}", service_name);
            let svc_w = to_wide(&svc_path);
            let mut hkey = HKEY::default();
            if unsafe {
                RegOpenKeyExW(
                    HKEY_LOCAL_MACHINE,
                    PCWSTR(svc_w.as_ptr()),
                    0,
                    KEY_WRITE | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            }
            .is_err()
            {
                return Err("Нет прав на изменение службы (нужен администратор)".into());
            }

            let start_w = to_wide("Start");
            let orig_w = to_wide("AutorunsOrigStart");

            if target_enabled {
                let val = *orig_start;
                unsafe {
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(start_w.as_ptr()),
                        0,
                        REG_DWORD,
                        Some(&val.to_le_bytes()),
                    );
                    let _ = RegDeleteValueW(hkey, PCWSTR(orig_w.as_ptr()));
                }
            } else {
                let disabled_val: u32 = 4;
                unsafe {
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(orig_w.as_ptr()),
                        0,
                        REG_DWORD,
                        Some(&orig_start.to_le_bytes()),
                    );
                    let _ = RegSetValueExW(
                        hkey,
                        PCWSTR(start_w.as_ptr()),
                        0,
                        REG_DWORD,
                        Some(&disabled_val.to_le_bytes()),
                    );
                }
            }
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            item.enabled = target_enabled;
            Ok(())
        }
        _ => Err("Переключение для этой системной секции заблокировано".into()),
    }
}

fn delete_item(item: &AutorunItem) -> Result<(), String> {
    match &item.source {
        SourceKind::RegistryValue {
            is_hkcu,
            subkey,
            value_name,
            supports_disable: true,
            ..
        } => {
            let root = if *is_hkcu {
                HKEY_CURRENT_USER
            } else {
                HKEY_LOCAL_MACHINE
            };
            let target_sub = if item.enabled {
                subkey.clone()
            } else {
                format!(r"{}\AutorunsDisabled", subkey)
            };
            let sub_w = to_wide(&target_sub);
            let mut hkey = HKEY::default();
            if unsafe {
                RegOpenKeyExW(
                    root,
                    PCWSTR(sub_w.as_ptr()),
                    0,
                    KEY_SET_VALUE | KEY_WOW64_64KEY,
                    &mut hkey,
                )
            }
            .is_err()
            {
                return Err("Нет доступа к ветке реестра".into());
            }
            let val_w = to_wide(value_name);
            let res = unsafe { RegDeleteValueW(hkey, PCWSTR(val_w.as_ptr())) };
            unsafe {
                let _ = RegCloseKey(hkey);
            }
            if res.is_err() {
                Err("Не удалось удалить ключ".into())
            } else {
                Ok(())
            }
        }
        SourceKind::StartupFile { dir, file_name } => {
            let path = if item.enabled {
                dir.join(file_name)
            } else {
                dir.join("AutorunsDisabled").join(file_name)
            };
            fs::remove_file(path).map_err(|e| format!("Ошибка удаления: {}", e))
        }
        SourceKind::ScheduledTask { xml_path } => {
            fs::remove_file(xml_path).map_err(|e| format!("Ошибка удаления задачи: {}", e))
        }
        _ => Err("Удаление из системных веток заблокировано ради безопасности".into()),
    }
}

struct AutorunsApp {
    items: Vec<AutorunItem>,
    active_tab: Category,
    search_query: String,
    hide_microsoft: bool,
    selected_idx: Option<usize>,
    status_msg: String,
}

impl AutorunsApp {
    fn new() -> Self {
        let items = collect_all();
        let count = items.len();
        Self {
            items,
            active_tab: Category::Everything,
            search_query: String::new(),
            hide_microsoft: true,
            selected_idx: None,
            status_msg: format!("Готово. Всего объектов в базе: {}", count),
        }
    }

    fn refresh(&mut self) {
        self.items = collect_all();
        self.selected_idx = None;
        self.status_msg = format!("Обновлено. Всего объектов в базе: {}", self.items.len());
    }
}

impl eframe::App for AutorunsApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh (F5)").clicked()
                    || ctx.input(|i| i.key_pressed(egui::Key::F5))
                {
                    self.refresh();
                }

                ui.separator();
                ui.label("Quick Filter:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_query)
                        .hint_text("Filter by entry, publisher, path...")
                        .desired_width(240.0),
                );
                if ui.button("✖").clicked() {
                    self.search_query.clear();
                }

                ui.separator();
                ui.checkbox(&mut self.hide_microsoft, "Hide Microsoft Entries");

                ui.separator();
                if let Some(idx) = self.selected_idx {
                    if idx < self.items.len() {
                        if ui.button("🗑 Delete").clicked()
                            || ctx.input(|i| i.key_pressed(egui::Key::Delete))
                        {
                            match delete_item(&self.items[idx]) {
                                Ok(()) => {
                                    self.status_msg =
                                        format!("Deleted: {}", self.items[idx].entry_name);
                                    self.items.remove(idx);
                                    self.selected_idx = None;
                                }
                                Err(e) => self.status_msg = e,
                            }
                        }
                    }
                }
            });

            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(2.0, 2.0);
                for &cat in Category::top_row() {
                    ui.selectable_value(&mut self.active_tab, cat, cat.label());
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(2.0, 2.0);
                for &cat in Category::bottom_row() {
                    ui.selectable_value(&mut self.active_tab, cat, cat.label());
                }
            });
            ui.add_space(2.0);
        });

        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status_msg);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(idx) = self.selected_idx {
                        if let Some(item) = self.items.get(idx) {
                            ui.label(format!("Location: {}", item.location));
                        }
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            let query_low = self.search_query.to_lowercase();

            // Группировка индексов по Location (как синие заголовки в Sysinternals Autoruns)
            let mut groups: BTreeMap<String, Vec<usize>> = BTreeMap::new();
            for (idx, item) in self.items.iter().enumerate() {
                if self.active_tab != Category::Everything && item.category != self.active_tab {
                    continue;
                }
                if self.hide_microsoft && item.is_microsoft {
                    continue;
                }
                if !query_low.is_empty()
                    && !item.entry_name.to_lowercase().contains(&query_low)
                    && !item.description.to_lowercase().contains(&query_low)
                    && !item.publisher.to_lowercase().contains(&query_low)
                    && !item.image_path.to_lowercase().contains(&query_low)
                    && !item.location.to_lowercase().contains(&query_low)
                {
                    continue;
                }
                groups.entry(item.location.clone()).or_default().push(idx);
            }

            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    egui::Grid::new("autoruns_grid")
                        .striped(true)
                        .min_col_width(30.0)
                        .spacing([14.0, 3.0])
                        .show(ui, |ui| {
                            ui.strong("");
                            ui.strong("Autoruns Entry");
                            ui.strong("Description");
                            ui.strong("Publisher");
                            ui.strong("Image Path");
                            ui.strong("Timestamp");
                            ui.end_row();

                            for (location, indices) in groups {
                                // Строка-заголовок группы (как в оригинале)
                                ui.label("");
                                ui.label(
                                    egui::RichText::new(&location)
                                        .strong()
                                        .color(egui::Color32::from_rgb(110, 175, 255)),
                                );
                                ui.label("");
                                ui.label("");
                                ui.label("");
                                ui.label("");
                                ui.end_row();

                                for idx in indices {
                                    let mut checked = self.items[idx].enabled;
                                    if ui.checkbox(&mut checked, "").changed() {
                                        match toggle_item(&mut self.items[idx]) {
                                            Ok(()) => {
                                                self.status_msg = format!(
                                                    "{}: {}",
                                                    if self.items[idx].enabled {
                                                        "Enabled"
                                                    } else {
                                                        "Disabled"
                                                    },
                                                    self.items[idx].entry_name
                                                );
                                            }
                                            Err(e) => self.status_msg = e,
                                        }
                                    }

                                    let item = &self.items[idx];
                                    let is_selected = self.selected_idx == Some(idx);

                                    let name_text = if !item.file_exists {
                                        egui::RichText::new(format!(
                                            "{} (File not found)",
                                            item.entry_name
                                        ))
                                        .color(egui::Color32::from_rgb(240, 90, 90))
                                    } else if !item.enabled {
                                        egui::RichText::new(&item.entry_name).weak()
                                    } else {
                                        egui::RichText::new(&item.entry_name)
                                    };

                                    if ui.selectable_label(is_selected, name_text).clicked() {
                                        self.selected_idx = Some(idx);
                                    }

                                    ui.label(&item.description);
                                    ui.label(&item.publisher);
                                    ui.label(&item.image_path);
                                    ui.label(&item.timestamp);
                                    ui.end_row();
                                }
                            }
                        });
                });
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1240.0, 700.0])
            .with_title("Autoruns-RS"),
        ..Default::default()
    };

    eframe::run_native(
        "Autoruns-RS",
        options,
        Box::new(|_cc| Ok(Box::new(AutorunsApp::new()))),
    )
}