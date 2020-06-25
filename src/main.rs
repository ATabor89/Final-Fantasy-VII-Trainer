use config::*;
use notify::{DebouncedEvent, RecommendedWatcher, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::mpsc::channel;
use std::sync::RwLock;
#[macro_use]
extern crate lazy_static;

#[cfg(debug_assertions)]
macro_rules! debug_print {
    ($( $args:expr ),*) => { println!( $( $args ),* ); }
}

// Non-debug version
#[cfg(not(debug_assertions))]
macro_rules! debug_print {
    ($( $args:expr ),*) => {};
}

#[cfg(windows)]
extern crate winapi;
use std::sync::{Arc, Mutex};

struct KeyStates {
    ctrl_num8_was_pressed: bool,
    ctrl_num9_was_pressed: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct MemoryState {
    experience: u32,
    ap: u32,
    gil: u32,
}

impl MemoryState {
    fn read_memory_state(
        &mut self,
        handle: *mut winapi::ctypes::c_void,
        module_base_address: *mut u8,
    ) {
        read_process_memory(
            handle,
            module_base_address,
            0x0059_E2C0,
            &mut self.experience,
        );
        read_process_memory(handle, module_base_address, 0x0059_E2C4, &mut self.ap);
        read_process_memory(handle, module_base_address, 0x0059_E2C8, &mut self.gil);
    }
}

// TODO: The AP may actually be stored in a three-byte array, but two-bytes should be enough for most, if not all, of the game
#[derive(Debug, Eq, PartialEq)]
struct Enemy {
    ap_value: u16,
    experience_value: u32,
    gil_value: u32,
}

#[derive(Serialize, Deserialize, Debug)]
struct Settings {
    experience_multiplier: f32,
    ap_multiplier: f32,
    gil_multiplier: f32,
}

#[derive(Debug, Eq, PartialEq)]
struct EnemyMemoryState {
    ap_value: [u16; 3],
    experience_value: [u32; 6],
    gil_value: [u32; 6],
}

static SLEEP_WHEN_WAITING: std::time::Duration = std::time::Duration::from_millis(100);
static AP_OFFSETS: [u32; 3] = [0x005A_8F3A, 0x005A_8FF2, 0x005A_90AA];
static EXPERIENCE_OFFSETS: [u32; 6] = [
    0x005A_B2D8,
    0x005A_B340,
    0x005A_B3A8,
    0x005A_B410,
    0x005A_B478,
    0x005A_B4E0,
];
static GIL_OFFSETS: [u32; 6] = [
    0x005A_B2D4,
    0x005A_B33C,
    0x005A_B3A4,
    0x005A_B40C,
    0x005A_B474,
    0x005A_B4DC,
];
static EMPTY_ENEMY_MEMORY_STATE: EnemyMemoryState = EnemyMemoryState {
    ap_value: [0, 0, 0],
    experience_value: [0, 0, 0, 0, 0, 0],
    gil_value: [0, 0, 0, 0, 0, 0],
};

// TODO: Add a get_totals() function so we can see what values we should see after battle
// This should only be used in debug print statements
impl EnemyMemoryState {
    fn is_zero(&self) -> bool {
        *self == EMPTY_ENEMY_MEMORY_STATE
    }

    fn read_enemy_memory_state(
        &mut self,
        handle: *mut winapi::ctypes::c_void,
        module_base_address: *mut u8,
    ) {
        for (ap, offset) in self.ap_value.iter_mut().zip(AP_OFFSETS.iter()) {
            read_process_memory(handle, module_base_address, *offset, ap);
        }

        for (exp, offset) in self
            .experience_value
            .iter_mut()
            .zip(EXPERIENCE_OFFSETS.iter())
        {
            read_process_memory(handle, module_base_address, *offset, exp);
        }

        for (gil, offset) in self.gil_value.iter_mut().zip(GIL_OFFSETS.iter()) {
            read_process_memory(handle, module_base_address, *offset, gil);
        }
    }

    fn write_enemy_memory_state(
        &mut self,
        handle: *mut winapi::ctypes::c_void,
        module_base_address: *mut u8,
        (experience_multiplier, ap_multiplier, gil_multiplier): (f32, f32, f32),
    ) {
        for exp in self.experience_value.iter_mut() {
            *exp = ((*exp as f32) * experience_multiplier) as u32;
        }
        for ap in self.ap_value.iter_mut() {
            *ap = ((*ap as f32) * ap_multiplier) as u16;
        }
        for gil in self.gil_value.iter_mut() {
            *gil = ((*gil as f32) * gil_multiplier) as u32;
        }

        for (ap, offset) in self.ap_value.iter_mut().zip(AP_OFFSETS.iter()) {
            write_process_memory(handle, module_base_address, *offset, ap);
        }

        for (exp, offset) in self
            .experience_value
            .iter_mut()
            .zip(EXPERIENCE_OFFSETS.iter())
        {
            write_process_memory(handle, module_base_address, *offset, exp);
        }

        for (gil, offset) in self.experience_value.iter_mut().zip(GIL_OFFSETS.iter()) {
            write_process_memory(handle, module_base_address, *offset, gil);
        }
    }
}

lazy_static! {
    static ref SETTINGS: RwLock<Config> = RwLock::new({
        let mut settings = Config::default();
        settings.merge(File::with_name("Settings.toml")).unwrap();

        settings
    });
}

fn show() {
    println!(
        " * Settings :: \n\x1b[31m{:?}\x1b[0m",
        SETTINGS
            .read()
            .unwrap()
            .clone()
            .try_into::<HashMap<String, String>>()
            .unwrap()
    );
}

fn get_settings() -> Settings {
    let settings = SETTINGS
        .read()
        .unwrap()
        .clone()
        .try_into::<Settings>()
        .unwrap();

    settings
}

fn watch() {
    // Create a channel to receive the events.
    let (tx, rx) = channel();

    // Automatically select the best implementation for your platform.
    // You can also access each implementation directly e.g. INotifyWatcher.
    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, std::time::Duration::from_secs(2)).unwrap();

    // Add a path to be watched. All files and directories at that path and
    // below will be monitored for changes.
    watcher
        .watch("./Settings.toml", RecursiveMode::NonRecursive)
        .unwrap();

    // This is a simple loop, but you may want to use more complex logic here,
    // for example to handle I/O.
    loop {
        match rx.recv() {
            Ok(DebouncedEvent::Write(_)) => {
                println!(" * Settings.toml written; refreshing configuration ...");
                SETTINGS.write().unwrap().refresh().unwrap();
                show();
            }

            Err(e) => println!("watch error: {:?}", e),

            _ => {
                // Ignore event
            }
        }
    }
}

fn close_listener() {
    use winapi::um::winuser::{VK_LCONTROL, VK_NUMPAD9};

    loop {
        if vk_is_held(VK_LCONTROL) && vk_is_pressed(VK_NUMPAD9) {
            break;
        } // End Ctrl + Num9
    }
}

fn vk_is_held(input: i32) -> bool {
    unsafe { winapi::um::winuser::GetAsyncKeyState(input) & ((0x8000u16) as i16) != 0 }
}

fn vk_is_pressed(input: i32) -> bool {
    unsafe { winapi::um::winuser::GetAsyncKeyState(input) & 1 != 0 }
}

fn get_process_handle_and_id(
    window_name: &str,
) -> Result<(*mut winapi::ctypes::c_void, u32), String> {
    let game_name = std::ffi::CString::new(window_name).unwrap();
    let hwnd = unsafe { winapi::um::winuser::FindWindowA(std::ptr::null(), game_name.as_ptr()) };

    if hwnd as *const _ == std::ptr::null() {
        let formatted_err = format!(
            "Error when getting window handle with FindWindowA; hwnd is NULL. Windows Error: {:?}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        return Err(formatted_err);
    } // end if
    debug_print!("hwnd == {:?}", hwnd);

    //let mut proc_id = 0 as *mut u32;
    let mut proc_id: u32 = 1;
    unsafe { winapi::um::winuser::GetWindowThreadProcessId(hwnd, &mut proc_id) };
    // println!("proc_id after GetWindowThreadProcessId() == {:?}", proc_id);

    let handle = unsafe {
        winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_VM_READ
                | winapi::um::winnt::PROCESS_VM_WRITE
                | winapi::um::winnt::PROCESS_VM_OPERATION,
            0, /*false*/
            proc_id,
        )
    };

    if proc_id == 0 {
        let formatted_err = format!(
            "Error when getting proc_id with OpenProcess; proc_id == 0. Windows Error: {:?}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        return Err(formatted_err);
    }

    if handle.is_null() {
        let formatted_err = format!(
            "Error when getting handle with OpenProcess; handle is NULL. Windows Error: {:?}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        return Err(formatted_err);
    }

    // println!(
    //     "get_process_handle_and_id: handle: {:?}\tprocess id: {:?}",
    //     handle, proc_id
    // );
    Ok((handle, proc_id))
} // End get_process_handle_and_id

fn read_process_memory<T: std::fmt::Display + Clone>(
    handle: winapi::um::winnt::HANDLE,
    base_address: *mut u8,
    offset: u32,
    buffer: &mut T,
) {
    let mut temp: T = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    let result = unsafe {
        winapi::um::memoryapi::ReadProcessMemory(
            handle,
            (base_address.offset(offset as isize)) as *const _,
            &mut temp as *mut _ as *mut _,
            std::mem::size_of::<T>(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        unsafe {
            println!(
                "read_process_memory: Error: {:?}",
                winapi::um::errhandlingapi::GetLastError()
            );
        }
    } else {
        *buffer = temp;
        // println!("read_process_memory: buffer: {}", buffer);
    }
}

fn write_process_memory<T: std::fmt::Display + Clone>(
    handle: winapi::um::winnt::HANDLE,
    base_address: *mut u8,
    offset: u32,
    buffer: &T,
) {
    let mut temp: T = buffer.clone();
    let result = unsafe {
        winapi::um::memoryapi::WriteProcessMemory(
            handle,
            (base_address.offset(offset as isize)) as *mut _,
            &mut temp as *mut _ as *mut _,
            std::mem::size_of::<T>(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        unsafe {
            println!(
                "write_process_memory: Error: {:?}",
                winapi::um::errhandlingapi::GetLastError()
            );
        }
    }
}

// DWORD_PTR dwGetModuleBaseAddress(DWORD dwProcID, TCHAR *szModuleName)
fn dw_get_module_base_address(dw_proc_id: u32, sz_module_name: &str) -> Result<*mut u8, String> {
    let mut dw_module_base_address = 0 as *mut u8;
    let h_snapshot = unsafe {
        winapi::um::tlhelp32::CreateToolhelp32Snapshot(
            winapi::um::tlhelp32::TH32CS_SNAPMODULE | winapi::um::tlhelp32::TH32CS_SNAPMODULE32,
            dw_proc_id,
        )
    };

    if h_snapshot != winapi::um::handleapi::INVALID_HANDLE_VALUE {
        let mut module_entry_32: winapi::um::tlhelp32::MODULEENTRY32 =
            winapi::um::tlhelp32::MODULEENTRY32::default();
        module_entry_32.dwSize = std::mem::size_of::<winapi::um::tlhelp32::MODULEENTRY32>() as u32;
        if match unsafe { winapi::um::tlhelp32::Module32First(h_snapshot, &mut module_entry_32) } {
            0 => false,
            _ => true,
        } {
            let temp_sz_module = module_entry_32
                .szModule
                .iter()
                .map(|x| *x as u8)
                .collect::<Vec<u8>>();
            let temp_sz_module = std::str::from_utf8(temp_sz_module.as_slice()).unwrap();
            // println!("dw_get_module_base_address: temp_sz_module: {}", temp_sz_module);
            if temp_sz_module.contains(sz_module_name) {
                // println!("Found matching module.");
                dw_module_base_address = module_entry_32.modBaseAddr;
            } else {
                while match unsafe {
                    winapi::um::tlhelp32::Module32Next(h_snapshot, &mut module_entry_32)
                } {
                    0 => false,
                    _ => true,
                }
                /*match bracket*/
                {
                    // while open
                    let temp_sz_module = module_entry_32
                        .szModule
                        .iter()
                        .map(|x| *x as u8)
                        .collect::<Vec<u8>>();
                    let temp_sz_module = std::str::from_utf8(temp_sz_module.as_slice()).unwrap();
                    // println!("dw_get_module_base_address: temp_sz_module: {}", temp_sz_module);

                    if temp_sz_module.contains(sz_module_name) {
                        // println!("Found matching module.");
                        dw_module_base_address = module_entry_32.modBaseAddr;
                        break;
                    } // end if
                } /* while close */
            } // end else
        }

        unsafe {
            winapi::um::handleapi::CloseHandle(h_snapshot);
        }
    } else {
        let formatted_err = format!(
            "Error when CreatingToolhelp32Shapshot. Windows Error: {:?}",
            unsafe { winapi::um::errhandlingapi::GetLastError() }
        );
        return Err(formatted_err);
    }

    Ok(dw_module_base_address)
}

// TODO: Add error checking when reading memory values to ensure that we don't keep reading after the game is closed
// This may involve checking the handle (Consider GetHandleInformation)
// TODO: Modify logic to wait until it finds a handle and address rather than immediately exiting
fn run_game_hacks(key_states_input: &Arc<Mutex<KeyStates>>) -> Result<(), String> {
    let (handle, proc_id) = get_process_handle_and_id("FINAL FANTASY VII")?;
    let module_base_address;

    module_base_address = dw_get_module_base_address(proc_id, "FF7_EN.exe")?;
    // println!("\n\nmodule_base_address: 0x{:?}\n\n", module_base_address);

    let mut enemy_memory_state = EnemyMemoryState {
        ap_value: [0, 0, 0],
        experience_value: [0, 0, 0, 0, 0, 0],
        gil_value: [0, 0, 0, 0, 0, 0],
    };

    let mut battle_monitor = false;
    enemy_memory_state.write_enemy_memory_state(handle, module_base_address, (0.0, 0.0, 0.0));

    let mut memory_state = MemoryState {
        experience: 1,
        ap: 1,
        gil: 1,
    };
    let default_memory_state = MemoryState {
        experience: 0,
        ap: 0,
        gil: 0,
    };

    'outer: loop {
        {
            let key_states = key_states_input.lock().unwrap();
            if key_states.ctrl_num8_was_pressed {
                break 'outer;
            }
        }

        // Monitor enemy_values until we find a change from default
        enemy_memory_state.read_enemy_memory_state(handle, module_base_address);
        if !enemy_memory_state.is_zero() {
            // An enemy value has been modified, so we must be in battle
            battle_monitor = true;
        }

        if battle_monitor {
            debug_print!("Writing enemy data.");
            debug_print!("Initial State: {:?}", enemy_memory_state);
            let settings = get_settings();
            enemy_memory_state.write_enemy_memory_state(
                handle,
                module_base_address,
                (
                    settings.experience_multiplier,
                    settings.ap_multiplier,
                    settings.gil_multiplier,
                ),
            );
            debug_print!("Modified State: {:?}\n", enemy_memory_state);

            // Wait for clear message
            'battle_ending: loop {
                memory_state.read_memory_state(handle, module_base_address);

                if memory_state == default_memory_state {
                    // Loop until the correct values are written
                    loop {
                        memory_state.read_memory_state(handle, module_base_address);

                        // if memory_state is not 0s
                        if memory_state != default_memory_state {
                            std::thread::sleep(std::time::Duration::from_millis(6000));
                            // Clear memory state so we can monitor it for changes when we enter the next battle
                            enemy_memory_state.write_enemy_memory_state(
                                handle,
                                module_base_address,
                                (0.0, 0.0, 0.0),
                            );
                            battle_monitor = false;
                            break 'battle_ending;
                        } // end if memory_state != default_memory_state
                    } // loop
                } // end if memory_state == default_memory_state
            } // 'battle_ending
        } // end if battle_monitor

        std::thread::sleep(SLEEP_WHEN_WAITING);
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let key_states = Arc::new(Mutex::new(KeyStates {
        ctrl_num8_was_pressed: false,
        ctrl_num9_was_pressed: false,
    }));

    std::thread::spawn(|| {
        watch();
    });

    let key_listener_states = Arc::clone(&key_states);
    std::thread::spawn(move || {
        keyboard_listener(&key_listener_states);
    });

    let autoplay_key_states = Arc::clone(&key_states);
    std::thread::spawn(move || -> Result<(), String> { run_game_hacks(&autoplay_key_states) });

    // Once this function exits, we will exit main and terminate the program
    close_listener();

    Ok(())
}

fn keyboard_listener(key_listener_states: &Arc<Mutex<KeyStates>>) {
    use winapi::um::winuser::{VK_LCONTROL, /*VK_LMENU,*/ /*VK_LSHIFT,*/ VK_NUMPAD8};

    loop {
        if vk_is_held(VK_LCONTROL) && vk_is_pressed(VK_NUMPAD8) {
            let mut key_states = key_listener_states.lock().unwrap();
            key_states.ctrl_num8_was_pressed = true;
            key_states.ctrl_num9_was_pressed = false;

            println!("Ctrl + Num8 detected...");
        }
        std::thread::sleep(SLEEP_WHEN_WAITING);
    }
}
