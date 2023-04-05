#![allow(clippy::not_unsafe_ptr_arg_deref)]

use memmem::{Searcher, TwoWaySearcher};
use std::{mem::*, ptr::null_mut};
use winapi::um::{
    handleapi::*,
    memoryapi::*,
    processthreadsapi::{GetCurrentProcessId, OpenProcess},
    tlhelp32::*,
    winnt::*,
};

/// Module Search Errors.
#[derive(Debug)]
pub enum ModuleSearchError<'a> {
    NotFound(String),
    InvalidHandleValue(&'a str),
}

/// WinAPI Memory Manipulation.
pub struct Memory;

impl Memory {
    /// Opens the injected process for `PROCESS_ALL_ACCESS`, then returns the `HANDLE`.
    pub fn open_current() -> HANDLE {
        unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, GetCurrentProcessId()) }
    }

    /// Returns the injected process's id.
    pub fn get_current_pid() -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    /// Reads a value from the specified address.
    /// # Example
    /// ```rust
    /// // `read` returns a `Vec<T>` of the type specified for scenarios where you're reading
    /// // an array of bytes.
    /// // If you're just reading a value like `i32` or similar, grab the first entry and continue.
    ///
    /// // Read the name of the entity with 32 characters being set as the max capacity.
    /// let name = String::from_utf8(Memory::read::<u8>(&handle, &address, Some(32))).unwrap();
    ///
    /// // Read the health of the entity.
    /// let health = Memory::read::<i32>(&handle, &address, None)[0];
    /// ```
    /// Only specify a custom value for `custom_buffer_size` if you're planning on reading a slice
    /// of bytes or similar.
    pub fn read<T: Copy + Default>(
        handle: &HANDLE,
        address: &i64,
        custom_buffer_size: Option<usize>,
    ) -> Vec<T> {
        let custom_buffer_size = custom_buffer_size.unwrap_or(size_of::<T>());
        let mut result = Vec::with_capacity(custom_buffer_size);
        unsafe {
            ReadProcessMemory(
                *handle,
                *address as _,
                result.as_mut_ptr() as _,
                custom_buffer_size,
                null_mut(),
            );
        }

        result
    }

    /// Writes to the specified address with a custom value.
    /// # Example
    /// ```rust
    /// // Write "Johnny Smith" to the specified address.
    /// let new_name = b"Johnny Smith";
    /// // + 1 to get a null-byte at the end of the slice when writing it.
    /// Memory::write::<[u8; 12]>(&handle, &address, &*new_name, Some(new_name.len() + 1));
    ///
    /// // Write 100 to the specified address.
    /// Memory::write::<i32>(&handle, &address, &100, None);
    /// ```
    /// Only specify a custom value for `custom_buffer_size` if you're writing an array of bytes.
    pub fn write<T: Clone + Default + 'static>(
        handle: &HANDLE,
        address: &i64,
        data: &T,
        custom_buffer_size: Option<usize>,
    ) {
        let custom_buffer_size = custom_buffer_size.unwrap_or(size_of::<T>());

        // Based on the type, execute special behavior to make it easier for the user to interact
        // with the memory.
        let buffer = if generic_cast::equals::<T, Vec<u8>>() {
            // Array of Bytes found, cast to Vec<u8> and then into a pointer, otherwise writing
            // will fail.
            generic_cast::cast_ref::<T, Vec<u8>>(data).unwrap().as_ptr() as _
        } else if generic_cast::equals::<T, String>() {
            // String found, turn it into bytes and then into a Vec<u8> before returning the
            // pointer.
            let string = generic_cast::cast_ref::<T, String>(data).unwrap();
            string.as_bytes().to_vec().as_ptr() as _
        } else {
            data as *const _ as _
        };

        unsafe {
            WriteProcessMemory(
                *handle,
                *address as _,
                buffer,
                custom_buffer_size,
                null_mut(),
            );
        }
    }

    /// Fills the `address` with *x*-amount null-bytes (`\0`), overriding old content.
    /// The amount is specified through `length`.
    pub fn nullify(handle: &HANDLE, address: &i64, length: usize) {
        Self::write::<[u8; 1]>(handle, address, b"\0", Some(length))
    }

    /// Searches for an AoB address in the process's memory, then return all the addresses (if
    /// any).
    /// # Example
    /// ```rust
    /// let name = Memory::aob_scan(&handle, b"John Smith").expect("Found no results matching your
    /// query!");
    /// println!("Found {} matches!", name.len());
    /// ```
    pub fn aob_scan(handle: &HANDLE, aob: &[u8]) -> Option<Vec<*mut i64>> {
        let mut address = null_mut();
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
        let mut bytes_read = 0;
        let mut addresses = vec![];
        let searcher = TwoWaySearcher::new(aob);

        loop {
            let result = unsafe {
                VirtualQueryEx(
                    *handle,
                    address,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };

            if result == 0 {
                break;
            }

            if (info.State & 0x1000) != 0
                && (info.Protect & PAGE_READWRITE == PAGE_READWRITE
                    || info.Protect & PAGE_WRITECOPY == PAGE_WRITECOPY)
            {
                let mut buffer = Vec::with_capacity(info.RegionSize);
                let result = unsafe {
                    ReadProcessMemory(
                        *handle,
                        info.BaseAddress,
                        buffer.as_mut_ptr() as _,
                        info.RegionSize,
                        &mut bytes_read,
                    )
                };

                if result == 1 && bytes_read > 0 {
                    // Reading was successful and the bytes read was more than 0, continue.
                    unsafe {
                        buffer.set_len(bytes_read);
                    }

                    // Search for the AoB inside the buffer, from start -> bytes_read.
                    if let Some(offset) = searcher.search_in(&buffer[..bytes_read]) {
                        // Found, add the address.
                        let address = (info.BaseAddress as usize + offset) as *mut i64;
                        addresses.push(address);
                    }
                }
            }

            address = (info.BaseAddress as usize + info.RegionSize) as _;
        }

        if addresses.is_empty() {
            None
        } else {
            Some(addresses)
        }
    }

    /// Attempts to get all the modules from the currently running process.
    pub fn get_modules() -> Result<Vec<MODULEENTRY32>, ModuleSearchError<'static>> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                GetCurrentProcessId(),
            )
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(ModuleSearchError::InvalidHandleValue(
                "Failed retrieving a valid snapshot handle!",
            ));
        }

        let mut module_entry: MODULEENTRY32 = unsafe { zeroed() };
        module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;
        let mut modules = vec![];

        // If there's any modules present, begin the loop and store the module in
        // `module_entry`.
        if unsafe { Module32First(snapshot, &mut module_entry as _) } != 0 {
            loop {
                modules.push(module_entry);

                // Keep the loop active until there's no remaining modules, again storing the
                // module in `module_entry`.
                if unsafe { Module32Next(snapshot, &mut module_entry as _) } == 0 {
                    unsafe {
                        CloseHandle(snapshot);
                    }
                    break;
                }
            }
        }

        Ok(modules)
    }

    /// Tries to get the module by the specified name.
    /// If `exact` is true, the module name has to match what you specified.
    /// If false, it checks if the name is present in any way, then returns.
    pub fn get_module(module_name: &str, exact: bool) -> Result<MODULEENTRY32, ModuleSearchError> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                GetCurrentProcessId(),
            )
        };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(ModuleSearchError::InvalidHandleValue(
                "Failed retrieving a valid snapshot handle!",
            ));
        }

        let mut module_entry: MODULEENTRY32 = unsafe { zeroed() };
        module_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

        // If there's any modules present, begin the loop and store the module in
        // `module_entry`.
        if unsafe { Module32First(snapshot, &mut module_entry as _) } != 0 {
            loop {
                let name = String::from_utf8(Self::convert_module_name(module_entry.szModule))
                    .expect("Failed converting module name to a valid string!");

                if name == module_name && exact || name.contains(module_name) && !exact {
                    unsafe {
                        CloseHandle(snapshot);
                    }
                    return Ok(module_entry);
                }

                unsafe {
                    CloseHandle(snapshot);
                }

                // Keep the loop active until there's no remaining modules, again storing the
                // module in `module_entry`.
                if unsafe { Module32Next(snapshot, &mut module_entry as _) } == 0 {
                    break;
                }
            }
        }

        Err(ModuleSearchError::NotFound(format!(
            "No modules matching `{module_name}` was found."
        )))
    }

    /// Converts all `i8` values into `u8` and returns it as a `Vec<u8>`, making it valid for
    /// String conversions.
    /// This also removes all null-bytes (`\0`) before returning the result.
    fn convert_module_name(sz_module: [i8; 256]) -> Vec<u8> {
        let mut result = sz_module.map(|entry| entry as u8).to_vec();
        result.retain(|&entry| entry != 0); // Keep all bytes that aren't 0.
        result
    }
}
