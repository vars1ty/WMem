use std::{
    ffi::{CStr, CString},
    mem::*,
};
use windows::{
    core::Error,
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::{Debug::*, ToolHelp::*},
            Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, *},
            Threading::*,
        },
    },
};

/// WinAPI Memory Manipulation.
pub struct Memory;

impl Memory {
    /// Opens a process by its ID with `PROCESS_ALL_ACCESS`, then returns the `HANDLE`.
    #[inline(always)]
    pub fn open_process_id(process_id: u32) -> Result<HANDLE, Error> {
        unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, process_id) }
    }

    /// Opens the attached process for `PROCESS_ALL_ACCESS`, then returns the `HANDLE`.
    #[inline(always)]
    pub fn open_current_process() -> Result<HANDLE, Error> {
        Self::open_process_id(Self::get_current_process_id())
    }

    /// Returns the current Process's ID.
    #[inline(always)]
    pub fn get_current_process_id() -> u32 {
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
    /// let name = String::from_utf8(Memory::read::<u8>(&handle, address, Some(32)).expect("Failed
    /// reading a slice of bytes")).unwrap();
    ///
    /// // Read the health of the entity.
    /// let health = Memory::read::<i32>(&handle, address, None).expect("Failed reading i32")[0];
    /// ```
    /// Only specify a custom value for `custom_buffer_size` if you're planning on reading a slice
    /// of bytes or similar.
    pub fn read<T: Clone + Default>(
        handle: &HANDLE,
        address: *const i64,
        custom_buffer_size: Option<usize>,
    ) -> Result<Vec<T>, Error> {
        unsafe {
            let custom_buffer_size = custom_buffer_size.unwrap_or(std::mem::size_of::<T>());
            let mut result = vec![T::default(); custom_buffer_size]; // Use `with_capacity` later?
            let mut bytes_read = 0;
            ReadProcessMemory(
                *handle,
                address as _,
                result.as_mut_ptr() as _,
                custom_buffer_size,
                Some(&mut bytes_read),
            )?;

            if bytes_read != custom_buffer_size {
                Error::new(
                    windows::core::HRESULT(4005),
                    "Bytes read isn't the same length as custom_buffer_size!".into(),
                );
            }

            Ok(result)
        }
    }

    /// Writes to the specified address with a custom value.
    /// # Example
    /// ```rust
    /// // Write "Johnny Smith" to the specified address.
    /// let new_name = "Johnny Smith".to_owned();
    /// // + 1 to get a null-byte at the end of the slice when writing it.
    /// Memory::write::<String>(&handle, address, &new_name, Some(new_name.len() +
    /// 1)).expect("Failed writing String!");
    ///
    /// // Write 100 to the specified address.
    /// Memory::write::<i32>(&handle, address, &100, None).expect("Failed writing i32");
    /// ```
    /// Only specify a custom value for `custom_buffer_size` if you're writing an array of bytes.
    pub fn write<T: Clone + Default + 'static>(
        handle: &HANDLE,
        address: *const i64,
        data: &T,
        custom_buffer_size: Option<usize>,
    ) -> Result<(), Error> {
        unsafe {
            let custom_buffer_size = custom_buffer_size.unwrap_or(std::mem::size_of::<T>());
            let mut bytes_written = 0;

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

                // Add a null-byte at the end if there's none.
                if !string.ends_with('\0') {
                    format!("{string}\0").as_ptr() as _
                } else {
                    string.as_ptr() as _
                }
            } else {
                data as *const _ as _
            };

            WriteProcessMemory(
                *handle,
                address as _,
                buffer,
                custom_buffer_size,
                Some(&mut bytes_written),
            )?;

            if bytes_written != custom_buffer_size {
                Error::new(
                    windows::core::HRESULT(4005),
                    "Bytes read isn't the same length as custom_buffer_size!".into(),
                );
            }

            Ok(())
        }
    }

    /// Fills the `address` with *x*-amount null-bytes (`\0`), overriding old content.
    /// The amount is specified through `length`.
    pub fn nullify(handle: &HANDLE, address: *const i64, length: usize) -> Result<(), Error> {
        Self::write::<[u8; 1]>(handle, address, b"\0", Some(length))
    }

    /// Nullifies all bytes starting from the `address`, ends at the `address` + `range_from_address`,
    /// going through all addresses from start (`address`) to finish (`address + range_from_address`).
    /// This is unsafe as it uses `CString::from_raw()` and takes ownership of the byte at the
    /// address, then drops it.
    pub unsafe fn nullify_internal(address: *const i64, range_from_address: i64) {
        // Loop over addresses starting from `address` -> `address + range_from_address`.
        let address = address as i64;
        for i in address..address + range_from_address {
            // Get the string from the address.
            let c_str = CString::from_raw(i as _);
            // Take ownership of the string so we can `drop` it.
            let string = c_str.to_string_lossy().into_owned();
            // Drop the string to free the resources at the address.
            drop(string)
        }
    }

    /// Finds a signature in the specified byte-slice.
    fn find_signature(signature: &[u8], data: &[u8]) -> Option<usize> {
        for i in 0..data.len() - signature.len() {
            let mut matched = true;
            // Enumerate to also get the index of the byte.
            for (j, &byte) in signature.iter().enumerate() {
                // Using the "DELETE"-byte as the wildcard one, since it's highly unlikely to be
                // used in any non-user-defined pattern.
                if byte != 0x7F && data[i + j] != byte {
                    matched = false;
                    break;
                }
            }

            // If matched, return the offset where it was found at.
            if matched {
                return Some(i);
            }
        }
        None
    }

    /// Searches for an AoB address in the process's memory, then return all the addresses (if
    /// any).
    /// # Example
    /// ```rust
    /// let name = Memory::aob_scan(&handle, b"John Smith").expect("AoB scan failed!").expect("Found no results matching your
    /// query!");
    /// let pattern = Memory::aob_scan(&handle, &[0x7F, 0x7F, 0x1A, 0x2A, 0x3A]).expect("AoB scan failed!").expect("Found no results matching your pattern query!");
    /// println!("Found {} results for 'name', and {} for 'pattern'!", name.len(), pattern.len());
    /// ```
    /// # Wildcards
    /// The `0x7F` byte is reserved as a wildcard-byte.
    ///
    /// # Returns
    /// `Error` if unsuccessful.
    /// `None` if successful but found no addresses.
    /// `Some(Vec<*const i64>)` if successful and found any addresses.
    pub fn aob_scan(handle: HANDLE, signature: &[u8]) -> Result<Option<Vec<*const i64>>, Error> {
        unsafe {
            if handle.is_invalid() {
                return Err(Error::new(
                    windows::core::HRESULT(4005),
                    "Invalid HANDLE value!".into(),
                ));
            }

            let mut addresses = Vec::with_capacity(8);
            let mut address = std::ptr::null();
            let mut info: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();
            let mut bytes_read = 0;

            static BUFFER_SIZE: usize = (1024 * 1024) / 2;
            let mut buffer = vec![0; BUFFER_SIZE]; // with_capacity crashes here.

            while VirtualQuery(
                Some(address as _),
                &mut info,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            ) != 0
            {
                // Read any memory with the state of COMMIT.
                if !info.Protect.contains(PAGE_NOACCESS | PAGE_GUARD)
                    && info.State.contains(MEM_COMMIT)
                {
                    let mut offset = 0;
                    while offset < info.RegionSize {
                        let size_to_read = std::cmp::min(BUFFER_SIZE, info.RegionSize - offset);
                        if ReadProcessMemory(
                            handle,
                            (info.BaseAddress as usize + offset) as _,
                            buffer.as_mut_ptr() as _,
                            size_to_read,
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                            && bytes_read > 0
                        {
                            if let Some(offset_in_buffer) =
                                Self::find_signature(signature, &buffer[..bytes_read])
                            {
                                // Found, add into the buffer.
                                let address =
                                    (info.BaseAddress as usize + offset + offset_in_buffer) as _;
                                addresses.push(address);
                            }
                        }

                        offset += size_to_read;
                    }
                }

                address = (info.BaseAddress as usize + info.RegionSize) as _;
            }

            if addresses.is_empty() {
                Ok(None)
            } else {
                Ok(Some(addresses))
            }
        }
    }

    /// Attempts to get all the modules from the currently running process.
    pub fn get_modules() -> Result<Vec<MODULEENTRY32>, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                Self::get_current_process_id(),
            )?;

            let mut module_entry: MODULEENTRY32 = std::mem::zeroed();
            module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;
            let mut modules = vec![];

            // If there's any modules present, begin the loop and store the module in
            // `module_entry`.
            if Module32First(snapshot, &mut module_entry as _).is_ok() {
                loop {
                    modules.push(module_entry);

                    // Keep the loop active until there's no remaining modules, again storing the
                    // module in `module_entry`.
                    if Module32Next(snapshot, &mut module_entry as _).is_ok() {
                        let _ = CloseHandle(snapshot);
                        break;
                    }
                }
            }

            Ok(modules)
        }
    }

    /// Tries to get the module by the specified name.
    /// If `exact` is true, the module name has to match what you specified.
    /// If false, it checks if the name is present in any way, then returns.
    pub fn get_module(module_name: &str, exact: bool) -> Result<MODULEENTRY32, Error> {
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(
                TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                Self::get_current_process_id(),
            )?;

            let mut module_entry: MODULEENTRY32 = std::mem::zeroed();
            module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

            // If there's any modules present, begin the loop and store the module in
            // `module_entry`.
            if Module32First(snapshot, &mut module_entry as _).is_ok() {
                loop {
                    let name = String::from_utf8(Self::convert_module_name(module_entry.szModule))
                        .expect("Failed converting module name to a valid string!");

                    if name == module_name && exact || name.contains(module_name) && !exact {
                        let _ = CloseHandle(snapshot);
                        return Ok(module_entry);
                    }

                    // Keep the loop active until there's no remaining modules, again storing the
                    // module in `module_entry`.
                    if Module32Next(snapshot, &mut module_entry as _).is_ok() {
                        let _ = CloseHandle(snapshot);
                        break;
                    }
                }
            }

            Err(Error::new(
                windows::core::HRESULT(4005),
                "Bytes read isn't the same length as custom_buffer_size!".into(),
            ))
        }
    }

    /// Converts all `i8` values into `u8` and returns it as a `Vec<u8>`, making it valid for
    /// String conversions.
    /// This also removes all null-bytes (`\0`) before returning the result.
    pub fn convert_module_name(sz_module: [u8; 256]) -> Vec<u8> {
        let mut result = sz_module.to_vec();
        result.retain(|&entry| entry != 0); // Keep all bytes that aren't 0.
        result
    }

    /// Converts a `*const u8` pointer (C-String) to a `&'static str` if successful.
    pub fn ptr_to_string(handle: &HANDLE, ptr: *const u8) -> Option<&'static str> {
        // Safety: Read 1 byte using normal read function to see if it's valid, initialized memory.
        if Self::read::<u8>(handle, ptr as _, Some(1)).is_err() || ptr.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(ptr as _).to_str() }.ok()
    }
}
