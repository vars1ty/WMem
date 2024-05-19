use rayon::iter::{IntoParallelIterator, ParallelIterator};
use std::ffi::{CStr, CString};
use windows::{
    core::{Error, PCSTR},
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::{Debug::*, ToolHelp::*},
            LibraryLoader::*,
            Memory::*,
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
            let mut real_custom_buffer_size =
                custom_buffer_size.unwrap_or(std::mem::size_of::<T>());
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

                // Automatically assign real_custom_buffer_size if the user-specified one is unset.
                if custom_buffer_size.is_none() {
                    real_custom_buffer_size = string.len() + 1;
                }

                let cstring = CString::new(&**string)
                    .expect("Failed converting `String` input into CString!");
                cstring.as_ptr() as _
            } else if generic_cast::equals::<T, &str>() {
                // String found, turn it into bytes and then into a Vec<u8> before returning the
                // pointer.
                let string = generic_cast::cast_ref::<T, &str>(data).unwrap();

                // Automatically assign real_custom_buffer_size if the user-specified one is unset.
                if custom_buffer_size.is_none() {
                    real_custom_buffer_size = string.len() + 1;
                }

                let cstring =
                    CString::new(&**string).expect("Failed converting `&str` input into CString!");
                cstring.as_ptr() as _
            } else {
                data as *const _ as _
            };

            WriteProcessMemory(
                *handle,
                address as _,
                buffer,
                real_custom_buffer_size,
                Some(&mut bytes_written),
            )?;

            if bytes_written != real_custom_buffer_size {
                Error::new(
                    windows::core::HRESULT(4005),
                    "Bytes written isn't the same length as custom_buffer_size!".into(),
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

    /// Partially Parallel signature scanner, use `0x7F` as the wildcard byte.
    /// Returns the offset where the signature/pattern was found.
    fn find_in_signature(signature: &[u8], data: &[u8]) -> Option<Vec<usize>> {
        // Only use Rayon with the first loop, as the second one may otherwise give incorrect
        // results, or have high overhead.
        let results: Vec<usize> = (0..data.len() - signature.len())
            .into_par_iter()
            .filter_map(|i| {
                let mut matched = true;

                // Using the "DELETE"-byte as the wildcard one, since it's highly unlikely to be
                // used in any non-user-defined pattern.
                for (j, &byte) in signature.iter().enumerate() {
                    if byte != 0x7F && data[i + j] != byte {
                        matched = false;
                        continue;
                    }
                }

                if matched {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();

        if results.is_empty() {
            None
        } else {
            Some(results)
        }
    }

    /// Searches for an AoB address in the process's memory, then return all the addresses (if
    /// any).
    /// # Example
    /// ```rust
    /// let handle = ...;
    /// let name = Memory::aob_scan(&handle, b"John Smith").expect("AoB scan failed!");
    /// let pattern = Memory::aob_scan(&handle, &[0x7F, 0x7F, 0x1A, 0x2A, 0x3A]).expect("AoB scan failed!");
    /// println!("Found {} results for 'name', and {} for 'pattern'!", name.len(), pattern.len());
    /// ```
    /// # Wildcards
    /// The `0x7F` byte is reserved as a wildcard-byte.
    ///
    /// # Returns
    /// `Error` if there was an error, or if there were no results.
    /// `Vec<*const i64>` if successful and found any addresses.
    pub fn aob_scan(
        handle: HANDLE,
        signature: &[u8],
        include_exeutable: bool,
    ) -> Result<Vec<*const i64>, Error> {
        unsafe {
            if handle.is_invalid() {
                return Err(Error::new(
                    windows::core::HRESULT(4005),
                    "Invalid HANDLE value!".into(),
                ));
            }

            let sig_ptr = signature.as_ptr();
            static BUFFER_SIZE: usize = (1024 * 1024) / 2;
            let mut addresses = Vec::with_capacity(8);
            let mut address = std::ptr::null();
            let mut info = MEMORY_BASIC_INFORMATION::default();
            let mut bytes_read = 0;

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
                    if !include_exeutable && info.Protect.contains(PAGE_EXECUTE) {
                        continue;
                    }

                    let mut offset = 0;
                    let mut buffer = vec![0; BUFFER_SIZE]; // with_capacity crashes here.

                    while offset < info.RegionSize {
                        let size_to_read = std::cmp::min(BUFFER_SIZE, info.RegionSize - offset);
                        let base_address_w_offset = info.BaseAddress as usize + offset;

                        if ReadProcessMemory(
                            handle,
                            base_address_w_offset as _,
                            buffer.as_mut_ptr() as _,
                            size_to_read,
                            Some(&mut bytes_read),
                        )
                        .is_ok()
                            && bytes_read > 0
                        {
                            if let Some(offset_in_buffer) =
                                Self::find_in_signature(signature, &buffer[..bytes_read])
                            {
                                for offset_in_buffer in offset_in_buffer {
                                    // Found, add into the buffer.
                                    let address =
                                        (base_address_w_offset + offset_in_buffer) as *const i64;
                                    if !addresses.contains(&address) {
                                        addresses.push(address);
                                    }
                                }
                            }
                        }

                        offset += size_to_read;
                    }
                }

                address = (info.BaseAddress as usize + info.RegionSize) as _;
            }

            addresses.retain(|address| *address != sig_ptr as _);
            if addresses.is_empty() {
                Err(Error::new(
                    windows::core::HRESULT(4005),
                    "No results were found!".into(),
                ))
            } else {
                Ok(addresses)
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

            let mut module_entry = MODULEENTRY32 {
                dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
                ..Default::default()
            };
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

                    let _ = CloseHandle(snapshot);
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

            let mut module_entry = MODULEENTRY32 {
                dwSize: std::mem::size_of::<MODULEENTRY32>() as u32,
                ..Default::default()
            };

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

                    let _ = CloseHandle(snapshot);
                }
            }

            Err(Error::new(
                windows::core::HRESULT(4005),
                "Failed finding the desired module!".into(),
            ))
        }
    }

    /// Gets the address to a function inside of a module.
    /// ## Example
    /// ```rust
    /// let result = Memory::get_module_symbol_address(c"opengl32.dll",
    /// c"wglSwapBuffers").expect("Failed finding wglSwapBuffers!");
    /// ```
    pub fn get_module_symbol_address(module: &CStr, symbol: &CStr) -> Option<usize> {
        unsafe {
            GetModuleHandleA(PCSTR(module.as_ptr() as _))
                .ok()
                .and_then(|handle| GetProcAddress(handle, PCSTR(symbol.as_ptr() as _)))
                .map(|result| result as usize)
        }
    }

    /// Reads the data from `sz_module` up until the first null-byte.
    pub fn convert_module_name(sz_module: [u8; 256]) -> Vec<u8> {
        let mut result = sz_module.to_vec();
        // Read up until a null-byte.
        if let Some(position) = result.iter().position(|&byte| byte == 0) {
            result.truncate(position);
        }

        result
    }

    /// Converts a `*const u8` C-String pointer to a `&'static str` if successful.
    /// ## Known Issues
    /// This implementation is **not** bullet-proof, it *can* crash for unexpected reasons.
    /// This implementation also isn't exceptionally fast if used in hot-paths, since it calls the
    /// `Memory::read` function to read 1 byte at `ptr` to ensure that the memory is initialized
    /// and doesn't return an error. This is by no means perfect, but does increase safety by a
    /// bit, after that it calls `CStr::from_ptr`.
    /// ## Example
    /// ```rust
    /// let handle = ...;
    /// let cstr_literal = c"Hello World!";
    /// let result = Memory::ptr_to_string(&handle, cstr_literal.as_ptr() as *const u8).expect("Failed reading
    /// C-String!");
    /// ```
    pub fn ptr_to_string(handle: &HANDLE, ptr: *const u8) -> Option<&'static str> {
        if Self::read::<u8>(handle, ptr as _, Some(1)).is_err() || ptr.is_null() {
            return None;
        }

        unsafe { CStr::from_ptr(ptr as _).to_str() }.ok()
    }
}
