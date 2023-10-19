# WMem
A basic Windows Memory Manipulation library, aimed at cheat trainers.

## Usage Example
### Obtaining a handle to the injected process
```rust
let handle = Memory::open_current_process();
/// ...
```

The same works for external usage, but via `open_process_id`

### Writing
```rust
// Write "Johnny Smith" to the specified address.
let new_name = "Johnny Smith".to_owned();
// + 1 to get a null-byte at the end of the slice when writing it.
Memory::write::<String>(handle, address, &new_name, Some(new_name.len() + 1));

// Write 100 to the specified address.
Memory::write::<i32>(handle, address, 100, None);
```

### Reading
```rust
// `read` returns a `Vec<T>` of the type specified for scenarios where you're reading
// an array of bytes.
// If you're just reading a value like `i32` or similar, grab the first entry and continue.

// Read the name of the entity with 32 characters being set as the max capacity.
let name = String::from_utf8(Memory::read::<u8>(handle, address, Some(32))).unwrap();

// Read the health of the entity.
let health = Memory::read::<i32>(handle, address, None)[0];
```
