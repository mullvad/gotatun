# GotaTun

## Memory allocation
`gotatun` uses the [system]'s default allocator by default, but other allocators may be enabled via features:

- `mimalloc`: Uses [mi-malloc] as the global memory allocator.
- `jemalloc`: Uses [jemalloc] as the global memory allocator (Currently not available for Windows).

[system]: https://doc.rust-lang.org/std/alloc/struct.System.html
[mi-malloc]: https://microsoft.github.io/mimalloc/
[jemalloc]: https://github.com/jemalloc/jemalloc
