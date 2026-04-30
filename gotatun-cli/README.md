# GotaTun

## Memory allocation
`gotatun` uses the [system]'s default allocator by default, but other allocators may be enabled via features:

- `mimalloc`: Uses [mi-malloc] as the global memory allocator.

[system]: https://doc.rust-lang.org/std/alloc/struct.System.html
[mi-malloc]: https://microsoft.github.io/mimalloc/
