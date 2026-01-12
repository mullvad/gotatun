# GotaTun

## Memory allocation
By default, `gotatun` use the default system allocator (libc). But it also allows you to use other allocators via features:

- `mimalloc`: Uses [mi-malloc](https://microsoft.github.io/mimalloc/) as global memory allocator.
