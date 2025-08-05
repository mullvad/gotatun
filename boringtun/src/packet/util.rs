/// Assert that the size of type `T` is `size`. If not, panic.
#[allow(dead_code)] // lies
pub const fn assert_size<T>(size: usize) {
    if size_of::<T>() != size {
        panic!("Size of T is wrong!")
    }
}
