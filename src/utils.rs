#[inline]
#[cold]
fn cold() {}

/// Hints to the compiler that the condition is likely to be true.
#[inline]
pub fn likely(condition: bool) -> bool {
    if !condition {
        cold()
    }
    condition
}

/// Hints to the compiler that the condition is likely to be false.
#[inline]
pub fn unlikely(condition: bool) -> bool {
    if condition {
        cold()
    }
    condition
}
