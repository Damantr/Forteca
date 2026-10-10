use super::ffi;
use std::ptr::NonNull;

pub struct ModSecurity {
    ptr: NonNull<ffi::ModSecurity>,
}

impl ModSecurity {
    pub fn new() -> Result<Self, &'static str> {
        let ptr = unsafe { ffi::msc_init() };
        let ptr = NonNull::new(ptr).ok_or("Failed to initialize ModSecurity")?;
        Ok(Self { ptr })
    }
    pub(crate) fn as_ptr(&self) -> *mut ffi::ModSecurity {
        self.ptr.as_ptr()
    }
}

impl Drop for ModSecurity {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_cleanup(self.ptr.as_ptr());
        }
    }
}
