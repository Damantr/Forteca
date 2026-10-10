use super::ffi;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::ptr::NonNull;

pub struct Rules {
    ptr: NonNull<ffi::RulesSet>,
}

impl Rules {
    pub fn new() -> Result<Self, &'static str> {
        let ptr = unsafe { ffi::msc_create_rules_set() };
        let ptr = NonNull::new(ptr).ok_or("Failed to create rules set")?;

        Ok(Self { ptr })
    }
    pub(crate) fn as_ptr(&self) -> *mut ffi::RulesSet {
        self.ptr.as_ptr()
    }

    pub fn add(&mut self, rule: &str) -> Result<(), String> {
        let rule = CString::new(rule).map_err(|e| e.to_string())?;
        let mut error: *const c_char = ptr::null();

        let result = unsafe { ffi::msc_rules_add(self.ptr.as_ptr(), rule.as_ptr(), &mut error) };
        if result < 0 {
            let message = if error.is_null() {
                "Unknown ModSec error".to_string()
            } else {
                unsafe { CStr::from_ptr(error).to_string_lossy().into_owned() }
            };
            return Err(message);
        }
        Ok(())
    }
}

impl Drop for Rules {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_rules_cleanup(self.ptr.as_ptr());
        }
    }
}
