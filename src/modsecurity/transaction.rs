use std::{
    ffi::CString,
    marker::PhantomData,
    ptr::{self, NonNull},
};

use super::{engine::ModSecurity, ffi, rules::Rules};

pub struct Transaction<'a> {
    ptr: NonNull<ffi::Transaction>,
    _lifetime: PhantomData<(&'a ModSecurity, &'a Rules)>,
}

impl<'a> Transaction<'a> {
    pub fn new(engine: &'a ModSecurity, rules: &'a Rules) -> Result<Self, String> {
        let ptr =
            unsafe { ffi::msc_new_transaction(engine.as_ptr(), rules.as_ptr(), ptr::null_mut()) };
        let ptr = NonNull::new(ptr).ok_or("Failed to create")?;
        Ok(Self {
            ptr,
            _lifetime: PhantomData,
        })
    }

    pub fn process_uri(&mut self, uri: &str, method: &str, version: &str) -> Result<(), String> {
        let uri = CString::new(uri).map_err(|e| e.to_string())?;

        let method = CString::new(method).map_err(|e| e.to_string())?;

        let version = CString::new(version).map_err(|e| e.to_string())?;

        unsafe {
            ffi::msc_process_uri(
                self.ptr.as_ptr(),
                uri.as_ptr(),
                method.as_ptr(),
                version.as_ptr(),
            );
        }
        Ok(())
    }
    pub fn intervention(&mut self) -> WafDecision {
        let mut intervention = ffi::ModSecurityIntervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        };

        let result = unsafe { ffi::msc_intervention(self.ptr.as_ptr(), &mut intervention) };

        if result == 0 || intervention.disruptive == 0 {
            return WafDecision::Allow;
        }
        WafDecision::Block(intervention.status as u16)
    }

    pub fn process_request_headers(&mut self) -> i32 {
        unsafe { ffi::msc_process_request_headers(self.ptr.as_ptr()) }
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_transaction_cleanup(self.ptr.as_ptr());
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum WafDecision {
    Allow,
    Block(u16),
    Redirect { status: u16, url: String },
}
