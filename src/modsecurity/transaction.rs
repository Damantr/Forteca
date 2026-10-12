use std::{
    ffi::{CStr, CString},
    marker::PhantomData,
    ptr::{self, NonNull},
};

use super::{engine::ModSecurity, ffi, rules::Rules};

pub struct Transaction<'a> {
    ptr: NonNull<ffi::Transaction>,
    state: TransactionState,
    _lifetime: PhantomData<(&'a ModSecurity, &'a Rules)>,
    terminal_decision: Option<WafDecision>,
}

impl<'a> Transaction<'a> {
    pub fn new(engine: &'a ModSecurity, rules: &'a Rules) -> Result<Self, String> {
        let ptr =
            unsafe { ffi::msc_new_transaction(engine.as_ptr(), rules.as_ptr(), ptr::null_mut()) };
        let ptr = NonNull::new(ptr).ok_or("Failed to create")?;
        Ok(Self {
            ptr,
            _lifetime: PhantomData,
            state: TransactionState::Created,
            terminal_decision: None,
        })
    }

    pub fn process_uri(&mut self, uri: &str, method: &str, version: &str) -> Result<(), String> {
        if self.state != TransactionState::Created {
            return Err("URI olready processed or invalid state".into());
        }
        let uri = CString::new(uri).map_err(|e| e.to_string())?;

        let method = CString::new(method).map_err(|e| e.to_string())?;

        let version = CString::new(version).map_err(|e| e.to_string())?;

        let result = unsafe {
            ffi::msc_process_uri(
                self.ptr.as_ptr(),
                uri.as_ptr(),
                method.as_ptr(),
                version.as_ptr(),
            )
        };

        Self::check_result(result, "process_uri")?;
        self.state = TransactionState::UriProcessed;
        Ok(())
    }
    pub fn intervention(&mut self) -> WafDecision {
        if let Some(decision) = &self.terminal_decision {
            return decision.clone();
        }

        let mut intervention = ffi::ModSecurityIntervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        };

        let result = unsafe { ffi::msc_intervention(self.ptr.as_ptr(), &mut intervention) };

        let decision = if result == 0 || intervention.disruptive == 0 {
            WafDecision::Allow
        } else if !intervention.url.is_null() {
            let url = unsafe {
                CStr::from_ptr(intervention.url)
                    .to_string_lossy()
                    .into_owned()
            };
            WafDecision::Redirect {
                status: intervention.status as u16,
                url,
            }
        } else {
            WafDecision::Block(intervention.status as u16)
        };

        unsafe {
            ffi::msc_intervention_cleanup(&mut intervention);
        }

        if matches!(
            decision,
            WafDecision::Block(_) | WafDecision::Redirect { .. }
        ) {
            self.state = TransactionState::Interrupted;
            self.terminal_decision = Some(decision.clone());
        }

        decision
    }

    pub fn process_request_headers(&mut self) -> Result<(), String> {
        if self.state != TransactionState::UriProcessed {
            return Err("URI must be processed before".into());
        }

        let result = unsafe { ffi::msc_process_request_headers(self.ptr.as_ptr()) };
        Self::check_result(result, "process_request_headers")?;
        self.state = TransactionState::HeadersProcessed;
        Ok(())
    }

    pub fn append_request_body(&mut self, body: &[u8]) -> i32 {
        unsafe { ffi::msc_append_request_body(self.ptr.as_ptr(), body.as_ptr(), body.len()) }
    }
    pub fn check_result(result: i32, operation: &str) -> Result<(), String> {
        if result == 1 {
            Ok(())
        } else {
            Err(format!("ModSecurity {operation} failed: code {result}"))
        }
    }

    pub fn process_request_body(&mut self) -> Result<(), String> {
        if self.state != TransactionState::HeadersProcessed {
            return Err("Headers must br processed before".into());
        }

        let result = unsafe { ffi::msc_process_request_body(self.ptr.as_ptr()) };
        Self::check_result(result, "process request body")?;
        self.state = TransactionState::BodyProcessed;
        Ok(())
    }

    pub fn add_request_header(&mut self, name: &str, value: &str) -> Result<(), String> {
        let name = name.as_bytes();
        let value = value.as_bytes();
        unsafe {
            ffi::msc_add_n_request_header(
                self.ptr.as_ptr(),
                name.as_ptr(),
                name.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::msc_transaction_cleanup(self.ptr.as_ptr());
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum WafDecision {
    Allow,
    Block(u16),
    Redirect { status: u16, url: String },
}

#[derive(Debug, PartialEq, Eq)]
enum TransactionState {
    Created,
    UriProcessed,
    HeadersProcessed,
    BodyProcessed,
    Interrupted,
}
