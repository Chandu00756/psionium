use libc::{mmap, munmap, PROT_READ, PROT_WRITE, MAP_ANON, MAP_PRIVATE};
use std::ptr;
use crate::utils::PsioniumError;
use log::{info, error};

pub struct PsioniumEnclave {
    key_ptr: *mut u8,
    capacity: usize,
    len: usize,
}

impl PsioniumEnclave {
    pub fn new(size: usize) -> Result<Self, PsioniumError> {
        if size == 0 {
            return Err(PsioniumError::EnclaveInit("Capacity must be non-zero".into()));
        }
        info!("Initializing enclave with capacity: {} bytes", size);
        let key_ptr = unsafe {
            mmap(
                ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIVATE,
                -1,
                0,
            )
        };
        if key_ptr == libc::MAP_FAILED {
            return Err(PsioniumError::EnclaveInit(format!("mmap failed for size {}", size)));
        }
        info!("Enclave memory allocated at {:p}", key_ptr);
        Ok(PsioniumEnclave {
            key_ptr: key_ptr as *mut u8,
            capacity: size,
            len: 0,
        })
    }

    pub fn store_key(&mut self, key_blob: Vec<u8>) -> Result<(), PsioniumError> {
        info!("Storing key of size: {} bytes at {:p}", key_blob.len(), self.key_ptr);
        if key_blob.len() > self.capacity {
            error!("Key blob size {} exceeds capacity {}", key_blob.len(), self.capacity);
            return Err(PsioniumError::EnclaveInit(format!(
                "Key blob size {} exceeds capacity {}",
                key_blob.len(),
                self.capacity
            )));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(key_blob.as_ptr(), self.key_ptr, key_blob.len());
            info!("Key stored successfully");
        }
        self.len = key_blob.len();
        Ok(())
    }

    pub fn retrieve_key(&self) -> Result<&[u8], PsioniumError> {
        info!("Retrieving key of size: {} bytes from {:p}", self.len, self.key_ptr);
        if self.len == 0 {
            return Err(PsioniumError::EnclaveInit("No key stored".into()));
        }
        unsafe { Ok(std::slice::from_raw_parts(self.key_ptr, self.len)) }
    }
}

impl Drop for PsioniumEnclave {
    fn drop(&mut self) {
        info!("Dropping enclave, wiping {} bytes at {:p}", self.capacity, self.key_ptr);
        unsafe {
            std::ptr::write_bytes(self.key_ptr, 0, self.capacity);
            info!("Memory zeroed");
            if munmap(self.key_ptr as *mut _, self.capacity) != 0 {
                error!("munmap failed");
            } else {
                info!("Memory deallocated");
            }
        }
    }
}