use tss_esapi::{
    interface_types::{
        resource_handles::NvIndex,
    },
    Context, TctiNameConf,
    structures::NvPublicBuilder,
};

#[derive(Debug)]
pub enum NonceError {
    CounterReadFailed,
    CounterIncrementFailed,
    InitializationFailed,
    TpmUnavailable,
}

pub struct TpmNonce {
    index: NvIndex,
}

impl TpmNonce {
    /// Initialize monotonic counter at specific NV index (e.g. 0x01500001)
    pub fn new(index_handle: u32) -> Result<Self, NonceError> {
        // In real implementation, we check if index exists, create if not.
        // Requires Owner Auth usually.
        Ok(Self {
            index: NvIndex::try_from(index_handle).map_err(|_| NonceError::InitializationFailed)?,
        })
    }

    /// Read current counter value
    pub fn read(&mut self) -> Result<u64, NonceError> {
        let mut context = Context::new(
            TctiNameConf::from_environment_variable().map_err(|_| NonceError::TpmUnavailable)?
        ).map_err(|_| NonceError::TpmUnavailable)?;
        
        let (data, _) = context.nv_read(
            self.index,
            self.index, // auth handle (assuming owner/index auth needed)
            8, // size (u64)
            0  // offset
        ).map_err(|_| NonceError::CounterReadFailed)?;

        // Convert bytes to u64
        if data.len() < 8 {
            return Err(NonceError::CounterReadFailed);
        }
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&data[0..8]);
        Ok(u64::from_be_bytes(bytes))
    }

    /// Increment counter
    pub fn increment(&mut self) -> Result<(), NonceError> {
        let mut context = Context::new(
            TctiNameConf::from_environment_variable().map_err(|_| NonceError::TpmUnavailable)?
        ).map_err(|_| NonceError::TpmUnavailable)?;

        context.nv_increment(
            self.index,
            self.index // auth handle
        ).map_err(|_| NonceError::CounterIncrementFailed)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires hardware TPM
    fn test_tpm_nonce_hardware() {
        let mut nonce = TpmNonce::new(0x01500001).unwrap();
        // Since this requires hardware, we just ensure it compiles.
        // We'd expect this to fail if no TPM is present or provisioned.
        let _ = nonce.read();
    }
}
