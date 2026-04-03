// firmware/src/nvs.rs
//
// NVS storage for root secret. Plaintext NVS — encryption deferred.

use esp_idf_svc::nvs::{EspDefaultNvsPartition, EspNvs, NvsDefault};

const NVS_NAMESPACE: &str = "heartwood";
const NVS_KEY: &str = "root_secret";

/// Read the root secret from NVS. Returns None if not provisioned.
pub fn read_root_secret(
    nvs_partition: EspDefaultNvsPartition,
) -> Result<(EspNvs<NvsDefault>, Option<[u8; 32]>), &'static str> {
    let nvs = EspNvs::new(nvs_partition, NVS_NAMESPACE, true)
        .map_err(|_| "failed to open NVS namespace")?;

    let mut buf = [0u8; 32];
    match nvs.get_blob(NVS_KEY, &mut buf) {
        Ok(Some(bytes)) => {
            if bytes.len() == 32 {
                Ok((nvs, Some(buf)))
            } else {
                Ok((nvs, None))
            }
        }
        Ok(None) => Ok((nvs, None)),
        Err(_) => Ok((nvs, None)),
    }
}

/// Write the root secret to NVS.
pub fn write_root_secret(
    nvs: &mut EspNvs<NvsDefault>,
    secret: &[u8; 32],
) -> Result<(), &'static str> {
    nvs.set_blob(NVS_KEY, secret)
        .map_err(|_| "failed to write root secret to NVS")
}
