//! Current-user DPAPI software identity; no TPM or machine-wide trust mutation.
use crate::{
    DeviceKey, Fingerprint, Result, error, fingerprint_from_smbios, require, sha256, uuid,
};
use std::{
    ffi::{OsStr, c_void},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{Authorization::*, Cryptography::*, *},
    System::{
        SystemInformation::GetSystemFirmwareTable,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};
use zeroize::{Zeroize, Zeroizing};

struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void, usize);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                if self.1 > 0 {
                    std::slice::from_raw_parts_mut(self.0.cast::<u8>(), self.1).zeroize();
                }
                LocalFree(self.0);
            }
        }
    }
}
fn wide(value: &OsStr) -> Result<Vec<u16>> {
    let mut bytes: Vec<u16> = value.encode_wide().collect();
    require(!bytes.contains(&0), "INVALID_IDENTITY_ROOT")?;
    bytes.push(0);
    Ok(bytes)
}
fn no_links(path: &Path) -> Result<()> {
    for current in path.ancestors() {
        match fs::symlink_metadata(current) {
            Ok(meta) => require(
                meta.file_attributes() & 0x400 == 0,
                "IDENTITY_PATH_REDIRECTED",
            )?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(error("IDENTITY_STORE_UNAVAILABLE")),
        }
    }
    Ok(())
}
fn private_directory(path: &Path) -> Result<()> {
    // Token buffer uses usize alignment because TOKEN_USER contains pointer fields.
    unsafe {
        let mut raw = null_mut();
        require(
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) != 0,
            "WINDOWS_USER_UNAVAILABLE",
        )?;
        let token = Handle(raw);
        let mut length = 0;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut length);
        require(
            length as usize >= size_of::<TOKEN_USER>() && length <= 65536,
            "WINDOWS_USER_UNAVAILABLE",
        )?;
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        require(
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                length,
                &mut length,
            ) != 0,
            "WINDOWS_USER_UNAVAILABLE",
        )?;
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        let mut sid_string = null_mut();
        require(
            ConvertSidToStringSidW(user.User.Sid, &mut sid_string) != 0,
            "WINDOWS_USER_UNAVAILABLE",
        )?;
        let _sid = Local(sid_string.cast(), 0);
        let mut chars = 0;
        while *sid_string.add(chars) != 0 {
            chars += 1;
        }
        let sid = String::from_utf16(std::slice::from_raw_parts(sid_string, chars))
            .map_err(|_| error("WINDOWS_USER_UNAVAILABLE"))?;
        let sddl = wide(OsStr::new(&format!("O:{sid}D:P(A;OICI;FA;;;{sid})")))?;
        let mut descriptor = null_mut();
        require(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            ) != 0,
            "IDENTITY_ACL_FAILED",
        )?;
        let _descriptor = Local(descriptor, 0);
        let mut dacl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        require(
            GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) != 0
                && present != 0
                && !dacl.is_null(),
            "IDENTITY_ACL_FAILED",
        )?;
        let path = wide(path.as_os_str())?;
        require(
            SetNamedSecurityInfoW(
                path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION
                    | OWNER_SECURITY_INFORMATION,
                user.User.Sid,
                null_mut(),
                dacl,
                null(),
            ) == 0,
            "IDENTITY_ACL_FAILED",
        )?;
    }
    Ok(())
}
fn crypt(bytes: &[u8], entropy: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>> {
    require(
        bytes.len() <= 4096 && entropy.len() <= 1024,
        "INVALID_DEVICE_KEY_FILE",
    )?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    unsafe {
        let ok = if protect {
            CryptProtectData(
                &input,
                null(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                null_mut(),
                &entropy,
                null(),
                null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        let _output = Local(output.pbData.cast(), output.cbData as usize);
        require(ok != 0, "DEVICE_KEY_UNAVAILABLE")?;
        require(
            !output.pbData.is_null() && output.cbData > 0 && output.cbData <= 4096,
            "INVALID_DEVICE_KEY_FILE",
        )?;
        Ok(Zeroizing::new(
            std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec(),
        ))
    }
}
fn lock(path: &Path) -> Result<File> {
    let started = Instant::now();
    loop {
        no_links(path)?;
        match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .share_mode(0)
            .open(path)
        {
            Ok(file) => return Ok(file),
            Err(e)
                if matches!(e.raw_os_error(), Some(32 | 33))
                    && started.elapsed() < Duration::from_secs(10) =>
            {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(_) => return Err(error("IDENTITY_STORE_UNAVAILABLE")),
        }
    }
}
fn read(path: &Path, entropy: &[u8]) -> Result<DeviceKey> {
    no_links(path)?;
    let mut file = File::open(path).map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?;
    let length = file
        .metadata()
        .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?
        .len();
    require(length > 0 && length <= 4096, "INVALID_DEVICE_KEY_FILE")?;
    let mut cipher = Vec::new();
    file.read_to_end(&mut cipher)
        .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?;
    let seed = crypt(&cipher, entropy, false)?;
    require(seed.len() == 32, "INVALID_DEVICE_KEY_FILE")?;
    DeviceKey::from_ed25519_seed(
        seed.as_slice()
            .try_into()
            .map_err(|_| error("INVALID_DEVICE_KEY_FILE"))?,
    )
}
/// Uses the same format, domain separator and lock as the .NET SDK. Corruption never generates a replacement key.
pub fn load_or_create_key(
    product_id: &str,
    account_id: &str,
    storage_root: Option<&Path>,
    allow_creation: bool,
) -> Result<DeviceKey> {
    let valid_id = !product_id.is_empty()
        && product_id.len() <= 80
        && product_id.as_bytes()[0].is_ascii_alphanumeric()
        && product_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    require(valid_id, "INVALID_IDENTIFIER")?;
    require(uuid(account_id), "INVALID_ACCOUNT_ID")?;
    let account = account_id.to_ascii_lowercase();
    let root = match storage_root {
        Some(root) => root.to_path_buf(),
        None => {
            PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(error("INVALID_IDENTITY_ROOT"))?)
                .join("ProductLicenseKit")
                .join("Identity")
        }
    };
    require(root.is_absolute(), "INVALID_IDENTITY_ROOT")?;
    let directory = root.join(sha256(product_id.as_bytes())).join(&account);
    no_links(&directory)?;
    require(
        allow_creation
            || directory
                .join("device.key")
                .try_exists()
                .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?,
        "DEVICE_KEY_NOT_FOUND",
    )?;
    fs::create_dir_all(&directory).map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?;
    no_links(&directory)?;
    private_directory(&directory)?;
    let _guard = lock(&directory.join("identity.lock"))?;
    let path = directory.join("device.key");
    let entropy = format!("product-license-kit-device-v1\0{product_id}\0{account}");
    if path
        .try_exists()
        .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?
    {
        return read(&path, entropy.as_bytes());
    }
    no_links(&path)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| error("RANDOM_UNAVAILABLE"))?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| error("RANDOM_UNAVAILABLE"))?;
    let temporary = directory.join(format!("{}.tmp", crate::base64url(&nonce)));
    let mut owns_temporary = false;
    let result = (|| {
        let cipher = crypt(seed.as_ref(), entropy.as_bytes(), true)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .share_mode(0)
            .open(&temporary)
            .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?;
        owns_temporary = true;
        file.write_all(&cipher)
            .and_then(|_| file.sync_all())
            .map_err(|_| error("IDENTITY_STORE_UNAVAILABLE"))?;
        drop(file);
        // Windows rename with no REPLACE_EXISTING. Never overwrite a separately committed identity.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
        }
        let from = wide(temporary.as_os_str())?;
        let to = wide(path.as_os_str())?;
        require(
            unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 8) } != 0,
            "IDENTITY_STORE_UNAVAILABLE",
        )?;
        read(&path, entropy.as_bytes())
    })();
    if owns_temporary && temporary.exists() {
        fs::remove_file(&temporary).map_err(|_| error("IDENTITY_TEMP_CLEANUP_FAILED"))?;
    }
    result
}
pub fn read_fingerprint(product_id: &str, schema: &str) -> Result<Fingerprint> {
    const RSMB: u32 = 0x52534d42;
    let length = unsafe { GetSystemFirmwareTable(RSMB, 0, null_mut(), 0) };
    require(
        length > 0 && length <= 1048576,
        "HARDWARE_IDENTIFIER_UNAVAILABLE",
    )?;
    let mut bytes = Zeroizing::new(vec![0u8; length as usize]);
    require(
        unsafe { GetSystemFirmwareTable(RSMB, 0, bytes.as_mut_ptr(), length) } == length,
        "HARDWARE_IDENTIFIER_UNAVAILABLE",
    )?;
    fingerprint_from_smbios(&bytes, product_id, schema)
}
