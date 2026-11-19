//! Native headless client for the Product License Kit protocol. Server trust is supplied by the host.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rsa::{
    pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding},
    sha2::{Digest, Sha256},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{fmt, io::Read, time::Duration};
use zeroize::Zeroizing;
mod strict_json;
#[cfg(windows)]
pub mod windows;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: &'static str,
    pub status: Option<u16>,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;
fn error(code: &'static str) -> Error {
    Error { code, status: None }
}
fn require(condition: bool, code: &'static str) -> Result<()> {
    if condition { Ok(()) } else { Err(error(code)) }
}
pub fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
pub fn base64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode_base64url(value: &str) -> Result<Vec<u8>> {
    require(
        !value.is_empty()
            && value.len() < 16384
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "INVALID_BASE64URL",
    )?;
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| error("INVALID_BASE64URL"))?;
    require(base64url(&bytes) == value, "NONCANONICAL_BASE64URL")?;
    Ok(bytes)
}
pub fn parse_json(bytes: &[u8]) -> Result<Value> {
    strict_json::parse(bytes).map_err(|_| error("INVALID_JSON"))
}
const ED_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
fn public_der(pem: &str) -> Result<Vec<u8>> {
    require(pem.len() <= 2048, "INVALID_PUBLIC_KEY")?;
    let inner = pem
        .trim()
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|s| s.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or(error("INVALID_PUBLIC_KEY"))?;
    require(
        inner.starts_with('\n') || inner.starts_with("\r\n"),
        "INVALID_PUBLIC_KEY",
    )?;
    require(
        inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=\r\n".contains(&b)),
        "INVALID_PUBLIC_KEY",
    )?;
    let encoded: String = inner
        .chars()
        .filter(|c| !matches!(c, '\r' | '\n'))
        .collect();
    let der = STANDARD
        .decode(&encoded)
        .map_err(|_| error("INVALID_PUBLIC_KEY"))?;
    require(STANDARD.encode(&der) == encoded, "INVALID_PUBLIC_KEY")?;
    Ok(der)
}
fn server_public_key(pem: &str) -> Result<VerifyingKey> {
    let der = public_der(pem)?;
    require(
        der.len() == 44 && der.starts_with(&ED_PREFIX),
        "ED25519_REQUIRED",
    )?;
    VerifyingKey::from_bytes(
        der[12..]
            .try_into()
            .map_err(|_| error("INVALID_PUBLIC_KEY"))?,
    )
    .map_err(|_| error("INVALID_PUBLIC_KEY"))
}
fn validate_rsa(key: &rsa::PublicKey) -> Result<()> {
    let exponent = key.e().to_be_bytes();
    let trimmed: Vec<u8> = exponent.iter().copied().skip_while(|b| *b == 0).collect();
    require(
        key.n().bit_width_vartime() == 2048 && trimmed == [1, 0, 1],
        "INVALID_DEVICE_KEY",
    )
}
pub fn device_thumbprint(pem: &str) -> Result<String> {
    let der = public_der(pem)?;
    if der.len() == 44 {
        server_public_key(pem)?;
    } else {
        let key =
            rsa::PublicKey::from_public_key_der(&der).map_err(|_| error("INVALID_DEVICE_KEY"))?;
        validate_rsa(&key)?;
        require(
            key.to_public_key_der()
                .map_err(|_| error("INVALID_DEVICE_KEY"))?
                .as_bytes()
                == der,
            "INVALID_DEVICE_KEY",
        )?;
    }
    Ok(sha256(&der))
}
fn text<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    value
        .get(name)
        .and_then(Value::as_str)
        .ok_or(error("INVALID_CLAIMS"))
}
fn integer(value: &Value, name: &str) -> Result<i64> {
    let number = value
        .get(name)
        .and_then(Value::as_i64)
        .ok_or(error("INVALID_CLAIMS"))?;
    require(
        (-9007199254740991..=9007199254740991).contains(&number),
        "INVALID_CLAIMS",
    )?;
    Ok(number)
}
fn shape(value: &Value, names: &[&str]) -> Result<()> {
    require(
        value
            .as_object()
            .is_some_and(|m| m.len() == names.len() && names.iter().all(|n| m.contains_key(*n))),
        "INVALID_CLAIMS",
    )
}
pub fn verify_envelope(
    token: &str,
    trusted_public_key: &str,
    expected_type: &str,
) -> Result<Value> {
    require(token.len() < 16384, "INVALID_ENVELOPE")?;
    let parts: Vec<&str> = token.split('.').collect();
    require(parts.len() == 3, "INVALID_ENVELOPE")?;
    let key = server_public_key(trusted_public_key)?;
    let header = parse_json(&decode_base64url(parts[0])?)?;
    shape(&header, &["alg", "typ", "kid"])?;
    require(
        text(&header, "alg")? == "EdDSA"
            && text(&header, "typ")? == expected_type
            && text(&header, "kid")? == &sha256(&public_der(trusted_public_key)?)[..24],
        "INVALID_ENVELOPE_HEADER",
    )?;
    let body = decode_base64url(parts[1])?;
    let signature = ed25519_dalek::Signature::from_slice(&decode_base64url(parts[2])?)
        .map_err(|_| error("INVALID_SIGNATURE"))?;
    key.verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
        .map_err(|_| error("INVALID_SIGNATURE"))?;
    parse_json(&body)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    pub schema: String,
    pub digest: String,
}
#[derive(Clone)]
pub struct LicenseScope {
    pub issuer: String,
    pub product_id: String,
    pub edition_id: String,
    pub account_id: String,
    pub device_id: String,
    pub device_public_key: String,
    pub fingerprint: Fingerprint,
    pub channel: String,
    pub generation: Option<i64>,
}
pub fn verify_license(
    token: &str,
    trusted_public_key: &str,
    expected: &LicenseScope,
    now_seconds: i64,
) -> Result<Value> {
    let claims = verify_envelope(token, trusted_public_key, "plk-license")?;
    shape(
        &claims,
        &[
            "iss",
            "aud",
            "sub",
            "edition",
            "device",
            "channel",
            "fingerprint",
            "keyThumbprint",
            "generation",
            "ownership",
            "iat",
            "nbf",
            "exp",
        ],
    )?;
    require(
        matches!(expected.channel.as_str(), "stable" | "beta"),
        "INVALID_CHANNEL",
    )?;
    for (name, value) in [
        ("iss", &expected.issuer),
        ("aud", &expected.product_id),
        ("sub", &expected.account_id),
        ("edition", &expected.edition_id),
        ("device", &expected.device_id),
        ("channel", &expected.channel),
    ] {
        require(text(&claims, name)? == value, "LICENSE_SCOPE_MISMATCH")?;
    }
    let fingerprint = claims.get("fingerprint").ok_or(error("INVALID_CLAIMS"))?;
    shape(fingerprint, &["schema", "digest"])?;
    require(
        expected.fingerprint.digest.len() == 64
            && expected
                .fingerprint
                .digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && text(fingerprint, "schema")? == expected.fingerprint.schema
            && text(fingerprint, "digest")? == expected.fingerprint.digest
            && text(&claims, "keyThumbprint")? == device_thumbprint(&expected.device_public_key)?,
        "LICENSE_SCOPE_MISMATCH",
    )?;
    let generation = integer(&claims, "generation")?;
    require(
        generation > 0 && text(&claims, "ownership")? == "perpetual",
        "INVALID_CLAIMS",
    )?;
    require(
        expected.generation.is_none_or(|g| g == generation),
        "LICENSE_SCOPE_MISMATCH",
    )?;
    let issued = integer(&claims, "iat")?;
    let not_before = integer(&claims, "nbf")?;
    let expires = integer(&claims, "exp")?;
    require(
        issued <= now_seconds
            && not_before <= now_seconds
            && expires > now_seconds
            && expires > issued
            && expires > not_before,
        "LICENSE_EXPIRED_OR_NOT_YET_VALID",
    )?;
    Ok(claims)
}
pub fn verify_distribution(
    token: &str,
    trusted_public_key: &str,
    artifact: &[u8],
    distribution_id: &str,
    edition_id: &str,
    release_id: &str,
) -> Result<Value> {
    let manifest = verify_envelope(token, trusted_public_key, "plk-distribution")?;
    shape(
        &manifest,
        &[
            "distributionId",
            "editionId",
            "releaseId",
            "sha256",
            "issuedAt",
        ],
    )?;
    integer(&manifest, "issuedAt")?;
    require(
        text(&manifest, "distributionId")? == distribution_id
            && text(&manifest, "editionId")? == edition_id
            && text(&manifest, "releaseId")? == release_id
            && text(&manifest, "sha256")? == sha256(artifact),
        "DISTRIBUTION_MISMATCH",
    )?;
    Ok(manifest)
}
enum SigningMaterial {
    Ed25519(Box<SigningKey>),
    Rsa(Box<rsa::PrivateKey>),
}
pub struct DeviceKey {
    material: SigningMaterial,
    public_key: String,
}
impl DeviceKey {
    pub fn from_ed25519_seed(seed: &[u8; 32]) -> Result<Self> {
        let key = SigningKey::from_bytes(seed);
        let mut der = ED_PREFIX.to_vec();
        der.extend(key.verifying_key().to_bytes());
        Ok(Self {
            public_key: format!(
                "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                STANDARD.encode(der)
            ),
            material: SigningMaterial::Ed25519(Box::new(key)),
        })
    }
    pub fn generate_ed25519() -> Result<Self> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| error("RANDOM_UNAVAILABLE"))?;
        Self::from_ed25519_seed(&seed)
    }
    pub fn from_rsa(key: rsa::PrivateKey) -> Result<Self> {
        let public = key.to_public_key();
        validate_rsa(&public)?;
        let pem = public
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| error("INVALID_DEVICE_KEY"))?;
        Ok(Self {
            public_key: pem,
            material: SigningMaterial::Rsa(Box::new(key)),
        })
    }
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
    pub fn sign_enrollment(
        &self,
        message: &str,
        challenge_id: &str,
        account_id: &str,
        group_id: &str,
        fingerprint: &Fingerprint,
    ) -> Result<String> {
        self.sign(message, "enroll", challenge_id, account_id, &json!({"groupId":group_id,"publicKey":self.public_key,"thumbprint":device_thumbprint(&self.public_key)?,"fingerprint":fingerprint}))
    }
    pub fn sign_license(
        &self,
        message: &str,
        challenge_id: &str,
        scope: &LicenseScope,
    ) -> Result<String> {
        require(
            matches!(scope.channel.as_str(), "stable" | "beta")
                && scope.generation.is_some_and(|g| g > 0),
            "INVALID_CHALLENGE",
        )?;
        self.sign(message,"license",challenge_id,&scope.account_id,&json!({"deviceId":scope.device_id,"editionId":scope.edition_id,"channel":scope.channel,"generation":scope.generation}))
    }
    fn sign(
        &self,
        message: &str,
        kind: &str,
        challenge_id: &str,
        account_id: &str,
        payload: &Value,
    ) -> Result<String> {
        require(message.len() < 16384, "INVALID_CHALLENGE")?;
        let value = parse_json(message.as_bytes())?;
        let array = value.as_array().ok_or(error("INVALID_CHALLENGE"))?;
        require(array.len() == 7, "INVALID_CHALLENGE")?;
        require(
            array[0] == "product-license-kit"
                && array[1].as_i64() == Some(1)
                && array[2] == kind
                && array[3] == challenge_id
                && array[4] == account_id
                && uuid(challenge_id)
                && uuid(account_id)
                && &array[5] == payload
                && array[6]
                    .as_str()
                    .is_some_and(|s| decode_base64url(s).is_ok_and(|b| b.len() == 32)),
            "CHALLENGE_SCOPE_MISMATCH",
        )?;
        let bytes = match &self.material {
            SigningMaterial::Ed25519(key) => key.sign(message.as_bytes()).to_bytes().to_vec(),
            SigningMaterial::Rsa(key) => key
                .pss_sign::<Sha256>(message.as_bytes())
                .map_err(|_| error("DEVICE_SIGN_FAILED"))?,
        };
        Ok(base64url(&bytes))
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
pub struct LicenseClient {
    origin: reqwest::Url,
    http: reqwest::blocking::Client,
}
impl LicenseClient {
    pub fn new(base_url: &str) -> Result<Self> {
        let origin = reqwest::Url::parse(base_url).map_err(|_| error("INVALID_SERVER_URL"))?;
        require(
            origin.username().is_empty()
                && origin.password().is_none()
                && origin.path() == "/"
                && origin.query().is_none()
                && origin.fragment().is_none(),
            "INVALID_SERVER_URL",
        )?;
        require(
            origin.scheme() == "https"
                || origin.scheme() == "http"
                    && matches!(
                        origin.host_str(),
                        Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
                    ),
            "HTTPS_REQUIRED",
        )?;
        let http = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|_| error("HTTP_CLIENT_FAILED"))?;
        Ok(Self { origin, http })
    }
    pub fn request(
        &self,
        path: &str,
        body: Option<&Value>,
        access_token: Option<&str>,
        idempotency_key: Option<&str>,
    ) -> Result<Value> {
        let (route, query) = path.split_once('?').unwrap_or((path, ""));
        require(
            path.len() <= 8192
                && route.starts_with("/v1/")
                && route.len() > 4
                && route
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
                && !route.split('/').any(|s| matches!(s, "." | ".."))
                && query
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_%=&.~-".contains(&b)),
            "INVALID_API_PATH",
        )?;
        let valid_header = |value: &str, min, max| {
            (min..=max).contains(&value.len())
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        };
        require(
            access_token.is_none_or(|t| valid_header(t, 32, 512)),
            "INVALID_ACCESS_TOKEN",
        )?;
        require(
            idempotency_key.is_none_or(|k| valid_header(k, 16, 128)),
            "INVALID_IDEMPOTENCY_KEY",
        )?;
        let url = self
            .origin
            .join(path)
            .map_err(|_| error("INVALID_API_PATH"))?;
        let mut request = if body.is_some() {
            self.http.post(url)
        } else {
            self.http.get(url)
        };
        if let Some(token) = access_token {
            request = request.bearer_auth(token);
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if let Some(value) = body {
            let bytes = serde_json::to_vec(value).map_err(|_| error("INVALID_REQUEST"))?;
            require(bytes.len() <= 16384, "REQUEST_TOO_LARGE")?;
            request = request
                .header("Content-Type", "application/json")
                .body(bytes);
        }
        let response = request.send().map_err(|_| error("NETWORK_FAILED"))?;
        if !response.status().is_success() {
            return Err(Error {
                code: "API_REQUEST_FAILED",
                status: Some(response.status().as_u16()),
            });
        }
        const MAX: u64 = 1048576;
        require(
            response.content_length().is_none_or(|length| length <= MAX),
            "RESPONSE_TOO_LARGE",
        )?;
        let mut bytes = Vec::new();
        response
            .take(MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| error("NETWORK_FAILED"))?;
        require(bytes.len() as u64 <= MAX, "RESPONSE_TOO_LARGE")?;
        parse_json(&bytes)
    }
}
pub fn fingerprint_from_smbios(raw: &[u8], product_id: &str, schema: &str) -> Result<Fingerprint> {
    let identifier = |s: &str| {
        !s.is_empty()
            && s.len() <= 80
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    require(
        identifier(product_id) && identifier(schema),
        "INVALID_IDENTIFIER",
    )?;
    require(
        (8..=1048576).contains(&raw.len())
            && u32::from_le_bytes(raw[4..8].try_into().map_err(|_| error("INVALID_SMBIOS"))?)
                as usize
                == raw.len() - 8,
        "INVALID_SMBIOS",
    )?;
    let mut uuid = None;
    let mut position = 8;
    while position < raw.len() {
        require(position + 4 <= raw.len(), "INVALID_SMBIOS")?;
        let kind = raw[position];
        let length = raw[position + 1] as usize;
        require(
            length >= 4 && position + length <= raw.len(),
            "INVALID_SMBIOS",
        )?;
        if kind == 1 && length >= 24 {
            let value = &raw[position + 8..position + 24];
            require(
                uuid.is_none() && value.iter().any(|b| *b != 0) && value.iter().any(|b| *b != 255),
                "HARDWARE_IDENTIFIER_UNAVAILABLE",
            )?;
            uuid = Some(value.iter().map(|b| format!("{b:02x}")).collect::<String>());
        }
        let mut end = position + length;
        while end + 1 < raw.len() && !(raw[end] == 0 && raw[end + 1] == 0) {
            end += 1;
        }
        require(end + 1 < raw.len(), "INVALID_SMBIOS")?;
        position = end + 2;
        if kind == 127 {
            break;
        }
    }
    let uuid = uuid.ok_or(error("HARDWARE_IDENTIFIER_UNAVAILABLE"))?;
    Ok(Fingerprint {
        schema: schema.into(),
        digest: sha256(
            format!("product-license-kit-hwid-v1\0{product_id}\0{schema}\0uuid:{uuid}").as_bytes(),
        ),
    })
}
