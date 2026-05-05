// Build script for `headlines-proto`.
//
// Responsibilities:
//   1. Discover every `.proto` file under `<workspace>/proto/headlines/` and
//      compile them with `tonic-build`. Files under `<workspace>/proto/google/`
//      are vendored googleapis (e.g. `google/api/annotations.proto`,
//      `google/api/http.proto`) used as imports — they're on the include path
//      but are NOT compiled into Rust types here (prost compiles its own
//      `google.protobuf.*` types internally; the googleapis ones travel only
//      as descriptor metadata for the build script's authorization extraction).
//   2. Persist the FileDescriptorSet to `$OUT_DIR/descriptor.bin`.
//   3. Walk the descriptor set's raw wire bytes — `prost-types` drops unknown
//      extensions on decode, so we hand-walk to find every method's
//      `auth_requirement` (field 50001 inside `MethodOptions`) — and emit
//      `$OUT_DIR/auth_table.rs` with a `phf::Map` keyed by full RPC method
//      name. Build FAILS if any RPC on a `headlines.*` service is missing an
//      annotation. Single source of truth, per
//      `docs/design/architecture.md`.
//   4. Emit `cargo:rerun-if-changed` for every `.proto` so edits trigger a
//      rebuild.

use std::io::Write;
use std::path::{Path, PathBuf};

/// Field number of `headlines.v1.auth_requirement` in `MethodOptions`. Pinned
/// in `proto/headlines/v1/options.proto`.
const AUTH_REQUIREMENT_FIELD: u32 = 50001;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = PathBuf::from(env_var("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("manifest_dir has no grandparent")?
        .to_path_buf();
    let proto_root = workspace_root.join("proto");

    println!("cargo:rerun-if-changed={}", proto_root.display());

    let all_protos = discover_proto_files(&proto_root)?;
    for proto in &all_protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    if all_protos.is_empty() {
        return Err(format!("no .proto files found under {}", proto_root.display()).into());
    }

    let headlines_root = proto_root.join("headlines");
    let compile_targets: Vec<PathBuf> = all_protos
        .iter()
        .filter(|p| p.starts_with(&headlines_root))
        .cloned()
        .collect();

    let out_dir = PathBuf::from(env_var("OUT_DIR"));
    let descriptor_path = out_dir.join("descriptor.bin");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .disable_comments(".")
        .file_descriptor_set_path(&descriptor_path)
        .compile_protos(
            &compile_targets
                .iter()
                .map(|p| p.as_path())
                .collect::<Vec<_>>(),
            &[proto_root.as_path()],
        )?;

    let descriptor_bytes = std::fs::read(&descriptor_path)
        .map_err(|e| format!("failed to read {}: {e}", descriptor_path.display()))?;

    let entries = scan_descriptor_set(&descriptor_bytes)?;
    write_auth_table(&out_dir.join("auth_table.rs"), &entries)?;

    Ok(())
}

fn env_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|e| panic!("{key} not set in build env: {e}"))
}

/// One projected `(method_path, AuthSpec)` row.
struct AuthEntry {
    full_method: String,
    allowed: Vec<String>,
    scopes: Vec<String>,
}

/// Walk the raw wire bytes of `FileDescriptorSet`. Tag layout per
/// `descriptor.proto`:
///
///   FileDescriptorSet.file       = 1 (length-delimited FileDescriptorProto)
///   FileDescriptorProto.name     = 1 (string)
///   FileDescriptorProto.package  = 2 (string)
///   FileDescriptorProto.service  = 6 (length-delimited ServiceDescriptorProto)
///   ServiceDescriptorProto.name  = 1 (string)
///   ServiceDescriptorProto.method = 2 (length-delimited MethodDescriptorProto)
///   MethodDescriptorProto.name   = 1 (string)
///   MethodDescriptorProto.options = 4 (length-delimited MethodOptions; raw)
fn scan_descriptor_set(bytes: &[u8]) -> Result<Vec<AuthEntry>, Box<dyn std::error::Error>> {
    let mut entries = Vec::new();
    for (field_no, _wire, body) in WireScanner::new(bytes) {
        if field_no == 1 {
            scan_file(body?, &mut entries)?;
        }
    }
    Ok(entries)
}

fn scan_file(bytes: &[u8], entries: &mut Vec<AuthEntry>) -> Result<(), Box<dyn std::error::Error>> {
    let mut package = String::new();
    let mut services: Vec<&[u8]> = Vec::new();
    for (field_no, _wire, body) in WireScanner::new(bytes) {
        let body = body?;
        match field_no {
            2 => package = std::str::from_utf8(body)?.to_owned(),
            6 => services.push(body),
            _ => {}
        }
    }
    if !package.starts_with("headlines.") {
        // Vendored googleapis travel with the descriptor; we don't enforce
        // their methods (none in v1) and we definitely don't emit them.
        return Ok(());
    }
    for svc_bytes in services {
        scan_service(svc_bytes, &package, entries)?;
    }
    Ok(())
}

fn scan_service(
    bytes: &[u8],
    package: &str,
    entries: &mut Vec<AuthEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut svc_name = String::new();
    let mut methods: Vec<&[u8]> = Vec::new();
    for (field_no, _wire, body) in WireScanner::new(bytes) {
        let body = body?;
        match field_no {
            1 => svc_name = std::str::from_utf8(body)?.to_owned(),
            2 => methods.push(body),
            _ => {}
        }
    }
    for m_bytes in methods {
        scan_method(m_bytes, package, &svc_name, entries)?;
    }
    Ok(())
}

fn scan_method(
    bytes: &[u8],
    package: &str,
    svc: &str,
    entries: &mut Vec<AuthEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut name = String::new();
    let mut options_bytes: Option<&[u8]> = None;
    for (field_no, _wire, body) in WireScanner::new(bytes) {
        let body = body?;
        match field_no {
            1 => name = std::str::from_utf8(body)?.to_owned(),
            // MethodDescriptorProto.options is field 4.
            4 => options_bytes = Some(body),
            _ => {}
        }
    }
    let full = format!("/{package}.{svc}/{name}");
    let req = options_bytes
        .map(scan_method_options_for_auth)
        .transpose()?
        .flatten();
    let Some(req) = req else {
        return Err(format!(
            "method {full} is missing the headlines.v1.auth_requirement \
             MethodOption — every RPC must declare its authorization policy at \
             the proto level (see docs/design/architecture.md)"
        )
        .into());
    };
    entries.push(AuthEntry {
        full_method: full,
        allowed: req.allowed,
        scopes: req.scopes,
    });
    Ok(())
}

#[derive(Debug, Default)]
struct AuthRequirementBytes {
    allowed: Vec<String>,
    scopes: Vec<String>,
}

fn scan_method_options_for_auth(
    bytes: &[u8],
) -> Result<Option<AuthRequirementBytes>, Box<dyn std::error::Error>> {
    let mut found: Option<&[u8]> = None;
    for (field_no, _wire, body) in WireScanner::new(bytes) {
        let body = body?;
        if field_no == AUTH_REQUIREMENT_FIELD {
            // Last instance wins (proto3 semantics for repeated singular extensions).
            found = Some(body);
        }
    }
    let Some(body) = found else {
        return Ok(None);
    };
    decode_auth_requirement_message(body).map(Some)
}

fn decode_auth_requirement_message(
    bytes: &[u8],
) -> Result<AuthRequirementBytes, Box<dyn std::error::Error>> {
    let mut out = AuthRequirementBytes::default();
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let (tag, n) = decode_varint(&bytes[cursor..])?;
        cursor += n;
        let field_no = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match (field_no, wire) {
            // allowed_subjects: enum (varint) or packed (length-delimited).
            (1, 0) => {
                let (val, n) = decode_varint(&bytes[cursor..])?;
                cursor += n;
                out.allowed.push(subject_class_name(val as i32)?);
            }
            (1, 2) => {
                let (len, n) = decode_varint(&bytes[cursor..])?;
                cursor += n;
                let end = cursor + len as usize;
                if end > bytes.len() {
                    return Err("truncated packed enum".into());
                }
                let mut inner = cursor;
                while inner < end {
                    let (val, n) = decode_varint(&bytes[inner..])?;
                    inner += n;
                    out.allowed.push(subject_class_name(val as i32)?);
                }
                cursor = end;
            }
            // required_scopes: string
            (2, 2) => {
                let (len, n) = decode_varint(&bytes[cursor..])?;
                cursor += n;
                let end = cursor + len as usize;
                if end > bytes.len() {
                    return Err("truncated string field".into());
                }
                let s = std::str::from_utf8(&bytes[cursor..end])?;
                out.scopes.push(s.to_owned());
                cursor = end;
            }
            (_, w) => {
                cursor = skip_wire_value(bytes, cursor, w)?;
            }
        }
    }
    Ok(out)
}

/// Iterator over wire-format key + body slices in a length-delimited message.
struct WireScanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WireScanner<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
}

impl<'a> Iterator for WireScanner<'a> {
    /// `(field_number, wire_type, body)` — `body` is `Err` on a malformed
    /// frame. Non-length-delimited fields produce a body slice that is the
    /// raw bytes of the value (varint or fixed slot); callers usually ignore
    /// those.
    type Item = (u32, u8, Result<&'a [u8], Box<dyn std::error::Error>>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        let (tag, n) = match decode_varint(&self.bytes[self.pos..]) {
            Ok(v) => v,
            Err(e) => return Some((0, 0, Err(e))),
        };
        self.pos += n;
        let field_no = (tag >> 3) as u32;
        let wire = (tag & 0x7) as u8;
        match wire {
            0 => {
                let start = self.pos;
                let (_, n) = match decode_varint(&self.bytes[self.pos..]) {
                    Ok(v) => v,
                    Err(e) => return Some((field_no, wire, Err(e))),
                };
                self.pos += n;
                Some((field_no, wire, Ok(&self.bytes[start..self.pos])))
            }
            1 => {
                let start = self.pos;
                self.pos += 8;
                Some((field_no, wire, Ok(&self.bytes[start..self.pos])))
            }
            2 => {
                let (len, n) = match decode_varint(&self.bytes[self.pos..]) {
                    Ok(v) => v,
                    Err(e) => return Some((field_no, wire, Err(e))),
                };
                self.pos += n;
                let end = self.pos + len as usize;
                if end > self.bytes.len() {
                    return Some((
                        field_no,
                        wire,
                        Err("truncated length-delimited field".into()),
                    ));
                }
                let body = &self.bytes[self.pos..end];
                self.pos = end;
                Some((field_no, wire, Ok(body)))
            }
            5 => {
                let start = self.pos;
                self.pos += 4;
                Some((field_no, wire, Ok(&self.bytes[start..self.pos])))
            }
            other => Some((
                field_no,
                wire,
                Err(format!("unexpected wire type {other}").into()),
            )),
        }
    }
}

fn skip_wire_value(
    bytes: &[u8],
    cursor: usize,
    wire: u8,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut cursor = cursor;
    match wire {
        0 => {
            let (_, n) = decode_varint(&bytes[cursor..])?;
            cursor += n;
        }
        1 => cursor += 8,
        2 => {
            let (len, n) = decode_varint(&bytes[cursor..])?;
            cursor += n + len as usize;
        }
        5 => cursor += 4,
        other => return Err(format!("unexpected wire type {other}").into()),
    }
    Ok(cursor)
}

fn decode_varint(bytes: &[u8]) -> Result<(u64, usize), Box<dyn std::error::Error>> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, byte) in bytes.iter().enumerate().take(10) {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
    }
    Err("varint too long".into())
}

fn subject_class_name(value: i32) -> Result<String, Box<dyn std::error::Error>> {
    Ok(match value {
        1 => "Anonymous".to_owned(),
        2 => "UserSelf".to_owned(),
        3 => "AccountSelf".to_owned(),
        4 => "AccountOwnsResource".to_owned(),
        5 => "System".to_owned(),
        other => return Err(format!("unknown SubjectClass value: {other}").into()),
    })
}

fn write_auth_table(path: &Path, entries: &[AuthEntry]) -> std::io::Result<()> {
    let mut out = std::fs::File::create(path)?;
    writeln!(out, "// @generated by build.rs - do not hand-edit.")?;
    // The file is `include!`d into `src/lib.rs`, so we reference the in-scope
    // names — no additional imports here.
    writeln!(out)?;

    let mut builder = phf_codegen::Map::<&'static str>::new();

    let key_strings: Vec<String> = entries.iter().map(|e| e.full_method.clone()).collect();
    let value_literals: Vec<String> = entries
        .iter()
        .map(|e| {
            let allowed_lit = if e.allowed.is_empty() {
                "&[]".to_owned()
            } else {
                let inner = e
                    .allowed
                    .iter()
                    .map(|n| format!("SubjectClass::{n}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("&[{inner}]")
            };
            let scopes_lit = if e.scopes.is_empty() {
                "&[]".to_owned()
            } else {
                let inner = e
                    .scopes
                    .iter()
                    .map(|s| format!("{:?}", s))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("&[{inner}]")
            };
            format!("AuthSpec {{ allowed: {allowed_lit}, scopes: {scopes_lit} }}")
        })
        .collect();

    for (k, v) in key_strings.iter().zip(value_literals.iter()) {
        builder.entry(k.as_str(), v.as_str());
    }

    writeln!(
        out,
        "pub static AUTH_TABLE: ::phf::Map<&'static str, AuthSpec> = {};",
        builder.build()
    )?;

    Ok(())
}

fn discover_proto_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    walk(root, &mut out)?;
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk(&path, out)?;
        } else if file_type.is_file() && path.extension().and_then(|s| s.to_str()) == Some("proto")
        {
            out.push(path);
        }
    }
    Ok(())
}
