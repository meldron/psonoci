//! Capture the final executable's link inputs inside the actual build environment.
//! No crates or interpreter are needed, including in old Cross images.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn quote(value: &str) -> String {
    let mut result = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c < ' ' => result.push_str(&format!("\\u{:04x}", c as u32)),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

fn response_args(args: &[String]) -> io::Result<Vec<String>> {
    let mut expanded = Vec::new();
    for arg in args {
        if let Some(path) = arg.strip_prefix('@') {
            let bytes = fs::read(path)?;
            let text = if bytes.starts_with(&[0xff, 0xfe]) {
                String::from_utf16_lossy(
                    &bytes[2..]
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>(),
                )
            } else {
                String::from_utf8_lossy(&bytes).into_owned()
            };
            let mut token = String::new();
            let mut quoted = false;
            for c in text.chars() {
                if c == '"' {
                    quoted = !quoted;
                } else if c.is_whitespace() && !quoted {
                    if !token.is_empty() {
                        expanded.push(std::mem::take(&mut token));
                    }
                } else {
                    token.push(c);
                }
            }
            if !token.is_empty() {
                expanded.push(token);
            }
        } else {
            expanded.push(arg.clone());
        }
    }
    Ok(expanded)
}

fn library(path: &Path) -> bool {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    path.is_file()
        && (name.ends_with(".a")
            || name.ends_with(".rlib")
            || name.ends_with(".lib")
            || name.ends_with(".dylib")
            || name.ends_with(".tbd")
            || name.contains(".so")
            || name.ends_with(".o")
            || name.ends_with(".obj"))
}

fn object_role(path: &Path, output: &Path, explicit: bool) -> &'static str {
    if !explicit {
        return "provider";
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let stem = output.file_stem().unwrap_or_default().to_string_lossy();
    let directory = output.parent();
    if path.parent() == directory
        && name.starts_with(&format!("{stem}."))
        && (name.ends_with(".rcgu.o") || name.ends_with(".rcgu.obj"))
    {
        return "root-rust-object";
    }
    if path.parent() == directory && name == "psonoci_audit_data.o" {
        return "auditable-metadata-object";
    }
    if name == "symbols.o"
        && path.parent().and_then(Path::parent) == directory
        && path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|n| n.to_string_lossy().starts_with("rustc"))
    {
        return "rustc-symbol-object";
    }
    "provider"
}

fn traced_paths(line: &str) -> Vec<PathBuf> {
    let line = line
        .trim()
        .trim_start_matches("ld: ")
        .trim_start_matches("trace: ")
        .trim_start_matches("Searching ")
        .trim_end_matches(':');
    // Try the whole path first: Windows paths can contain parentheses.
    let whole = PathBuf::from(line.trim_matches('"'));
    if library(&whole) {
        return vec![whole];
    }
    let mut paths = Vec::new();
    for (index, _) in line.match_indices('(') {
        let (before, rest) = (&line[..index], &line[index + 1..]);
        for candidate in [before, rest.rsplit_once(')').map(|p| p.0).unwrap_or(rest)] {
            let path = PathBuf::from(candidate.trim().trim_matches('"'));
            if library(&path) {
                paths.push(path);
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn capture() -> Result<i32, Box<dyn std::error::Error>> {
    let target = env!("PSONOCI_SBOM_TARGET");
    let linker = env!("PSONOCI_SBOM_LINKER");
    let prefix = target.replace('-', "_").to_uppercase();
    for key in [
        String::from("OPENSSL_NO_VENDOR"),
        format!("{prefix}_OPENSSL_NO_VENDOR"),
    ] {
        if env::var_os(&key).is_some_and(|value| value != "0") {
            return Err(format!("{key} disables the required vendored OpenSSL build").into());
        }
    }
    for key in [
        String::from("OPENSSL_STATIC"),
        format!("{prefix}_OPENSSL_STATIC"),
    ] {
        if env::var_os(&key).is_some_and(|value| value == "0") {
            return Err(format!("{key} disables the required static OpenSSL build").into());
        }
    }
    let args: Vec<String> = env::args().skip(1).collect();
    let expanded = response_args(&args)?;
    let output = expanded
        .windows(2)
        .find(|a| a[0] == "-o")
        .map(|a| a[1].clone())
        .or_else(|| {
            expanded
                .iter()
                .find_map(|a| a.strip_prefix("/OUT:").map(String::from))
        })
        .ok_or("link command has no output file")?;
    let output = PathBuf::from(output);
    let release = output.parent().ok_or("output has no directory")?;
    let release = if release.file_name().is_some_and(|n| n == "deps") {
        release.parent().unwrap()
    } else {
        release
    };
    let directory = release.join("runtime-capture");
    // A failed or cached build must never reuse evidence from a previous link.
    if directory.exists() {
        fs::remove_dir_all(&directory)?;
    }
    fs::create_dir_all(directory.join("inputs"))?;
    let mut command = Command::new(linker);
    command.args(&args);
    if target.contains("msvc") {
        command.arg("/VERBOSE:LIB");
    } else if target.contains("apple") {
        command.arg("-Wl,-t");
    } else {
        command.arg("-Wl,--trace");
    }
    let result = command.stdin(Stdio::inherit()).output()?;
    // Keep diagnostics visible to Cargo as well as retaining the trace.
    use std::io::Write;
    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;
    fs::write(directory.join("link.stdout"), &result.stdout)?;
    fs::write(directory.join("link.stderr"), &result.stderr)?;
    if !result.status.success() {
        return Ok(result.status.code().unwrap_or(1));
    }
    let mut paths = Vec::<PathBuf>::new();
    let mut search: Vec<PathBuf> = env::var_os("LIB")
        .map(|s| env::split_paths(&s).collect())
        .unwrap_or_default();
    for arg in &expanded {
        if let Some(path) = arg.strip_prefix("/LIBPATH:") {
            search.push(PathBuf::from(path));
        }
    }
    for arg in &expanded {
        let path = PathBuf::from(arg);
        if library(&path) {
            paths.push(path);
        } else if arg.ends_with(".lib") {
            if let Some(path) = search.iter().map(|p| p.join(arg)).find(|p| p.is_file()) {
                paths.push(path);
            }
        }
    }
    for bytes in [&result.stdout, &result.stderr] {
        for line in String::from_utf8_lossy(bytes).lines() {
            paths.extend(traced_paths(line));
        }
    }
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err("link trace contains no resolved libraries".into());
    }
    let mut entries = Vec::new();
    for (index, path) in paths.iter().enumerate() {
        let name = format!(
            "inputs/{index:04}-{}",
            path.file_name()
                .ok_or("input has no name")?
                .to_string_lossy()
        );
        fs::copy(path, directory.join(&name))?;
        let role = object_role(
            path,
            &output,
            expanded.iter().any(|arg| Path::new(arg) == path),
        );
        entries.push(format!(
            "{{\"path\":{},\"copy\":{},\"role\":{}}}",
            quote(&path.to_string_lossy()),
            quote(&name),
            quote(role)
        ));
    }
    fs::copy(&output, directory.join("binary"))?;
    let rustc = env::var("RUSTC").unwrap_or_else(|_| String::from("rustc"));
    let version = Command::new(rustc).arg("-vV").output()?;
    if !version.status.success() {
        return Err("cannot identify the build Rust toolchain".into());
    }
    let mut compiler = String::from("null");
    if !target.contains("msvc") && !target.contains("apple") {
        let banner = Command::new(linker).arg("--version").output()?;
        let banner = String::from_utf8_lossy(&banner.stdout);
        if !banner.to_lowercase().contains("clang") {
            let version = Command::new(linker).arg("-dumpfullversion").output()?;
            let mut version = String::from_utf8_lossy(&version.stdout).trim().to_owned();
            if version.is_empty() {
                version = String::from_utf8_lossy(
                    &Command::new(linker).arg("-dumpversion").output()?.stdout,
                )
                .trim()
                .to_owned();
            }
            let mut runtimes = Vec::new();
            for name in [
                "libgcc_s.so.1",
                "libgcc_s.so",
                "libgcc.a",
                "libgcc_eh.a",
                "libatomic.a",
                "libatomic.so",
                "libatomic.so.1",
                "crtbegin.o",
                "crtend.o",
                "crtbeginS.o",
                "crtendS.o",
                "crtbeginT.o",
            ] {
                let found = Command::new(linker)
                    .arg(format!("-print-file-name={name}"))
                    .output()?;
                let path = PathBuf::from(String::from_utf8_lossy(&found.stdout).trim());
                if path.is_file() {
                    let copy = format!("compiler-{name}");
                    fs::copy(&path, directory.join(&copy))?;
                    runtimes.push(quote(&copy));
                }
            }
            compiler = format!(
                "{{\"version\":{},\"files\":[{}]}}",
                quote(&version),
                runtimes.join(",")
            );
        }
    }
    let invocation = expanded
        .iter()
        .map(|s| quote(s))
        .collect::<Vec<_>>()
        .join(",");
    fs::write(
        directory.join("capture.json"),
        format!(
            "{{\"format\":1,\"target\":{},\"linker\":{},\"builderImage\":{},\"rustc\":{},\"arguments\":[{}],\"inputs\":[{}],\"compiler\":{},\"output\":{},\"buildPolicy\":{{\"opensslVendoredEnvironmentAllowed\":true}},\"cargoAuditableVersion\":{},\"opensslSource\":{}}}\n",
            quote(target),
            quote(linker),
            quote(option_env!("PSONOCI_SBOM_IMAGE").unwrap_or("native")),
            quote(&String::from_utf8_lossy(&version.stdout)),
            invocation,
            entries.join(","),
            compiler,
            quote(&output.to_string_lossy()),
            quote(option_env!("PSONOCI_CARGO_AUDITABLE_VERSION").unwrap_or("unverified")),
            option_env!("PSONOCI_OPENSSL_SOURCE").unwrap_or("null")
        ),
    )?;
    Ok(0)
}

fn main() {
    match capture() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("runtime link evidence: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_objects_are_captured_and_only_explicit_compiler_outputs_are_classified() {
        let root = env::temp_dir().join(format!("sbom-object-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let output = root.join("psonoci-abcdef");
        for name in ["codec.o", "assembly.obj", "psonoci-abcdef.unit.rcgu.o"] {
            let object = root.join(name);
            fs::write(&object, b"object").unwrap();
            assert!(library(&object));
            assert_eq!(
                traced_paths(&object.display().to_string()),
                vec![object.clone()]
            );
            assert_eq!(object_role(&object, &output, false), "provider");
            assert_eq!(
                object_role(&object, &output, true),
                if name.ends_with(".rcgu.o") {
                    "root-rust-object"
                } else {
                    "provider"
                }
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recognizes_gnu_trace_variants_and_parentheses_in_paths() {
        let root = env::temp_dir().join(format!("sbom-trace-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        for name in ["libm.so", "libexample.a", "Program Files (x86).lib"] {
            let path = root.join(name);
            fs::write(&path, b"resolved input").unwrap();
            for line in [
                path.display().to_string(),
                format!("-lm ({})", path.display()),
                format!("{}(member.o)", path.display()),
            ] {
                assert_eq!(traced_paths(&line), vec![path.clone()]);
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}
