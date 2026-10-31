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
            || (name.ends_with(".o")
                && (name.starts_with("crt")
                    || name.starts_with("Scrt")
                    || name.starts_with("rcrt")
                    || name.starts_with("rsbegin")
                    || name.starts_with("rsend"))))
}

fn capture() -> Result<i32, Box<dyn std::error::Error>> {
    let target = env!("PSONOCI_SBOM_TARGET");
    let linker = env!("PSONOCI_SBOM_LINKER");
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
            let line = line
                .trim()
                .trim_start_matches("ld: ")
                .trim_start_matches("trace: ")
                .trim_start_matches("Searching ")
                .trim_end_matches(':');
            let candidate = line
                .split('(')
                .next()
                .unwrap_or(line)
                .trim()
                .trim_matches('"');
            let path = PathBuf::from(candidate);
            if library(&path) {
                paths.push(path);
            }
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
        entries.push(format!(
            "{{\"path\":{},\"copy\":{}}}",
            quote(&path.to_string_lossy()),
            quote(&name)
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
            "{{\"format\":1,\"target\":{},\"linker\":{},\"builderImage\":{},\"rustc\":{},\"arguments\":[{}],\"inputs\":[{}],\"compiler\":{}}}\n",
            quote(target),
            quote(linker),
            quote(option_env!("PSONOCI_SBOM_IMAGE").unwrap_or("native")),
            quote(&String::from_utf8_lossy(&version.stdout)),
            invocation,
            entries.join(","),
            compiler
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
