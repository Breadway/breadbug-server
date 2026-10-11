//! Server-side symbolication.
//!
//! Shipped binaries are stripped; the release pipeline publishes their debug
//! symbols to a store keyed by GNU build-id. A frame that carries a build-id
//! and a module-relative offset is resolved here to a function name, source
//! file and line.
//!
//! Symbol files come from our own CI, but they are still parsed defensively:
//! a hard size cap, build-ids validated as lowercase hex (they become path
//! components), only memory-safe Rust parsers (`object`, `gimli`,
//! `addr2line`), and any panic inside them is caught and treated as "could
//! not resolve" so a bad file cannot take the intake down.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::schema::{Frame, Report};

/// Largest symbol file the server will open. A 1 GiB artifact is far beyond
/// the container's safe working set, so the worker refuses it.
pub const MAX_SYMBOL_FILE: u64 = 32 * 1024 * 1024;

/// CPU and wall-clock ceiling for one isolated lookup worker.
pub const WORKER_TIMEOUT: Duration = Duration::from_secs(15);
const CACHE_LIMIT: usize = 4096;
/// Frames symbolicated per stack; the rest cannot affect the fingerprint.
pub const MAX_FRAMES_PER_STACK: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub function: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    Resolved(Resolved),
    /// No symbol file is published for this build-id.
    MissingSymbols,
    /// A file exists but nothing is known at that address (or it is unusable).
    Unresolved,
}

/// What symbolicating a report did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub resolved: usize,
    pub missing_build_ids: BTreeSet<String>,
}

pub struct SymbolStore {
    dir: PathBuf,
    cache: Mutex<HashMap<(String, u64), Lookup>>,
}

/// Lowercase hex, 8 to 128 chars.
pub fn valid_build_id(id: &str) -> bool {
    (8..=128).contains(&id.len()) && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Keep the last three path components so build-host directories (which can
/// contain usernames) never reach storage.
fn tidy_path(p: &str) -> String {
    let comps: Vec<&str> = p.split('/').filter(|c| !c.is_empty()).collect();
    comps[comps.len().saturating_sub(3)..].join("/")
}

impl SymbolStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Where the symbol file for `build_id` lives.
    pub fn path_for(&self, build_id: &str) -> Option<PathBuf> {
        valid_build_id(build_id).then(|| {
            self.dir
                .join(&build_id[..2])
                .join(format!("{build_id}.debug"))
        })
    }

    pub fn lookup(&self, build_id: &str, offset: u64) -> Lookup {
        let key = (build_id.to_string(), offset);
        if let Ok(cache) = self.cache.lock() {
            if let Some(hit) = cache.get(&key) {
                return hit.clone();
            }
        }
        let Some(path) = self.path_for(build_id) else {
            return Lookup::Unresolved;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            // The expected artifact is absent, so release tooling can be told
            // which build id to publish. Corrupt and oversized files below are
            // unresolved instead: the artifact exists but cannot be trusted.
            return Lookup::MissingSymbols;
        };
        if !meta.is_file() || meta.len() > MAX_SYMBOL_FILE {
            return Lookup::Unresolved;
        }
        let result = isolated_lookup(&path, offset);
        if matches!(result, Lookup::Resolved(_)) {
            if let Ok(mut cache) = self.cache.lock() {
                if cache.len() >= CACHE_LIMIT {
                    cache.clear();
                }
                cache.insert(key, result.clone());
            }
        }
        result
    }

    /// Fill in `symbol`, `file` and `line` on frames that have a build-id and
    /// offset but no symbol. Only the top frames of the stacks that matter.
    pub fn symbolicate(&self, report: &mut Report) -> Stats {
        let mut stats = Stats::default();
        let mut stacks: Vec<&mut Vec<Frame>> = Vec::new();
        for m in report.markers.iter_mut() {
            stacks.push(&mut m.frames);
        }
        stacks.push(&mut report.live_stack);
        for frames in stacks {
            for f in frames.iter_mut().take(MAX_FRAMES_PER_STACK) {
                if f.symbol.is_some() {
                    continue;
                }
                let (Some(id), Some(off)) = (f.build_id.as_deref(), f.offset) else {
                    continue;
                };
                match self.lookup(id, off) {
                    Lookup::Resolved(r) => {
                        if r.function.is_some() {
                            stats.resolved += 1;
                        }
                        f.symbol = r.function;
                        f.file = r.file.map(|p| tidy_path(&p));
                        f.line = r.line;
                    }
                    Lookup::MissingSymbols => {
                        stats.missing_build_ids.insert(id.to_string());
                    }
                    Lookup::Unresolved => {}
                }
            }
        }
        stats
    }
}

fn isolated_lookup(path: &Path, offset: u64) -> Lookup {
    if std::env::var_os("BREADBUG_SYMBOL_WORKER").is_some() {
        return std::panic::catch_unwind(|| resolve_in(path, offset))
            .ok()
            .flatten()
            .map_or(Lookup::Unresolved, Lookup::Resolved);
    }
    let me = match std::env::var_os("BREADBUG_SYMBOL_WORKER_BIN") {
        Some(path) => PathBuf::from(path),
        None => match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => return Lookup::Unresolved,
        },
    };
    let mut command = std::process::Command::new(me);
    command
        .env("BREADBUG_SYMBOL_WORKER", "1")
        .env("BREADBUG_SYMBOL_PATH", path)
        .env("BREADBUG_SYMBOL_OFFSET", offset.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(target_os = "linux")]
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            set_worker_limits()?;
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return Lookup::Unresolved,
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return Lookup::Unresolved,
            Ok(None) if started.elapsed() > WORKER_TIMEOUT => {
                let _ = child.kill();
                let _ = child.wait();
                return Lookup::Unresolved;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let mut output = String::new();
    if std::io::Read::read_to_string(&mut child.stdout.take().unwrap(), &mut output).is_err() {
        return Lookup::Unresolved;
    }
    let mut parts = output.trim().split('\t');
    match parts.next() {
        Some("resolved") => Lookup::Resolved(Resolved {
            function: nonempty(parts.next()),
            file: nonempty(parts.next()),
            line: parts.next().and_then(|v| v.parse().ok()),
        }),
        _ => Lookup::Unresolved,
    }
}

fn nonempty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_string)
}

#[cfg(target_os = "linux")]
fn set_worker_limits() -> std::io::Result<()> {
    #[repr(C)]
    struct Rlimit {
        current: u64,
        maximum: u64,
    }
    const RLIMIT_CPU: i32 = 0;
    unsafe extern "C" {
        fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
    }
    // Address space and process count are not reliable budgets here: valid
    // debug files need large mappings, and tests compile fixtures from this
    // process. CPU time plus the wall-clock watchdog contain runaway parsing.
    let cpu = Rlimit {
        current: 15,
        maximum: 15,
    };
    if unsafe { setrlimit(RLIMIT_CPU, &cpu) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Run one lookup and exit. The server binary doubles as its worker so the
/// parser does not need a separately deployed executable.
pub fn clear_worker_limits() {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct Rlimit {
            current: u64,
            maximum: u64,
        }
        unsafe extern "C" {
            fn setrlimit(resource: i32, limit: *const Rlimit) -> i32;
        }
        let unlimited = Rlimit {
            current: u64::MAX,
            maximum: u64::MAX,
        };
        unsafe {
            let _ = setrlimit(0, &unlimited);
        }
    }
}

pub fn worker_main() -> bool {
    if std::env::var_os("BREADBUG_SYMBOL_WORKER").is_none() {
        return false;
    }
    let (Some(path), Some(offset)) = (
        std::env::var_os("BREADBUG_SYMBOL_PATH"),
        std::env::var("BREADBUG_SYMBOL_OFFSET")
            .ok()
            .and_then(|v| v.parse().ok()),
    ) else {
        return true;
    };
    if let Lookup::Resolved(resolved) = isolated_lookup(Path::new(&path), offset) {
        println!(
            "resolved\t{}\t{}\t{}",
            resolved.function.unwrap_or_default(),
            resolved.file.unwrap_or_default(),
            resolved.line.map(|v| v.to_string()).unwrap_or_default()
        );
    }
    true
}

fn resolve_in(path: &Path, offset: u64) -> Option<Resolved> {
    let loader = addr2line::Loader::new(path).ok()?;
    if let Ok(mut frames) = loader.find_frames(offset) {
        // Innermost first. Prefer it: it names the function that actually ran.
        while let Ok(Some(frame)) = frames.next() {
            let function = frame
                .function
                .as_ref()
                .and_then(|f| f.demangle().ok())
                .map(|s| s.into_owned());
            if function.is_some() {
                return Some(Resolved {
                    function,
                    file: frame
                        .location
                        .as_ref()
                        .and_then(|l| l.file)
                        .map(String::from),
                    line: frame.location.as_ref().and_then(|l| l.line),
                });
            }
        }
    }
    // No DWARF: fall back to the symbol table, but only for an address that
    // really lies inside a sized function symbol. The nearest preceding
    // symbol would be a confident wrong answer.
    let data = std::fs::read(path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    use object::{Object, ObjectSymbol, SymbolKind};
    file.symbols()
        .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
        .find(|s| offset >= s.address() && offset < s.address() + s.size())
        .and_then(|s| s.name().ok().map(String::from))
        .map(|name| Resolved {
            function: Some(
                addr2line::demangle_auto(std::borrow::Cow::Borrowed(&name), None).into_owned(),
            ),
            file: None,
            line: None,
        })
}

#[cfg(test)]
mod tests;
