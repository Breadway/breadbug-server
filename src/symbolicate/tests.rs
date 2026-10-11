use super::*;

#[ctor::ctor]
fn enter_symbol_worker() {
    if crate::symbol_worker_entry() {
        std::process::exit(0);
    }
}
use object::{Object, ObjectSymbol};
use serde_json::json;
use std::process::Command;
use std::time::Instant;

/// Compile a tiny binary with debug info and a GNU build-id; return
/// (path, build_id, address of `target_fn`, source file name).
fn build_fixture(dir: &Path) -> (PathBuf, String, u64) {
    super::clear_worker_limits();
    if let Ok(worker) = std::env::current_exe() {
        std::env::set_var("BREADBUG_SYMBOL_WORKER_BIN", worker);
    }
    let src = dir.join("fixture.rs");
    std::fs::write(
        &src,
        r#"
#[no_mangle]
#[inline(never)]
pub extern "C" fn target_fn(x: u32) -> u32 {
    let y = x.wrapping_mul(31);
    std::hint::black_box(y) + 1
}
fn main() {
    std::process::exit(target_fn(std::env::args().count() as u32) as i32 & 0);
}
"#,
    )
    .unwrap();
    let bin = dir.join("fixture");
    super::clear_worker_limits();
    let mut command = Command::new("rustc");
    unsafe {
        use std::os::unix::process::CommandExt;
        command.pre_exec(|| {
            super::clear_worker_limits();
            Ok(())
        });
    }
    let status = command
        .args([
            "-g",
            "-C",
            "opt-level=0",
            "-C",
            "link-arg=-Wl,--build-id",
            "-o",
        ])
        .arg(&bin)
        .arg(&src)
        .status()
        .expect("rustc is available");
    assert!(status.success());
    let data = std::fs::read(&bin).unwrap();
    let file = object::File::parse(&*data).unwrap();
    let build_id = hex(file.build_id().unwrap().unwrap());
    let addr = file
        .symbols()
        .find(|s| s.name() == Ok("target_fn"))
        .expect("target_fn symbol")
        .address();
    (bin, build_id, addr)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn install(store: &Path, bin: &Path, build_id: &str) {
    let dest = store.join(&build_id[..2]);
    std::fs::create_dir_all(&dest).unwrap();
    std::fs::copy(bin, dest.join(format!("{build_id}.debug"))).unwrap();
}

fn report_with(frame: serde_json::Value) -> Report {
    serde_json::from_value(json!({
        "schema": 1, "report_type": "crash", "created_unix": 1,
        "app": {"id": "clip"},
        "markers": [{"t": 1, "kind": "panic", "frames": [frame]}]
    }))
    .unwrap()
}

#[test]
fn repeated_lookups_are_cached_and_corrupt_or_huge_files_stay_contained() {
    let work = tempfile::tempdir().unwrap();
    let (bin, id, addr) = build_fixture(work.path());
    let store_dir = tempfile::tempdir().unwrap();
    install(store_dir.path(), &bin, &id);
    let store = SymbolStore::new(store_dir.path());
    let first = Instant::now();
    let resolved = store.lookup(&id, addr + 4);
    let again = store.lookup(&id, addr + 4);
    assert_eq!(resolved, again);
    assert!(first.elapsed() < WORKER_TIMEOUT);

    let hostile = store_dir.path().join("00");
    std::fs::create_dir_all(&hostile).unwrap();
    let path = hostile.join("0011223344556677.debug");
    std::fs::write(&path, vec![0x7f, b'E', b'L', b'F']).unwrap();
    assert_eq!(
        store.lookup("0011223344556677", 1),
        Lookup::Unresolved,
        "a present but corrupt artifact is contained"
    );
    let absent = store_dir.path().join("00").join("00112233aaaaaaaa.debug");
    assert_eq!(store.lookup("00112233aaaaaaaa", 1), Lookup::MissingSymbols);
    let _ = absent;
    let huge = store_dir.path().join("88");
    std::fs::create_dir_all(&huge).unwrap();
    let huge_path = huge.join("8899aabbccddeeff.debug");
    let file = std::fs::File::create(&huge_path).unwrap();
    file.set_len(MAX_SYMBOL_FILE + 1).unwrap();
    assert_eq!(store.lookup("8899aabbccddeeff", 1), Lookup::Unresolved);
}

#[test]
fn resolves_function_file_and_line_from_a_real_binary() {
    let work = tempfile::tempdir().unwrap();
    let (bin, id, addr) = build_fixture(work.path());
    let store_dir = tempfile::tempdir().unwrap();
    install(store_dir.path(), &bin, &id);
    let store = SymbolStore::new(store_dir.path());

    // a few bytes into the function
    match store.lookup(&id, addr + 4) {
        Lookup::Resolved(r) => {
            assert!(
                r.function
                    .as_deref()
                    .is_some_and(|f| f.contains("target_fn")),
                "{r:?}"
            );
            assert!(
                r.file.as_deref().is_some_and(|f| f.ends_with("fixture.rs")),
                "{r:?}"
            );
            assert!(r.line.is_some());
        }
        other => panic!("expected a resolution, got {other:?}"),
    }
}

#[test]
fn symbolicate_fills_frames_and_strips_build_host_paths() {
    let work = tempfile::tempdir().unwrap();
    let (bin, id, addr) = build_fixture(work.path());
    let store_dir = tempfile::tempdir().unwrap();
    install(store_dir.path(), &bin, &id);
    let store = SymbolStore::new(store_dir.path());

    let mut r = report_with(json!({"module": "fixture", "offset": addr + 4, "build_id": id}));
    let stats = store.symbolicate(&mut r);
    assert_eq!(stats.resolved, 1);
    assert!(stats.missing_build_ids.is_empty());
    let f = &r.markers[0].frames[0];
    assert!(f.symbol.as_deref().unwrap().contains("target_fn"));
    let file = f.file.as_deref().unwrap();
    assert!(file.split('/').count() <= 3, "{file}");
    assert!(
        !file.contains(work.path().to_str().unwrap().trim_start_matches('/'))
            || file.split('/').count() <= 3
    );
}

#[test]
fn already_symbolised_frames_are_left_alone() {
    let store = SymbolStore::new("/nonexistent");
    let mut r =
        report_with(json!({"symbol": "clip::run", "build_id": "aabbccddeeff", "offset": 1}));
    let stats = store.symbolicate(&mut r);
    assert_eq!(stats, Stats::default());
    assert_eq!(r.markers[0].frames[0].symbol.as_deref(), Some("clip::run"));
}

#[test]
fn missing_symbols_are_reported_by_build_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = SymbolStore::new(dir.path());
    let mut r = report_with(json!({"offset": 5, "build_id": "aabbccddeeff0011"}));
    let stats = store.symbolicate(&mut r);
    assert_eq!(stats.resolved, 0);
    assert!(stats.missing_build_ids.contains("aabbccddeeff0011"));
    assert!(r.markers[0].frames[0].symbol.is_none());
}

#[test]
fn build_ids_are_validated_before_touching_the_filesystem() {
    let dir = tempfile::tempdir().unwrap();
    let store = SymbolStore::new(dir.path());
    for bad in [
        "../../etc/passwd",
        "AABBCCDD",
        "abc",
        "aa/bb/cc/dd",
        &"a".repeat(129),
        "zz112233",
    ] {
        assert!(!valid_build_id(bad), "{bad}");
        assert!(store.path_for(bad).is_none());
        assert_eq!(store.lookup(bad, 0), Lookup::Unresolved);
    }
    assert!(valid_build_id("3f2a9c1de4b5a6978081726354453423a1b2c3d4"));
}

#[test]
fn corrupt_symbol_files_do_not_panic_or_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let id = "deadbeefdeadbeef";
    std::fs::create_dir_all(dir.path().join("de")).unwrap();
    std::fs::write(
        dir.path().join("de").join(format!("{id}.debug")),
        b"\x7fELF garbage not a real elf",
    )
    .unwrap();
    let store = SymbolStore::new(dir.path());
    assert_eq!(store.lookup(id, 10), Lookup::Unresolved);
    // a directory where a file should be
    std::fs::create_dir_all(dir.path().join("ab").join("abababababababab.debug")).unwrap();
    assert_eq!(store.lookup("abababababababab", 1), Lookup::Unresolved);
}

#[test]
fn unmapped_addresses_are_unresolved_not_wrong() {
    let work = tempfile::tempdir().unwrap();
    let (bin, id, _) = build_fixture(work.path());
    let store_dir = tempfile::tempdir().unwrap();
    install(store_dir.path(), &bin, &id);
    let store = SymbolStore::new(store_dir.path());
    assert!(!matches!(
        store.lookup(&id, 0xffff_ffff_0000),
        Lookup::Resolved(Resolved {
            function: Some(_),
            ..
        })
    ));
}

#[test]
fn only_the_top_frames_are_symbolicated() {
    let dir = tempfile::tempdir().unwrap();
    let store = SymbolStore::new(dir.path());
    let frames: Vec<_> = (0..40)
        .map(|i| json!({"offset": i, "build_id": format!("{:016x}", 0xabcd0000u64 + i)}))
        .collect();
    let mut r: Report = serde_json::from_value(json!({
        "schema": 1, "report_type": "crash", "created_unix": 1, "app": {"id": "clip"},
        "markers": [{"t": 1, "kind": "panic", "frames": frames}]
    }))
    .unwrap();
    let stats = store.symbolicate(&mut r);
    assert_eq!(stats.missing_build_ids.len(), MAX_FRAMES_PER_STACK);
}
