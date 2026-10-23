use super::*;

#[test]
fn tokens_drop_numbers_markers_and_stopwords() {
    assert_eq!(
        tokens("The app froze after 30 seconds at <HOME>/x <IP:1> when pasting"),
        ["app", "froze", "seconds", "pasting"]
    );
    assert!(tokens("").is_empty());
}

#[test]
fn hash_embedding_is_unit_length_and_deterministic() {
    let e = HashEmbedder;
    let a = e
        .embed("clipboard hangs when pasting a large image")
        .unwrap();
    assert_eq!(a.len(), HASH_DIM);
    let norm: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    assert!((norm - 1.0).abs() < 1e-4);
    assert_eq!(
        a,
        e.embed("clipboard hangs when pasting a large image")
            .unwrap()
    );
    // empty text embeds to the zero vector, which matches nothing
    let z = e.embed("").unwrap();
    assert_eq!(cosine(&z, &a), 0.0);
}

#[test]
fn similar_text_scores_higher_than_unrelated_text() {
    let e = HashEmbedder;
    let a = e
        .embed("clipboard hangs when pasting a large image")
        .unwrap();
    let b = e
        .embed("pasting a large image makes the clipboard hang")
        .unwrap();
    let c = e
        .embed("bar shows the wrong battery percentage after suspend")
        .unwrap();
    assert!(cosine(&a, &b) > 0.6, "{}", cosine(&a, &b));
    assert!(cosine(&a, &c) < 0.3, "{}", cosine(&a, &c));
}

#[test]
fn centroid_and_byte_roundtrip() {
    let a = vec![1.0, 0.0];
    let b = vec![0.0, 1.0];
    let c = centroid(&[a.clone(), b]).unwrap();
    assert!((cosine(&c, &a) - std::f32::consts::FRAC_1_SQRT_2).abs() < 1e-4);
    assert_eq!(from_bytes(&to_bytes(&c)), c);
    assert!(centroid(&[]).is_none());
    assert_eq!(cosine(&[1.0], &[1.0, 2.0]), 0.0);
}

#[test]
fn http_embedder_only_talks_to_local_and_private_addresses() {
    for ok in [
        "http://127.0.0.1:8080/embed",
        "http://[::1]:8080/embed",
        "http://localhost:8080/embed",
        "http://192.168.1.5:80/e",
        "http://10.1.2.3:8080/embed",
        "http://172.17.0.2:80/embed",
        "http://[fd00::5]:8080/embed",
    ] {
        assert!(HttpEmbedder::new(ok, "m").is_ok(), "{ok}");
    }
    for bad in [
        "https://api.example.com/embed",
        "http://example.com/embed",
        "ftp://127.0.0.1/x",
        "http://8.8.8.8/embed",
        "http://1.1.1.1:80/embed",
        "http://169.254.1.1/embed",
        "http://[2001:db8::1]/embed",
        "http://[::ffff:192.168.1.5]/embed",
        "http://127.0.0.1@example.org/embed",
        "http://user@127.0.0.1/embed",
        "http://127.0.0.1/embed#frag",
    ] {
        assert!(HttpEmbedder::new(bad, "m").is_err(), "{bad}");
    }
}

fn serve_once(body: &'static str) -> String {
    use std::io::{BufRead, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/embed", l.local_addr().unwrap());
    std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut r = std::io::BufReader::new(s.try_clone().unwrap());
        let mut len = 0usize;
        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            let line = line.trim_end().to_ascii_lowercase();
            if line.is_empty() {
                break;
            }
            if let Some(v) = line.strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
        }
        let mut buf = vec![0u8; len];
        std::io::Read::read_exact(&mut r, &mut buf).unwrap();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut s = s;
        let _ = s.write_all(resp.as_bytes());
    });
    url
}

#[test]
fn http_embedder_parses_and_normalises_a_reply() {
    let e = HttpEmbedder::new(&serve_once("[[3.0, 4.0]]"), "tei").unwrap();
    let v = e.embed("hello").unwrap();
    assert!((v[0] - 0.6).abs() < 1e-5 && (v[1] - 0.8).abs() < 1e-5);
    assert_eq!(e.model(), "http:tei");
    let bad = HttpEmbedder::new(&serve_once("{\"nope\": 1}"), "tei").unwrap();
    assert!(bad.embed("x").is_err());
}

#[test]
fn titles_prefer_the_users_words() {
    let r: Report = serde_json::from_value(serde_json::json!({
        "schema": 1, "report_type": "behavior", "created_unix": 1, "app": {"id": "clip"},
        "notes": "pasting is slow\nsecond line"
    }))
    .unwrap();
    assert_eq!(title_for(&r), "pasting is slow");
    let r: Report = serde_json::from_value(serde_json::json!({
        "schema": 1, "report_type": "freeze", "created_unix": 1, "app": {"id": "pad"}
    }))
    .unwrap();
    assert_eq!(title_for(&r), "freeze report for pad");
}
