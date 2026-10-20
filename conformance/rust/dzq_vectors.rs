//! dzq/1.0 conformance: runs the test vectors of https://github.com/WheelReinvent/dzq
//! through the DzenQ core (keri_wrapper).
//!
//! Install: copy this file to `rustLib/tests/dzq_vectors.rs`.
//! Vectors: `DZQ_VECTORS=/path/to/dzq/vectors`, or a `dzq` checkout next to
//! the DzenQ repo (`../../dzq/vectors` from rustLib/). Without either the
//! test is skipped, unless `DZQ_REQUIRED=1` (CI) makes that a failure.
//!
//! Every verifier reports a machine code for a failure (dzq/1.0 §6.4). The
//! core reports free text, so `code_of` maps its messages to those codes.

use keri_wrapper::challenge::Challenge;
use keri_wrapper::crypto::{calculate_merkle_root, verify_merkle_proof, MerkleProof};
use keri_wrapper::sdk::KeriSdk;
use keri_wrapper::verify::PeriodSeal;
use keri_wrapper::{acdc, CesrResult, DzenqManager};
use serde_json::Value;
use std::path::PathBuf;

fn vectors_dir() -> Option<PathBuf> {
    let dir = std::env::var("DZQ_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dzq/vectors"));
    if dir.join("manifest.json").exists() {
        Some(dir)
    } else if std::env::var("DZQ_REQUIRED").is_ok() {
        panic!("dzq vectors not found at {}", dir.display());
    } else {
        eprintln!("dzq vectors not found at {}; skipping", dir.display());
        None
    }
}

fn read(dir: &PathBuf, rel: &str) -> String {
    std::fs::read_to_string(dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn json(dir: &PathBuf, rel: &str) -> Value {
    serde_json::from_str(&read(dir, rel)).unwrap()
}

/// Core message → dzq/1.0 failure code.
fn code_of(reason: &str) -> &'static str {
    let r = reason;
    if r.contains("canonical") {
        "canonical"
    } else if r.contains("invalid ACDC JSON") || r.contains("no ACDC JSON") || r.contains("bad signature group") {
        "format"
    } else if r.contains("not a gratitude ACDC") || r.contains("unknown schema") || r.contains("names its recipient")
        || r.contains("has a.dq and no a.i")
        || r.contains("a.req")
    {
        "schema"
    } else if r.contains("SAID does not match") || r.contains("version string size") {
        "said"
    } else if r.contains("issuer KEL") || r.contains("bad issuer AID") {
        "kel"
    } else if r.contains("carries no signature") {
        "no-signature"
    } else if r.contains("not sealed, and not signed") {
        "not-current"
    } else if r.contains("signature does not match") || r.contains("no issuer keys") {
        "signature"
    } else if r.contains("period") || r.contains("seal") {
        "seal"
    } else if r.contains("nonce mismatch") {
        "nonce"
    } else if r.contains("holder signature") {
        "signature"
    } else if r.contains("holder KEL") {
        "kel"
    } else if r.contains("a credential is invalid") {
        "credential"
    } else if r.contains("presentation") {
        "format"
    } else {
        "unknown"
    }
}

#[test]
fn dzq_credentials() {
    let Some(dir) = vectors_dir() else { return };
    let manifest = json(&dir, "manifest.json");
    let mut failures = Vec::new();
    for v in manifest["credentials"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let sdk = KeriSdk::new(tmp.path().to_str().unwrap().to_string()).unwrap();
        if let Some(kel) = v["kel"].as_str() {
            let _ = sdk.process_cesr(&read(&dir, kel));
        }
        let seal: Option<PeriodSeal> = v["seal"].as_str().map(|s| serde_json::from_str(&read(&dir, s)).unwrap());
        let bundle = read(&dir, v["bundle"].as_str().unwrap());
        let r = sdk.check_credential_sealed(&bundle, seal.as_ref());
        let e = &v["expect"];
        let mut bad = Vec::new();
        if r.valid != e["valid"].as_bool().unwrap() {
            bad.push(format!("valid={} ({:?})", r.valid, r.reason));
        }
        if let Some(code) = e["code"].as_str() {
            let got = r.reason.as_deref().map(code_of).unwrap_or("none");
            if got != code {
                bad.push(format!("code {got} != {code} ({:?})", r.reason));
            }
        }
        if let Some(s) = e["sealed"].as_bool() {
            if r.valid && r.sealed != s {
                bad.push(format!("sealed={}", r.sealed));
            }
        }
        for (key, got) in [("anchored_at_sn", r.anchored_at_sn), ("redeemed_at_sn", r.redeemed_at_sn)] {
            if let Some(want) = e[key].as_u64() {
                if got != Some(want) {
                    bad.push(format!("{key}={got:?}"));
                }
            }
        }
        for (key, got) in [("said", &r.said), ("issuer", &r.issuer), ("recipient", &r.recipient)] {
            if let Some(want) = e[key].as_str() {
                if got.as_deref() != Some(want) {
                    bad.push(format!("{key}={got:?}"));
                }
            }
        }
        if !bad.is_empty() {
            failures.push(format!("{name}: {}", bad.join("; ")));
        }
    }
    assert!(failures.is_empty(), "credential vectors:\n  {}", failures.join("\n  "));
}

#[test]
fn dzq_archives() {
    let Some(dir) = vectors_dir() else { return };
    let manifest = json(&dir, "manifest.json");
    let mut failures = Vec::new();
    for v in manifest["archives"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let core = DzenqManager::new(tmp.path().to_str().unwrap().to_string()).unwrap();
        let bytes = std::fs::read(dir.join(v["file"].as_str().unwrap())).unwrap();
        let e = &v["expect"];
        let (valid, code) = match core.unpack_gratitude_detailed(bytes) {
            Err(_) => (false, "archive".to_string()),
            // Valid but not for a local identity: PROCESSED.
            Ok(o) if matches!(o.result, CesrResult::Processed | CesrResult::GratitudeSavedForUs) => (true, String::new()),
            Ok(o) => (false, o.reason.as_deref().map(code_of).unwrap_or("none").to_string()),
        };
        if valid != e["valid"].as_bool().unwrap() || e["code"].as_str().is_some_and(|c| c != code) {
            failures.push(format!("{name}: valid={valid} code={code}"));
        }
    }
    assert!(failures.is_empty(), "archive vectors:\n  {}", failures.join("\n  "));
}

#[test]
fn dzq_presentations() {
    let Some(dir) = vectors_dir() else { return };
    let manifest = json(&dir, "manifest.json");
    let mut failures = Vec::new();
    for v in manifest["presentations"].as_array().unwrap() {
        let name = v["name"].as_str().unwrap();
        if v.get("extensions").is_some() && std::env::var("DZQ_EXTENSIONS").is_err() {
            continue; // optional extensions (promises): set DZQ_EXTENSIONS=1 to run them
        }
        let tmp = tempfile::tempdir().unwrap();
        let core = DzenqManager::new(tmp.path().to_str().unwrap().to_string()).unwrap();
        let vp = read(&dir, v["file"].as_str().unwrap());
        let r = core.verify_presentation(vp, v["nonce"].as_str().unwrap().to_string()).unwrap();
        let e = &v["expect"];
        let mut bad = Vec::new();
        if r.valid != e["valid"].as_bool().unwrap() {
            bad.push(format!("valid={} ({:?})", r.valid, r.reason));
        }
        if let Some(code) = e["code"].as_str() {
            let got = r.reason.as_deref().map(code_of).unwrap_or("none");
            if got != code {
                bad.push(format!("code {got} != {code} ({:?})", r.reason));
            }
        }
        if let Some(h) = e["holder"].as_str() {
            if r.holder_aid.as_deref() != Some(h) {
                bad.push(format!("holder={:?}", r.holder_aid));
            }
        }
        if !bad.is_empty() {
            failures.push(format!("{name}: {}", bad.join("; ")));
        }
    }
    assert!(failures.is_empty(), "presentation vectors:\n  {}", failures.join("\n  "));
}

#[test]
fn dzq_conditions() {
    let Some(dir) = vectors_dir() else { return };
    for c in json(&dir, "conditions.json")["conditions"].as_array().unwrap() {
        // dzq/1.3 §4: one URL-style condition; DzenQ needs a parser for it.
        let text = c["condition"].as_str().unwrap();
        let parsed = Condition::parse(text);
        assert_eq!(parsed.is_some(), c["parses"].as_bool().unwrap(), "{text}");
        let Some(p) = parsed else { continue };
        assert_eq!(p.to_string(), c["canonical"].as_str().unwrap(), "{text}");
    }
}

#[test]
fn dzq_merkle_and_digests() {
    let Some(dir) = vectors_dir() else { return };
    for t in json(&dir, "merkle.json")["trees"].as_array().unwrap() {
        let leaves: Vec<blake3::Hash> = t["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| blake3::Hash::from_hex(l.as_str().unwrap()).unwrap())
            .collect();
        let root = blake3::Hash::from_hex(t["root"].as_str().unwrap()).unwrap();
        assert_eq!(calculate_merkle_root(&leaves), root);
        for (i, p) in t["proofs"].as_array().unwrap().iter().enumerate() {
            let proof: MerkleProof = serde_json::from_value(p.clone()).unwrap();
            assert!(verify_merkle_proof(root, leaves[i].as_bytes(), &proof), "leaf {i}");
        }
    }
    let d = json(&dir, "digests.json");
    assert_eq!(d["schemas"]["gratitude 1.0.0"].as_str().unwrap(), acdc::gratitude_schema_said());
    assert_eq!(d["schemas"]["gratitude-condition 2.0.0"].as_str().unwrap(), acdc::gratitude_condition_schema_said());
    assert_eq!(d["schemas"]["binding 1.0.0"].as_str().unwrap(), acdc::binding_schema_said());
    for s in d["blake3_said"].as_array().unwrap() {
        assert_eq!(acdc::blake3_said(s["input"].as_str().unwrap().as_bytes()), s["said"].as_str().unwrap());
    }
    for r in d["redemption_said"].as_array().unwrap() {
        assert_eq!(acdc::redemption_said(r["gratitude"].as_str().unwrap()), r["said"].as_str().unwrap());
    }
    // The published schema files are byte for byte what the core embeds.
    let schemas = dir.join("../schemas");
    if schemas.exists() {
        assert_eq!(std::fs::read_to_string(schemas.join("gratitude.schema.json")).unwrap(), acdc::gratitude_schema_json());
        assert_eq!(
            std::fs::read_to_string(schemas.join("gratitude-condition.schema.json")).unwrap(),
            acdc::gratitude_condition_schema_json()
        );
        assert_eq!(std::fs::read_to_string(schemas.join("binding.schema.json")).unwrap(), acdc::binding_schema_json());
    }
}
