# Third-party software

Network Toolbox is licensed under the Apache License 2.0 (see `LICENSE` and `NOTICE`). It includes or links the following third-party components. This list was generated with `cargo metadata` for the `x86_64-pc-windows-msvc` target; the license text of each crate is shipped in its source package.

## Data and fonts

| Component | Where | License |
|---|---|---|
| Instrument Sans (font) | `ui/fonts/` | SIL Open Font License 1.1 (`ui/fonts/OFL-InstrumentSans.txt`) |
| JetBrains Mono (font) | `ui/fonts/` | SIL Open Font License 1.1 (`ui/fonts/OFL-JetBrainsMono.txt`) |
| IEEE OUI registry (`oui.txt`) | `src-tauri/resources/` | Public registry published by the IEEE; no copyright claimed, free distribution |

## Rust dependencies (333 crates)

Dependencies are listed by license expression (an `A / B` expression means a choice between the two licenses).

### MIT / Apache-2.0 (173)

aes 0.8.4, anyhow 1.0.104, asn1-rs 0.6.2, asn1-rs-derive 0.5.1, async-trait 0.1.92, base64 0.22.1, base64 0.23.1, bitflags 2.13.2, block-buffer 0.10.4, block-padding 0.3.3, camino 1.2.6, cargo-platform 0.1.9, cbc 0.1.2, cc 1.10.0, cfb-mode 0.8.2, cfg-if 1.0.5, chacha20 0.10.2, chrono 0.4.45, cipher 0.4.4, cookie 0.18.2, cpufeatures 0.2.17, cpufeatures 0.3.1, crc32fast 1.5.3, critical-section 1.2.0, crossbeam-channel 0.5.17, crossbeam-epoch 0.9.21, crossbeam-utils 0.8.23, crypto-common 0.1.7, defmt 1.2.0, defmt-macros 1.2.0, defmt-parser 1.1.0, deranged 0.5.9, des 0.8.1, digest 0.10.7, dirs 7.0.0, dirs-sys 0.5.0, displaydoc 0.2.7, dtoa 1.0.11, dyn-clone 1.0.20, either 1.19.0, erased-serde 0.4.11, fdeflate 0.3.7, find-msvc-tools 0.1.15, flate2 1.1.10, form_urlencoded 1.2.3, futures-channel 0.3.34, futures-core 0.3.34, futures-io 0.3.34, futures-macro 0.3.34, futures-sink 0.3.34, futures-task 0.3.34, futures-util 0.3.34, getrandom 0.2.17, getrandom 0.3.4, getrandom 0.4.3, glob 0.3.4, hashbrown 0.12.3, hashbrown 0.17.1, heck 0.5.0, hex 0.4.3, hickory-net 0.26.3, hickory-proto 0.26.3, hickory-resolver 0.26.3, hmac 0.12.1, html5ever 0.39.0, http 1.5.0, httparse 1.10.1, idna 1.1.0, inout 0.1.4, ipnet 2.12.2, itoa 1.0.18, jsonptr 0.7.1, keyboard-types 0.8.3, lazy_static 1.5.1, libc 0.2.191, lock_api 0.4.14, log 0.4.34, markup5ever 0.39.0, md-5 0.10.6, mime 0.3.17, native-tls 0.2.18, num-bigint 0.4.8, num-conv 0.2.2, num-integer 0.1.47, num-traits 0.2.19, oid-registry 0.7.1, once_cell 1.21.4, parking_lot 0.12.5, parking_lot_core 0.9.12, percent-encoding 2.3.2, png 0.18.1, powerfmt 0.2.1, prefix-trie 0.8.4, proc-macro2 1.0.107, quote 1.0.47, rand 0.10.4, rand_core 0.10.1, ref-cast 1.0.27, ref-cast-impl 1.0.27, regex 1.13.1, regex-automata 0.4.18, regex-syntax 0.8.11, reqwest 0.12.28, resolv-conf 0.7.6, rustc_version 0.4.1, rustls-pki-types 1.15.1, rustls-platform-verifier 0.5.3, scopeguard 1.2.0, semver 1.0.28, serde 1.0.229, serde-untagged 0.1.9, serde_core 1.0.229, serde_derive 1.0.229, serde_derive_internals 0.29.1, serde_json 1.0.154, serde_repr 0.1.21, serde_spanned 1.1.2, serde_with 3.24.0, serde_with_macros 3.24.0, serialize-to-javascript 0.1.2, serialize-to-javascript-impl 0.1.2, servo_arc 0.4.3, sha1 0.10.7, sha2 0.10.9, shlex 2.0.1, siphasher 1.0.4, smallvec 1.16.4, socket2 0.6.5, softbuffer 0.4.8, stable_deref_trait 1.2.1, string_cache 0.9.0, string_cache_codegen 0.6.1, syn 2.0.119, syn 3.0.9, tendril 0.5.1, thiserror 1.0.69, thiserror 2.0.21, thiserror-impl 1.0.69, thiserror-impl 2.0.21, time 0.3.55, time-core 0.1.9, time-macros 0.2.32, tokio-rustls 0.26.6, toml 1.1.8+spec-1.1.0, toml_datetime 1.1.2+spec-1.1.0, toml_parser 1.1.5+spec-1.1.0, toml_writer 1.1.3+spec-1.1.0, tray-icon 0.25.1, typeid 1.0.3, typenum 1.20.1, unicode-segmentation 1.13.3, url 2.5.9, web-time 1.1.0, web_atoms 0.2.6, widestring 1.2.1, windows 0.62.2, windows-collections 0.3.2, windows-core 0.62.2, windows-future 0.3.2, windows-implement 0.60.2, windows-interface 0.59.3, windows-link 0.2.1, windows-numerics 0.3.1, windows-registry 0.6.1, windows-result 0.4.1, windows-strings 0.5.1, windows-sys 0.59.0, windows-sys 0.61.2, windows-targets 0.52.6, windows-threading 0.2.1, windows-version 0.1.7, windows_x86_64_msvc 0.52.6, x509-parser 0.16.0

### MIT (60)

bytes 1.12.1, cargo_metadata 0.19.2, cfb 0.14.0, darling 0.24.1, darling_core 0.24.1, darling_macro 0.24.1, data-encoding 2.11.1, derive_more 2.1.1, derive_more-impl 2.1.1, dom_query 0.28.0, embed-resource 3.0.12, generic-array 0.14.7, http-body 1.1.0, http-body-util 0.1.5, hyper 1.12.0, hyper-util 0.1.21, ico 0.6.0, infer 0.22.0, mio 1.2.4, new_debug_unreachable 1.0.6, nom 7.1.3, phf 0.13.1, phf_codegen 0.13.1, phf_generator 0.13.1, phf_macros 0.13.1, phf_shared 0.13.1, plist 1.10.3, precomputed-hash 0.1.1, quick-xml 0.42.0, schannel 0.1.30, schemars 0.8.22, schemars 0.9.0, schemars 1.2.3, schemars_derive 0.8.22, simd-adler32 0.3.10, slab 0.4.12, strsim 0.11.1, synstructure 0.13.2, synstructure 0.14.0, tauri-winres 0.3.7, tokio 1.54.1, tokio-macros 2.7.2, tokio-native-tls 0.3.1, tower 0.5.3, tower-http 0.6.11, tower-layer 0.3.3, tower-service 0.3.3, tracing 0.1.44, tracing-core 0.1.36, try-lock 0.2.5, urlpattern 0.6.0, vswhom 0.1.0, vswhom-sys 0.1.3, want 0.3.2, webview2-com 0.39.1, webview2-com-macros 0.8.1, webview2-com-sys 0.39.1, winnow 1.0.4, winreg 0.56.0, zmij 1.0.23

### Apache-2.0 / MIT (29)

atomic-waker 1.1.2, autocfg 1.5.1, bit-set 0.8.0, bit-vec 0.8.0, cargo_toml 1.0.1, ctor 1.0.13, equivalent 1.0.3, fastrand 2.5.0, fnv 1.0.7, idna_adapter 1.2.2, indexmap 1.9.3, indexmap 2.14.2, muda 0.20.0, pin-project-lite 0.2.17, portable-atomic 1.15.0, rustc-hash 2.1.3, tauri 2.12.5, tauri-build 2.7.4, tauri-codegen 2.7.4, tauri-macros 2.7.4, tauri-runtime 2.12.2, tauri-runtime-wry 2.12.3, tauri-utils 2.10.2, utf8_iter 1.1.0, utf_types 1.0.0, uuid 1.29.0, window-vibrancy 0.8.1, wry 0.57.1, zeroize 1.9.1

### Unicode-3.0 (18)

icu_collections 2.4.0, icu_locale_core 2.4.0, icu_normalizer 2.4.0, icu_normalizer_data 2.4.0, icu_properties 2.4.0, icu_properties_data 2.4.0, icu_provider 2.4.0, litemap 0.8.3, potential_utf 0.1.6, tinystr 0.8.5, writeable 0.6.4, yoke 0.8.4, yoke-derive 0.8.4, zerofrom 0.1.8, zerofrom-derive 0.1.8, zerotrie 0.2.5, zerovec 0.11.9, zerovec-derive 0.11.7

### MIT/Apache-2.0 (13)

asn1-rs-impl 0.2.0, bitflags 1.3.2, bs58 0.5.1, der-parser 9.0.0, hyper-tls 0.6.0, ident_case 1.0.1, ipconfig 0.3.4, json-patch 4.2.0, minimal-lexical 0.2.1, rusticata-macros 4.1.0, serde_urlencoded 0.7.1, tagptr 0.2.0, version_check 0.9.5

### Unlicense / MIT (8)

aho-corasick 1.1.5, byteorder 1.5.0, jiff 0.2.38, jiff-core 0.1.1, jiff-tzdb 0.1.9, jiff-tzdb-platform 0.1.3, memchr 2.8.3, winapi-util 0.1.11

### MPL-2.0 (5)

cssparser 0.37.0, cssparser-macros 0.7.1, dtoa-short 0.3.5, option-ext 0.2.0, selectors 0.38.0

### BSD-3-Clause (3)

alloc-no-stdlib 3.0.0, alloc-stdlib 0.3.0, subtle 2.6.1

### Apache-2.0 (2)

sync_wrapper 1.0.2, tao 0.37.2

### ISC (2)

rustls-webpki 0.103.16, untrusted 0.9.0

### MIT / Apache-2.0 / Zlib (2)

raw-window-handle 0.6.2, static_vcruntime 3.0.0

### MIT / Zlib / Apache-2.0 (2)

miniz_oxide 0.8.9, miniz_oxide 0.9.1

### Unlicense/MIT (2)

same-file 1.0.6, walkdir 2.5.0

### Zlib (2)

foldhash 0.2.0, zlib-rs 0.6.8

### (MIT / Apache-2.0) AND Apache-2.0 (1)

moka 0.12.16

### (MIT / Apache-2.0) AND Unicode-3.0 (1)

unicode-ident 1.0.27

### 0BSD / MIT / Apache-2.0 (1)

adler2 2.0.1

### Apache-2.0 / BSL-1.0 (1)

ryu 1.0.23

### Apache-2.0 / ISC / MIT (1)

rustls 0.23.46

### Apache-2.0 AND ISC (1)

ring 0.17.14

### Apache-2.0 AND MIT (1)

dpi 0.1.2

### BSD-3-Clause AND MIT (1)

brotli 9.1.1

### BSD-3-Clause/MIT (1)

brotli-decompressor 6.2.0

### CC0-1.0 / MIT-0 / Apache-2.0 (1)

dunce 1.0.5

### MIT / BSD-3-Clause (1)

if-addrs 0.13.4

### Zlib / Apache-2.0 / MIT (1)

tinyvec 1.13.3
