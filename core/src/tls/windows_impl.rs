//! Certificate chain as built by Windows (`CertGetCertificateChain`): from the
//! certificates sent by the server up to the root in the PC store, including the
//! intermediate CAs that the server does not send and that Windows retrieves on its own
//! (store, cache, AIA address). It is only used to show the chain: trust is decided by
//! the verifier used in the handshake.
//!
//! `crypt32.dll` is present on every edition of Windows (the verifier already imports it).

use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertFreeCertificateChain,
    CertFreeCertificateContext, CertGetCertificateChain, CertOpenStore, CERT_CHAIN_CONTEXT,
    CERT_CHAIN_PARA, CERT_CONTEXT, CERT_STORE_ADD_ALWAYS, CERT_STORE_PROV_MEMORY,
    X509_ASN_ENCODING,
};

/// Chain from the server certificate (`sent[0]`) towards the root, in DER. `None` if
/// Windows cannot build it. It may download an intermediate CA from the address
/// given in the certificate, as verification does: call it outside the async runtime.
pub(crate) fn system_chain(sent: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let first = sent.first()?;
    // SAFETY: every handle is checked before use and released before returning;
    // the chain pointers remain valid until CertFreeCertificateChain.
    unsafe {
        let store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, null());
        if store.is_null() {
            return None;
        }
        let mut leaf: *mut CERT_CONTEXT = null_mut();
        let ok = CertAddEncodedCertificateToStore(
            store,
            X509_ASN_ENCODING,
            first.as_ptr(),
            first.len() as u32,
            CERT_STORE_ADD_ALWAYS,
            &mut leaf,
        );
        if ok == 0 || leaf.is_null() {
            CertCloseStore(store, 0);
            return None;
        }
        for der in &sent[1..] {
            CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING,
                der.as_ptr(),
                der.len() as u32,
                CERT_STORE_ADD_ALWAYS,
                null_mut(),
            );
        }

        let mut para: CERT_CHAIN_PARA = std::mem::zeroed();
        para.cbSize = std::mem::size_of::<CERT_CHAIN_PARA>() as u32;
        let mut chain: *mut CERT_CHAIN_CONTEXT = null_mut();
        let ok = CertGetCertificateChain(
            Default::default(),
            leaf,
            null(),
            store,
            &para,
            0,
            null(),
            &mut chain,
        );
        let mut out = None;
        if ok != 0 && !chain.is_null() {
            let c = &*chain;
            if c.cChain > 0 && !c.rgpChain.is_null() && !(*c.rgpChain).is_null() {
                let simple = &**c.rgpChain;
                let mut v = Vec::new();
                for i in 0..simple.cElement as usize {
                    let el = *simple.rgpElement.add(i);
                    if el.is_null() || (*el).pCertContext.is_null() {
                        break;
                    }
                    let cc = &*(*el).pCertContext;
                    v.push(
                        std::slice::from_raw_parts(cc.pbCertEncoded, cc.cbCertEncoded as usize)
                            .to_vec(),
                    );
                }
                if !v.is_empty() {
                    out = Some(v);
                }
            }
            CertFreeCertificateChain(chain);
        }
        CertFreeCertificateContext(leaf);
        CertCloseStore(store, 0);
        out
    }
}
