# Lit ECDSA Combine
Portable lightweight recombination client application for threshold ECDSA.

Ported from ZenGo's Emerald City implementation of GG18 (based on [GG18](https://eprint.iacr.org/2019/114.pdf)), modified for GG20 structs.

Much of the core "curv" library has been removed to avoid using untried code; the basic goal is a pretty simple accumulation of shares from Lit Nodes in order to recreate a signature on the client web browser.

Validation checks are not included in the final release deploy - they add significant bloat to the WASM code, without any current benifits.   A validation check can be run directly using the web3.js or ethers.js library, which are currently a requirement for the Lit JS SDK.