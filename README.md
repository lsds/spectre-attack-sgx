# spectre-attack-sgx
Sample code demonstrating a Spectre-like attack against an Intel SGX enclave.

## Overview 
Given our [ongoing research](https://lsds.doc.ic.ac.uk/projects/sereca) on
Intel SGX here in the LSDS group at Imperial College London, a question that
occurred to us immediately on first hearing of the recent Meltdown and Spectre
attacks is *what are the security implications of speculative execution side
channels for Intel SGX enclaves*?

This repository contains a proof-of-concept attack (`SGXSpectre`) showing it is
indeed possible to use a speculative execution side-channel to leak data from
an Intel SGX enclave.   

## Attack Outline
The attack is similar conceptually to the conditional branch misprediction
[Spectre attack](https://spectreattack.com/spectre.pdf) of Kocher et al. The main
difference is that we move the secret data (`secret`) and the victim function
(`victim_function`) and overflow array (`array1`) inside [the
enclave](SGXSpectre/enclave/enclave_attack.c). The
[attacker](SGXSpectre/main/main.c) executes `victim_function` using an ecall,
passing it the index `x` used to index into `array1`. 

## Code Layout
* `SGXSpectre/main/main.c`: Contains the untrusted code to create the enclave and
mount the SGXSpectre attack.
* `SGXSpectre/enclave/enclave_attack.c`: Contains the enclave secret data
and victim function. 

## Caveats
* The attack requires that the `array1_size` variable (used to verify that `x` 
is within the bounds of `array1`) must *not* be cached. For simplicity our
proof-of-concept currently stores `array1_size` outside the enclave, allowing
the attacker to flush it with a `clflush` instruction before each invocation of
the victim function. In reality this would be unsafe, since the bounds check
should not rely on a value stored in untrusted memory. However the attack could
be adapted to keep `array1_size` inside the enclave by using an alternative
mechanism to flush it before each invocation (e.g. load other data whose
address coincides in the cache).

* For simplicity we keep the `array2` array whose entries are probed by the 
attacker outside the enclave. As mentioned in the [Spectre
paper](https://spectreattack.com/spectre.pdf), a prime+probe attack could
be used to infer the accesses to `array2` if it is not accessible to the attacker 
(e.g. if it is moved inside the enclave).
 
## How to run the code
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the SGXSpectre project with the prepared Makefile:
    * Hardware Mode:
        $ make 
    * Simulation Mode:
        $ make SGX_MODE=SIM
3. Execute the binary directly:
    $ ./sgxspectre
4. Remember to "make clean" before switching build mode

## Credits
SGXSpectre is brought to you by Dan O'Keeffe, Divya Muthukumaran, Pierre-Louis
Aublin, Florian Kelbert, Christian Priebe, Josh Lind, Huanzhou Zhu and Peter Pietzuch.
