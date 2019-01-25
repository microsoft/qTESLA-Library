
# qTESLA library v1.0 (C Edition)

**qTESLA** is a software library written in the C language that contains optimized implementations of the lattice-based digital signature scheme qTESLA [1]. 

qTESLA is a family of high-performance signature schemes based on the hardness of the decisional ring learning with errors (R-LWE) problem that is conjectured to be secure against quantum computer attacks. qTESLA comes in two variants: (i) **heuristic qTESLA**, which involves a heuristic parameter generation, and is intended for embedded and high-performance applications; and (ii) **provably-secure qTESLA**, which involves a provably-secure parameter generation according to existing security reductions, and is intended for high-sensitive applications.

Concretely, the qTESLA library includes the following heuristic qTESLA schemes:

* qTESLA-I: matching the post-quantum security of AES128.
* qTESLA-III-speed: matching the post-quantum security of AES192 (option for speed).
* qTESLA-III-size: matching the post-quantum security of AES192 (option for size).

And the following provably-secure qTESLA schemes:

* qTESLA-p-I: matching the post-quantum security of AES128.
* qTESLA-p-III: matching the post-quantum security of AES192.

The library was developed by [Microsoft Research](http://research.microsoft.com/) using as basis the [`qTESLA implementation`](https://github.com/qtesla/qTesla) developed by the qTESLA team and submitted to NIST's Post-Quantum Cryptography Standardization process [2].

## Contents

Available implementations:

* [`Portable implementation for heuristic qTESLA`](heuristic/portable/): portable implementation of heuristic qTESLA for 32-bit and 64-bit platforms. 
* [`AVX2-optimized implementation for heuristic qTESLA`](heuristic/avx2/): optimized implementation of heuristic qTESLA for x64 platforms using AVX2 instructions.
* [`Portable implementation for provably-secure qTESLA`](provably_secure/portable/): portable implementation of provably-secure qTESLA for 32-bit and 64-bit platforms. 

Each of the implementation folders above contains:

* KAT folder: known answer tests for 32-bit and 64-platforms.
* random folder: randombytes function using the system random number generator.
* sha3 folder: implementation of SHAKE and cSHAKE.  
* tests folder: test files for KATs, functionality and benchmarking.  
* Visual Studio folder (portable implementations): Visual Studio 2015 files for compilation in Windows.
* Makefile: Makefile for compilation using the GNU GCC or clang compilers on Linux. 
* README.md: readme file for each implementation.
* Source and header files.

Other files:

* [`License`](LICENSE): MIT license file.
* [`Readme`](README.md): this readme file.

## Main Features

- Supports two security levels matching the post-quantum security of AES128 and AES192.
- Protected against timing and cache-timing attacks through regular, constant-time implementation of 
  all operations on secret key material.
- Support for Windows OS using Microsoft Visual Studio and Linux OS using GNU GCC and clang.     
- Includes portable-C implementations with support for a wide range of platforms including x64, x86 and ARM. 
- Includes AVX2-optimized implementations for x64 platforms running Linux. 

## Supported Platforms

**qTESLA v1.0** is supported on a wide range of platforms including x64, x86 and ARM devices running Windows 
or Linux OS. We have tested the library with Microsoft Visual Studio 2015, GNU GCC v7.2, and clang v3.8.
See instructions below to choose an implementation option and compile on one of the supported platforms.

## Instructions for compilation and testing

Choose one of the available implementations and follow the instructions in the corresponding README.md file.

## License

This software is licensed under the MIT License; see [`License`](LICENSE) for details.
It includes some third party modules that are licensed differently. In particular:

- `sha3/fips202.c`: public domain
- `sha3/fips202x4.c`: public domain
- `sha3/keccak4x`: all files in this folder are public domain ([CC0](http://creativecommons.org/publicdomain/zero/1.0/)), excepting
- `sha3/keccak4x/brg_endian.h` which is copyrighted by Brian Gladman and comes with a BSD 3-clause license.
- `tests/ds_benchmark.h`: public domain
- `tests/PQCgenKAT_sign.c`: copyrighted by Lawrence E. Bassham 
- `tests/PQCtestKAT_sign.c`: copyrighted by Lawrence E. Bassham
- `tests/rng.c`: copyrighted by Lawrence E. Bassham 

# References

[1]  Erdem Alkim, Paulo S. L. M. Barreto, Nina Bindel, Patrick Longa, and Jefferson E. Ricardini. The lattice-based digital signature scheme qTESLA. 
The preprint version is available [`here`](http://eprint.iacr.org/2016/963). 

[2]  Nina Bindel, Sedat Akleylek, Erdem Alkim, Paulo S. L. M. Barreto, Johannes Buchmann, Edward Eaton, Gus Gutoski, Juliane Kramer, Patrick Longa, Harun Polat, Jefferson E. Ricardini, and Gustavo Zanon. Submission to NIST’s post-quantum standardization project: lattice-based digital signature scheme qTESLA. https://qtesla.org/   

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
