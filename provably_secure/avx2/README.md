## qTESLA library: AVX2-optimized implementation for x64 platforms on Linux

Includes support for the provably-secure parameter sets qTESLA-p-I and qTESLA-p-III.

## Linux

To compile, do:

```sh
make 
```

which by default sets `ARCH=x64`, `CC=gcc` and `STATS=FALSE`, or do:

```sh
make CC=[gcc/clang] STATS=[TRUE/FALSE]
```

The following executables are generated: `test_qtesla-SET`, `PQCtestKAT_sign-SET` and `PQCgenKAT_sign-SET`,
where `SET = [p-I / p-III]` represents one of the available parameter sets.

To get cycle counts for key generation, signing and verification, execute:

```sh
./test_qtesla-SET
```

To test against known answer values in the KAT folder, execute:

```sh
./PQCtestKAT_sign-SET
```

To generate new KAT files, execute:

```sh
./PQCgenKAT_sign-SET
```

Using `STATS=TRUE` generates statistics about acceptance rates and timings for internal functions.

