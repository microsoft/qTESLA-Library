## qTESLA library: AVX2-optimized implementation for x64 platforms on Linux

Includes support for the heuristic parameter sets qTESLA-I, qTESLA-III-speed, and qTESLA-III-size.

## Linux

To compile, do:

```sh
make 
```

which by default sets `ARCH=x64`, `CC=gcc` and `DEBUG=FALSE`, or do:

```sh
make CC=[gcc/clang] DEBUG=[TRUE/FALSE]
```

The following executables are generated: `test\_qtesla-SET`, `PQCtestKAT\_sign-SET` and `PQCgenKAT\_sign-SET`,
where `SET = [I / III-speed / III-size]` represents one of the available parameter sets.

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

Using `DEBUG=TRUE` generates statistics about acceptance rates and timings for internal functions. 
