# qTESLA library: an efficient software implementation of the post-quantum signature scheme qTESLA in portable C.
# Includes support for the heuristic parameter sets qTESLA-I, qTESLA-III-speed, and qTESLA-III-size.

# Linux

To compile, do:

make 

which by default sets ARCH=x64, CC=gcc and DEBUG=FALSE, or do:

make ARCH=[x64/x86/ARM/ARM64] CC=[gcc/clang] DEBUG=[TRUE/FALSE]

The following executables are generated: "test\_qtesla-SET", "PQCtestKAT\_sign-SET" and "PQCgenKAT\_sign-SET",
where SET = [I / III-speed / III-size] represents one of the available parameter sets.

To get cycle counts for key generation, signing and verification, execute:

./test\_qtesla-SET

To test against known answer values in the KAT folder, execute:

./PQCtestKAT\_sign-SET

To generate new KAT files, execute:

./PQCgenKAT\_sign-SET

Using DEBUG=TRUE generates statistics on acceptance rates and timings for internal functions. 

# Windows

Open the solution file "Visual Studio\qTESLA.sln" in Visual Studio 2015 and build for one of the available 
configurations (combinations of Release\Debug and x64\x86). This creates a few executables named "test-qTESLA-SET.exe".

