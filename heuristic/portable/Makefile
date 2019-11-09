CC=gcc
ifeq "$(CC)" "gcc"
    COMPILER=gcc
else ifeq "$(CC)" "clang"
    COMPILER=clang
endif

ARCHITECTURE=_AMD64_
ifeq "$(ARCH)" "x64"
    ARCHITECTURE=_AMD64_
else ifeq "$(ARCH)" "x86"
    ARCHITECTURE=_X86_
else ifeq "$(ARCH)" "ARM"
    ARCHITECTURE=_ARM_
    ARM_SETTING=-lrt
else ifeq "$(ARCH)" "ARM64"
    ARCHITECTURE=_ARM64_
    ARM_SETTING=-lrt
endif

AR=ar rcs
RANLIB=ranlib

CFLAGS = -std=gnu11 -O3 -D $(ARCHITECTURE) -D __LINUX__ -fomit-frame-pointer
LDFLAGS=-lm -L/usr/lib/ -lssl -lcrypto 

ifeq "$(CC)" "gcc"
    CFLAGS+= -march=native
endif

DFLAG=
ifeq "$(STATS)" "TRUE"
    DFLAG=-DSTATS
endif

OBJECTS_I = objs_I/sign.o objs_I/pack.o objs_I/sample.o objs_I/gauss.o objs_I/poly.o objs_I/consts.o objs/fips202.o objs/random.o
OBJECTS_II = objs_II/sign.o objs_II/pack.o objs_II/sample.o objs_II/gauss.o objs_II/poly_non2.o objs_II/consts.o objs/fips202.o objs/random.o
OBJECTS_III = objs_III/sign.o objs_III/pack.o objs_III/sample.o objs_III/gauss.o objs_III/poly.o objs_III/consts.o objs/fips202.o objs/random.o
SOURCE_TEST = tests/cpucycles.c tests/test_qtesla.c
SOURCE_KATS_GEN  = tests/rng.c tests/PQCgenKAT_sign.c
SOURCE_KATS_TEST = tests/rng.c tests/PQCtestKAT_sign.c

all: lib_I lib_II lib_III tests

objs_I/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_I_ $< -o $@

objs_II/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_II_ $< -o $@

objs_III/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_III_ $< -o $@

objs/random.o: random/random.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) random/random.c -o objs/random.o

objs/fips202.o: sha3/fips202.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) sha3/fips202.c -o objs/fips202.o

lib_I: $(OBJECTS_I)
	rm -rf lib_I
	mkdir lib_I
	$(AR) lib_I/libqtesla.a $^
	$(RANLIB) lib_I/libqtesla.a

lib_II: $(OBJECTS_II)
	rm -rf lib_II
	mkdir lib_II
	$(AR) lib_II/libqtesla.a $^
	$(RANLIB) lib_II/libqtesla.a

lib_III: $(OBJECTS_III)
	rm -rf lib_III
	mkdir lib_III
	$(AR) lib_III/libqtesla.a $^
	$(RANLIB) lib_III/libqtesla.a

tests: lib_I lib_II lib_III 
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_II -D _qTESLA_II_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-II $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_II -D _qTESLA_II_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-II $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_II -D _qTESLA_II_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-II $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III -D _qTESLA_III_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-III $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III -D _qTESLA_III_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-III $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III -D _qTESLA_III_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-III $(ARM_SETTING)

.PHONY: clean

clean:
	rm -rf objs* lib* test_qtesla-* PQCgenKAT_sign-* PQCtestKAT_sign-* PQCsignKAT_qTesla*
