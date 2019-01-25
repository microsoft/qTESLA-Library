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
ifeq "$(DEBUG)" "TRUE"
    DFLAG=-DDEBUG
endif

OBJECTS_I = objs_I/sign.o objs_I/pack.o objs_I/sample.o objs_I/gauss.o objs_I/poly.o objs_I/consts.o objs/fips202.o objs/random.o
OBJECTS_III_SPEED = objs_III_speed/sign.o objs_III_speed/pack.o objs_III_speed/sample.o objs_III_speed/gauss.o objs_III_speed/poly.o objs_III_speed/consts.o objs/fips202.o objs/random.o
OBJECTS_III_SIZE = objs_III_size/sign.o objs_III_size/pack.o objs_III_size/sample.o objs_III_size/gauss.o objs_III_size/poly.o objs_III_size/consts.o objs/fips202.o objs/random.o
SOURCE_TEST = tests/cpucycles.c tests/test_qtesla.c
SOURCE_KATS_GEN  = tests/rng.c tests/PQCgenKAT_sign.c
SOURCE_KATS_TEST = tests/rng.c tests/PQCtestKAT_sign.c

all: lib_I lib_III_speed lib_III_size tests

objs_I/%.o: %.c
	@mkdir -p $(@D)
#	$(CC) $(CFLAGS) $(DFLAG) -D _qTESLA_I_ -S $< -o objs_I/$*.asm -masm=intel
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_I_ $< -o $@

objs_III_speed/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_III_speed_ $< -o $@

objs_III_size/%.o: %.c
	@mkdir -p $(@D)
	$(CC) -c $(CFLAGS) $(DFLAG) -D _qTESLA_III_size_ $< -o $@

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

lib_III_speed: $(OBJECTS_III_SPEED)
	rm -rf lib_III_speed
	mkdir lib_III_speed
	$(AR) lib_III_speed/libqtesla.a $^
	$(RANLIB) lib_III_speed/libqtesla.a

lib_III_size: $(OBJECTS_III_SIZE)
	rm -rf lib_III_size
	mkdir lib_III_size
	$(AR) lib_III_size/libqtesla.a $^
	$(RANLIB) lib_III_size/libqtesla.a

tests: lib_I lib_III_speed lib_III_size
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_I -D _qTESLA_I_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-I $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_speed -D _qTESLA_III_speed_ $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-III-speed $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_speed -D _qTESLA_III_speed_ $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-III-speed $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_speed -D _qTESLA_III_speed_ $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-III-speed $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_size  -D _qTESLA_III_size_  $(SOURCE_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o test_qtesla-III-size $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_size  -D _qTESLA_III_size_  $(SOURCE_KATS_GEN) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCgenKAT_sign-III-size $(ARM_SETTING)
	$(CC) $(CFLAGS) -L./lib_III_size  -D _qTESLA_III_size_  $(SOURCE_KATS_TEST) $(DFLAG) -lqtesla $(LDFLAGS) -o PQCtestKAT_sign-III-size $(ARM_SETTING)

.PHONY: clean

clean:
	rm -rf objs* lib* test_qtesla-* PQCgenKAT_sign-* PQCtestKAT_sign-* PQCsignKAT_qTesla*
