CC = g++
DEBUG = -g
COMPILE_WITH_CODING_TOOL_LIB = 1
# compile on the HP cluster
#CFLAGS = -O3 -std=c++0x -Wall -I/opt/apps/HPCBIOS.20130301/software/GSL/1.15-goalf-1.1.0-no-OFED/include/ -c
#LIBS = -L/opt/apps/HPCBIOS.20130301/software/GSL/1.15-goalf-1.1.0-no-OFED/lib -lgsl -lgslcblas -lgmpxx -lgmp
# compile on local machine
#CFLAGS = -O3 -flto -mpopcnt -std=c++11 -c 
# -DNDEBUG disables all assert() -- see: http://www.cplusplus.com/reference/cassert/assert/
#CFLAGS = -O3 -std=gnu++11 -mpopcnt -mtune=native -m64 -flto -Wall -DNDEBUG -c # with NDEBUG
#override CFLAGS += -O3 -std=gnu++11 -mpopcnt -mtune=native -m64 -flto -Wall -c
#CFLAGS += -O3 -std=gnu++11 -mpopcnt -mtune=native -m64 -flto -Wall -c # <-
#CFLAGS = -O3 -Wall -std=c++11 -mpopcnt -flto -pg -c # profiling with gprof
#CFLAGS = -O3 -ffloat-store -std=c++0x -Wall -c 
#CFLAGS = -O2 -std=c++0x -Wall -c 
#CFLAGS = -O1 -std=c++0x -Wall -c 
#CFLAGS = -O3 -std=c++11 -Wall -DNDEBUG -c
#CFLAGS = -O3 -std=c++11 -Wall -c
CFLAGS = -std=c++11 -Wall -c
#CFLAGS = -ggdb -std=c++11 -Wall -c
#CFLAGS = -O3 -Wall -std=c++11 -pg -c # profiling with gprof
#CFLAGS = -ggdb -Wall -Wextra -pedantic -std=c++11 -Wshadow -Wformat=2 -Wfloat-equal -Wconversion -Wlogical-op -Wcast-qual -Wcast-align -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -D_FORTIFY_SOURCE=2 -fstack-protector -c # codeforces tricks
#LIBS = -lgsl -lgslcblas -lgmpxx -lgmp -pg # profiling with gprof
LIBS = -lgsl -lgslcblas -lgmpxx -lgmp
#endif
# Compilation with special flags: http://codeforces.com/blog/entry/15547
#CFLAGS = -Wall -Wextra -pedantic -std=c++11 -O2 -Wshadow -Wformat=2 -Wfloat-equal -Wconversion -Wlogical-op -Wcast-qual -Wcast-align -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC -D_FORTIFY_SOURCE=2 -fsanitize=address -fsanitize=undefined -fno-sanitize-recover -fstack-protector -c
#CFLAGS = -O3 -std=c++0x -Wall -I/usr/include/graphviz/ -c 
#LIBS = -lgsl -lgslcblas -lgmpxx -lgmp -lgvc
INCLUDES= ./include/
SOURCE_PATH = ./src/
BIN_PATH = ./bin/
OBJ_PATH = ./obj/
TESTS_PATH = ./tests/


#CFLAGS = -pg -std=c++0x -Wall -I/opt/apps/HPCBIOS.20130301/software/GSL/1.15-goalf-1.1.0-no-OFED/include/ -c
#LFLAGS = -Wall -pg
#LFLAGS = -Wl,--no-undefined

#CFLAGS = -O3 -march=native -ftree-vectorize -ftree-vectorizer-verbose=3 -foptimize-sibling-calls -fmerge-all-constants -std=c++0x -Wall -c

all: programs tests

programs: adp-xor \
          max-adp-xor \
          adp-xor-fi \
          max-adp-xor-fi \
          xdp-add \
          max-xdp-add \
          adp-xor3 \
          max-adp-xor3 \
          adp-lsh \
          adp-rsh \
          eadp-tea-f \
          max-eadp-tea-f \
          xtea-xor-threshold-search \
          tea-add-threshold-search \
          xtea-add-threshold-search 

tests: adp-xor-tests \
       adp-xor-fi-tests \
       adp-xor3-tests \
       xdp-add-tests \
       max-adp-xor-tests \
       max-adp-xor-fi-tests \
       max-adp-xor3-tests \
       max-adp-xor3-set-tests \
       max-xdp-add-tests \
       adp-shift-tests \
       adp-rsh-xor-tests \
       eadp-tea-f-tests \
       adp-tea-f-fk-tests \
       adp-tea-f-fk-ddt-tests \
       adp-tea-f-fk-noshift-tests \
       xdp-tea-f-fk-tests \
       xdp-xtea-f-fk-tests \
       adp-xtea-f-fk-tests \
       xdp-add-pddt-tests \
       adp-xor-pddt-tests \
       tea-f-add-pddt-tests \
       adp-arx-tests \
       simon-xor-threshold-search-tests \
       speck-tests \
       speck-xor-threshold-search-tests \
       speck-best-diff-search-tests \
       speck-best-linear-search-tests \
       speckey-best-diff-search-tests \
       speckey-best-linear-search-tests

# --- VA-TESTS ---

VA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)bsdr.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)va-tests.o

va-tests: common.o adp-xor.o xdp-add.o max-xdp-add.o bsdr.o xdp-add-diff-set.o va-tests.o
	$(CC) $(LFLAGS) $(VA_TESTS_OBJ) -o $(BIN_PATH)va-tests $(LIBS)

va-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)va-tests.cc -o $(OBJ_PATH)va-tests.o

# --- ADP-ROT-TESTS ---

ADP_ROT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)adp-rot-tests.o

adp-rot-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)adp-rot-tests.o
	$(CC) $(LFLAGS) $(ADP_ROT_TESTS_OBJ) -o $(BIN_PATH)adp-rot-tests $(LIBS)

$(OBJ_PATH)adp-rot-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-rot-tests.cc -o $(OBJ_PATH)adp-rot-tests.o

$(OBJ_PATH)adp-rot.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rot.cc -o $(OBJ_PATH)adp-rot.o

ADP_ROT_PROGRAM_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)adp-rot-program.o

adp-rot-program: $(OBJ_PATH)common.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)adp-rot-program.o
	$(CC) $(LFLAGS) $(ADP_ROT_PROGRAM_OBJ) -o $(BIN_PATH)adp-rot-program $(LIBS)

$(OBJ_PATH)adp-rot-program.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rot-program.cc -o $(OBJ_PATH)adp-rot-program.o

# --- ADP-MUL ---

ADP_MUL_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-mul.o $(OBJ_PATH)adp-mul-tests.o

adp-mul-tests: common.o adp-mul.o adp-mul-tests.o
	$(CC) $(LFLAGS) $(ADP_MUL_TESTS_OBJ) -o $(BIN_PATH)adp-mul-tests $(LIBS)

adp-mul-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-mul-tests.cc -o $(OBJ_PATH)adp-mul-tests.o

adp-mul.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-mul.cc -o $(OBJ_PATH)adp-mul.o

# -- IDEA --

IDEA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)bsdr.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-count-odiff.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-count-odiff.o $(OBJ_PATH)adp-mul.o $(OBJ_PATH)idea.o

idea: common.o bsdr.o adp-xor.o adp-xor-count-odiff.o adp-xor-fi.o adp-xor-fi-count-odiff.o adp-mul.o idea.o
	$(CC) $(LFLAGS) $(IDEA_TESTS_OBJ) -o $(BIN_PATH)idea $(LIBS)

idea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)idea.cc -o $(OBJ_PATH)idea.o

# -- SIMON --

SIMON_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)simon.o

simon: $(OBJ_PATH)common.o $(OBJ_PATH)simon.o
	$(CC) $(LFLAGS) $(SIMON_TESTS_OBJ) -o $(BIN_PATH)simon $(LIBS)

$(OBJ_PATH)simon.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)simon.cc -o $(OBJ_PATH)simon.o

# -- SPECK --

SPECK_MARKOV_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-tests.o

.PHONY: speck-tests
speck-tests: $(BIN_PATH)speck-tests

$(BIN_PATH)speck-tests: $(OBJ_PATH)common.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-tests.o
	$(CC) $(LFLAGS) $(SPECK_MARKOV_TESTS_OBJ) -o $(BIN_PATH)speck-tests $(LIBS)

$(OBJ_PATH)speck-tests.o: $(TESTS_PATH)speck-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speck-tests.cc -o $(OBJ_PATH)speck-tests.o

# -- SPECK --

SPECK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)speck.o

speck: $(OBJ_PATH)common.o $(OBJ_PATH)speck.o
	$(CC) $(LFLAGS) $(SPECK_TESTS_OBJ) -o $(BIN_PATH)speck $(LIBS)

$(OBJ_PATH)speck.o: $(SOURCE_PATH)speck.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)speck.cc -o $(OBJ_PATH)speck.o


# --- XDP-AND ---

XDP_AND_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-and-tests.o

xdp-and-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-and-tests.o
	$(CC) $(LFLAGS) $(XDP_AND_TESTS_OBJ) -o $(BIN_PATH)xdp-and-tests $(LIBS)

$(OBJ_PATH)xdp-and.o: $(SOURCE_PATH)xdp-and.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-and.cc -o $(OBJ_PATH)xdp-and.o

$(OBJ_PATH)xdp-and-tests.o: $(TESTS_PATH)xdp-and-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-and-tests.cc -o $(OBJ_PATH)xdp-and-tests.o

# --- XDP-ROT-AND ---

XDP_ROT_AND_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-rot-and.o $(OBJ_PATH)xdp-rot-and-tests.o

xdp-rot-and-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-rot-and.o $(OBJ_PATH)xdp-rot-and-tests.o
	$(CC) $(LFLAGS) $(XDP_ROT_AND_TESTS_OBJ) -o $(BIN_PATH)xdp-rot-and-tests $(LIBS)

$(OBJ_PATH)xdp-rot-and.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-rot-and.cc -o $(OBJ_PATH)xdp-rot-and.o

$(OBJ_PATH)xdp-rot-and-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-rot-and-tests.cc -o $(OBJ_PATH)xdp-rot-and-tests.o

# --- SIMON-XOR-THRESHOLD_SEARCH ---

SIMON_XOR_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)simon.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-rot-and.o $(OBJ_PATH)simon-xor-ddt-search.o $(OBJ_PATH)simon-xor-threshold-search.o  $(OBJ_PATH)simon-xor-threshold-search-tests.o

simon-xor-threshold-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)simon.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)xdp-rot-and.o $(OBJ_PATH)simon-xor-ddt-search.o $(OBJ_PATH)simon-xor-threshold-search.o $(OBJ_PATH)simon-xor-threshold-search-tests.o
	$(CC) $(LFLAGS) $(SIMON_XOR_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)simon-xor-threshold-search-tests $(LIBS)

$(OBJ_PATH)simon-xor-ddt-search.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)simon-xor-ddt-search.cc -o $(OBJ_PATH)simon-xor-ddt-search.o

$(OBJ_PATH)simon-xor-threshold-search.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)simon-xor-threshold-search.cc -o $(OBJ_PATH)simon-xor-threshold-search.o

$(OBJ_PATH)simon-xor-threshold-search-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)simon-xor-threshold-search-tests.cc -o $(OBJ_PATH)simon-xor-threshold-search-tests.o

# --- SPECK-XOR-THRESHOLD-SEARCH ---

SPECK_XOR_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-pddt.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-xor-ddt-search.o $(OBJ_PATH)speck-xor-threshold-search.o $(OBJ_PATH)speck-xor-threshold-search-tests.o

speck-xor-threshold-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-pddt.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-xor-ddt-search.o $(OBJ_PATH)speck-xor-threshold-search.o $(OBJ_PATH)speck-xor-threshold-search-tests.o
	$(CC) $(LFLAGS) $(SPECK_XOR_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)speck-xor-threshold-search-tests $(LIBS)

$(OBJ_PATH)speck-xor-threshold-search-tests.o: $(TESTS_PATH)speck-xor-threshold-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speck-xor-threshold-search-tests.cc -o $(OBJ_PATH)speck-xor-threshold-search-tests.o

$(OBJ_PATH)speck-xor-threshold-search.o: $(SOURCE_PATH)speck-xor-threshold-search.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)speck-xor-threshold-search.cc -o $(OBJ_PATH)speck-xor-threshold-search.o

$(OBJ_PATH)speck-xor-ddt-search.o: $(SOURCE_PATH)speck-xor-ddt-search.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)speck-xor-ddt-search.cc -o $(OBJ_PATH)speck-xor-ddt-search.o

# --- SPECK-BEST-DIFF-SEARCH ---

SPECK_BEST_DIFF_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-xor-threshold-search.o $(OBJ_PATH)speck-best-diff-search-tests.o

speck-best-diff-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-xor-threshold-search.o $(OBJ_PATH)speck-best-diff-search-tests.o
	$(CC) $(LFLAGS) $(SPECK_BEST_DIFF_SEARCH_TESTS_OBJ) -o $(BIN_PATH)speck-best-diff-search-tests $(LIBS)

$(OBJ_PATH)speck-best-diff-search-tests.o: $(TESTS_PATH)speck-best-diff-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speck-best-diff-search-tests.cc -o $(OBJ_PATH)speck-best-diff-search-tests.o

# --- SPECK-BEST-LINEAR-SEARCH ---

SPECK_BEST_LINEAR_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-best-linear-search-tests.o

speck-best-linear-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)speck.o $(OBJ_PATH)speck-best-linear-search-tests.o
	$(CC) $(LFLAGS) $(SPECK_BEST_LINEAR_SEARCH_TESTS_OBJ) -o $(BIN_PATH)speck-best-linear-search-tests $(LIBS)

$(OBJ_PATH)speck-best-linear-search-tests.o: $(TESTS_PATH)speck-best-linear-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speck-best-linear-search-tests.cc -o $(OBJ_PATH)speck-best-linear-search-tests.o

# --- SPECKEY-BEST-DIFF-SEARCH ---

SPECKEY_BEST_DIFF_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)speckey-best-diff-search-tests.o

.PHONY: speckey-best-diff-search-tests
speckey-best-diff-search-tests: $(BIN_PATH)speckey-best-diff-search-tests

$(BIN_PATH)speckey-best-diff-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)speckey-best-diff-search-tests.o
	$(CC) $(LFLAGS) $(SPECKEY_BEST_DIFF_SEARCH_TESTS_OBJ) -o $(BIN_PATH)speckey-best-diff-search-tests $(LIBS)

$(OBJ_PATH)speckey-best-diff-search-tests.o: $(TESTS_PATH)speckey-best-diff-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speckey-best-diff-search-tests.cc -o $(OBJ_PATH)speckey-best-diff-search-tests.o

# --- SPECKEY-BEST-LINEAR-SEARCH ---

SPECKEY_BEST_LINEAR_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)speckey-best-linear-search-tests.o

.PHONY: speckey-best-linear-search-tests
speckey-best-linear-search-tests: $(BIN_PATH)speckey-best-linear-search-tests

$(BIN_PATH)speckey-best-linear-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)speckey-best-linear-search-tests.o
	$(CC) $(LFLAGS) $(SPECKEY_BEST_LINEAR_SEARCH_TESTS_OBJ) -o $(BIN_PATH)speckey-best-linear-search-tests $(LIBS)

$(OBJ_PATH)speckey-best-linear-search-tests.o: $(TESTS_PATH)speckey-best-linear-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)speckey-best-linear-search-tests.cc -o $(OBJ_PATH)speckey-best-linear-search-tests.o

# --- MARX-BEST-DIFF-SEARCH ---

MARX_BEST_DIFF_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)marx-best-diff-search-tests.o

.PHONY: marx-best-diff-search-tests
marx-best-diff-search-tests: $(BIN_PATH)marx-best-diff-search-tests

$(BIN_PATH)marx-best-diff-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)marx-best-diff-search-tests.o
	$(CC) $(LFLAGS) $(MARX_BEST_DIFF_SEARCH_TESTS_OBJ) -o $(BIN_PATH)marx-best-diff-search-tests $(LIBS)

$(OBJ_PATH)marx-best-diff-search-tests.o: $(TESTS_PATH)marx-best-diff-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)marx-best-diff-search-tests.cc -o $(OBJ_PATH)marx-best-diff-search-tests.o

# --- MARX-BEST-LINEAR-SEARCH ---

MARX_BEST_LINEAR_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)marx-best-linear-search-tests.o

.PHONY: marx-best-linear-search-tests
marx-best-linear-search-tests: $(BIN_PATH)marx-best-linear-search-tests

$(BIN_PATH)marx-best-linear-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)marx-best-linear-search-tests.o
	$(CC) $(LFLAGS) $(MARX_BEST_LINEAR_SEARCH_TESTS_OBJ) -o $(BIN_PATH)marx-best-linear-search-tests $(LIBS)

$(OBJ_PATH)marx-best-linear-search-tests.o: $(TESTS_PATH)marx-best-linear-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)marx-best-linear-search-tests.cc -o $(OBJ_PATH)marx-best-linear-search-tests.o

# --- SPARX-WIDETRAIL-SEARCH ---

SPARX_WIDETRAIL_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)sparx-widetrail-search-tests.o

.PHONY: sparx-widetrail-search-tests
sparx-widetrail-search-tests: $(BIN_PATH)sparx-widetrail-search-tests

$(BIN_PATH)sparx-widetrail-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)sparx-widetrail-search-tests.o
	$(CC) $(LFLAGS) $(SPARX_WIDETRAIL_SEARCH_TESTS_OBJ) -o $(BIN_PATH)sparx-widetrail-search-tests $(LIBS)

$(OBJ_PATH)sparx-widetrail-search-tests.o: $(TESTS_PATH)sparx-widetrail-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)sparx-widetrail-search-tests.cc -o $(OBJ_PATH)sparx-widetrail-search-tests.o

# --- SPARX-WIDETRAIL-SINGLEPART-SEARCH ---

SPARX_WIDETRAIL_SINGLEPART_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)sparx-widetrail-singlepart-tests.o

.PHONY: sparx-widetrail-singlepart-tests
sparx-widetrail-singlepart-tests: $(BIN_PATH)sparx-widetrail-singlepart-tests

$(BIN_PATH)sparx-widetrail-singlepart-tests: $(OBJ_PATH)common.o $(OBJ_PATH)sparx-widetrail-singlepart-tests.o
	$(CC) $(LFLAGS) $(SPARX_WIDETRAIL_SINGLEPART_TESTS_OBJ) -o $(BIN_PATH)sparx-widetrail-singlepart-tests $(LIBS)

$(OBJ_PATH)sparx-widetrail-singlepart-tests.o: $(TESTS_PATH)sparx-widetrail-singlepart-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)sparx-widetrail-singlepart-tests.cc -o $(OBJ_PATH)sparx-widetrail-singlepart-tests.o

# -- LAX-CIPHER --

$(OBJ_PATH)lax-cipher.o: $(SOURCE_PATH)lax-cipher.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)lax-cipher.cc -o $(OBJ_PATH)lax-cipher.o

# --- LAX-BEST-DIFF-SEARCH ---

LAX_BEST_DIFF_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)lax-cipher.o $(OBJ_PATH)lax-best-diff-search-tests.o

.PHONY: lax-best-diff-search-tests
lax-best-diff-search-tests: $(BIN_PATH)lax-best-diff-search-tests

$(BIN_PATH)lax-best-diff-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)lax-cipher.o $(OBJ_PATH)lax-best-diff-search-tests.o
	$(CC) $(LFLAGS) $(LAX_BEST_DIFF_SEARCH_TESTS_OBJ) -o $(BIN_PATH)lax-best-diff-search-tests $(LIBS)

$(OBJ_PATH)lax-best-diff-search-tests.o: $(TESTS_PATH)lax-best-diff-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)lax-best-diff-search-tests.cc -o $(OBJ_PATH)lax-best-diff-search-tests.o

# --- LAX-BEST-LINEAR-SEARCH ---

LAX_BEST_LINEAR_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)lax-cipher.o $(OBJ_PATH)lax-best-linear-search-tests.o

.PHONY: lax-best-linear-search-tests
lax-best-linear-search-tests: $(BIN_PATH)lax-best-linear-search-tests

$(BIN_PATH)lax-best-linear-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)lax-cipher.o $(OBJ_PATH)lax-best-linear-search-tests.o
	$(CC) $(LFLAGS) $(LAX_BEST_LINEAR_SEARCH_TESTS_OBJ) -o $(BIN_PATH)lax-best-linear-search-tests $(LIBS)

$(OBJ_PATH)lax-best-linear-search-tests.o: $(TESTS_PATH)lax-best-linear-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)lax-best-linear-search-tests.cc -o $(OBJ_PATH)lax-best-linear-search-tests.o

# -- BSDR --

$(OBJ_PATH)bsdr.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)bsdr.cc -o $(OBJ_PATH)bsdr.o

# --- XDP-ADD-DIFF-SET ---

XDP-ADD-DIFF-SET_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)xdp-add-diff-set-tests.o

xdp-add-diff-set-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)xdp-add-diff-set-tests.o
	$(CC) $(LFLAGS) $(XDP-ADD-DIFF-SET_TESTS_OBJ) -o $(BIN_PATH)xdp-add-diff-set-tests $(LIBS)

$(OBJ_PATH)xdp-add-diff-set.o: $(SOURCE_PATH)xdp-add-diff-set.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-diff-set.cc -o $(OBJ_PATH)xdp-add-diff-set.o

$(OBJ_PATH)xdp-add-diff-set-tests.o: $(TESTS_PATH)xdp-add-diff-set-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-diff-set-tests.cc -o $(OBJ_PATH)xdp-add-diff-set-tests.o

# --- TWEETCIPHER ---

TWEETCIPHER_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tweetcipher-tests.o

tweetcipher-tests: common.o tweetcipher-tests.o
	$(CC) $(LFLAGS) $(TWEETCIPHER_TESTS_OBJ) -o $(BIN_PATH)tweetcipher-tests $(LIBS)

tweetcipher-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tweetcipher-tests.cc -o $(OBJ_PATH)tweetcipher-tests.o

# --- THREEFISH ---

THREEFISH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)threefish.o $(OBJ_PATH)threefish-xor.o $(OBJ_PATH)threefish-add.o $(OBJ_PATH)threefish-tests.o

threefish-tests: common.o xdp-add.o max-xdp-add.o xdp-add-diff-set.o threefish.o threefish-xor.o threefish-add.o threefish-tests.o
	$(CC) $(LFLAGS) $(THREEFISH_TESTS_OBJ) -o $(BIN_PATH)threefish-tests $(LIBS)

threefish-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)threefish-tests.cc -o $(OBJ_PATH)threefish-tests.o

threefish.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)threefish.cc -o $(OBJ_PATH)threefish.o

threefish-xor.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)threefish-xor.cc -o $(OBJ_PATH)threefish-xor.o

threefish-add.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)threefish-add.cc -o $(OBJ_PATH)threefish-add.o

# --- SALSA ---

SALSA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)salsa.o $(OBJ_PATH)salsa-tests.o

salsa-tests: common.o xdp-add.o xdp-add-diff-set.o salsa.o salsa-tests.o
	$(CC) $(LFLAGS) $(SALSA_TESTS_OBJ) -o $(BIN_PATH)salsa-tests $(LIBS)

salsa-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)salsa-tests.cc -o $(OBJ_PATH)salsa-tests.o

salsa.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)salsa.cc -o $(OBJ_PATH)salsa.o

# --- RC5 ---
# Note: some files need the CodingTool library

ifdef COMPILE_WITH_CODING_TOOL_LIB
RC5_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)rc5-ref.o $(OBJ_PATH)rc5-lwcs.o  $(OBJ_PATH)rc5-dc.o $(OBJ_PATH)rc5-eq.o $(OBJ_PATH)rc5-alex.o $(OBJ_PATH)add-approx.o $(OBJ_PATH)rc5-blind-oracle.o $(OBJ_PATH)rc5-tests.o -L../codingtool/lib/ 
else
RC5_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)rc5-ref.o $(OBJ_PATH)rc5-eq.o $(OBJ_PATH)rc5-dc.o $(OBJ_PATH)rc5-alex.o $(OBJ_PATH)add-approx.o $(OBJ_PATH)rc5-blind-oracle.o $(OBJ_PATH)rc5-tests.o
endif

ifdef COMPILE_WITH_CODING_TOOL_LIB
rc5-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)rc5-ref.o $(OBJ_PATH)rc5-lwcs.o $(OBJ_PATH)rc5-dc.o $(OBJ_PATH)rc5-eq.o $(OBJ_PATH)rc5-alex.o $(OBJ_PATH)add-approx.o $(OBJ_PATH)rc5-blind-oracle.o $(OBJ_PATH)rc5-tests.o
	$(CC) $(LFLAGS) $(RC5_TESTS_OBJ) -o $(BIN_PATH)rc5-tests $(LIBS) -lCodingTool
$(OBJ_PATH)rc5-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) -I../codingtool/includes/ $(TESTS_PATH)rc5-tests.cc -o $(OBJ_PATH)rc5-tests.o
$(OBJ_PATH)rc5-lwcs.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) -I../codingtool/includes/ $(SOURCE_PATH)rc5-lwcs.cc -o $(OBJ_PATH)rc5-lwcs.o
else
rc5-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-rot.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)rc5-ref.o $(OBJ_PATH)rc5-eq.o $(OBJ_PATH)rc5-dc.o $(OBJ_PATH)rc5-alex.o $(OBJ_PATH)add-approx.o $(OBJ_PATH)rc5-blind-oracle.o $(OBJ_PATH)rc5-tests.o
	$(CC) $(LFLAGS) $(RC5_TESTS_OBJ) -o $(BIN_PATH)rc5-tests $(LIBS)
$(OBJ_PATH)rc5-tests.o: $(TESTS_PATH)rc5-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)rc5-tests.cc -o $(OBJ_PATH)rc5-tests.o
endif

$(OBJ_PATH)rc5-ref.o: $(SOURCE_PATH)rc5-ref.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)rc5-ref.cc -o $(OBJ_PATH)rc5-ref.o

$(OBJ_PATH)rc5-eq.o: $(SOURCE_PATH)rc5-eq.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)rc5-eq.cc -o $(OBJ_PATH)rc5-eq.o

$(OBJ_PATH)rc5-dc.o: $(SOURCE_PATH)rc5-dc.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)rc5-dc.cc -o $(OBJ_PATH)rc5-dc.o

$(OBJ_PATH)rc5-alex.o: $(SOURCE_PATH)rc5-alex.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)rc5-alex.cc -o $(OBJ_PATH)rc5-alex.o

$(OBJ_PATH)add-approx.o: $(SOURCE_PATH)add-approx.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)add-approx.cc -o $(OBJ_PATH)add-approx.o

$(OBJ_PATH)rc5-blind-oracle.o: $(SOURCE_PATH)rc5-blind-oracle.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)rc5-blind-oracle.cc -o $(OBJ_PATH)rc5-blind-oracle.o

# --- XTEA-XOR-THRESHOLD-SEARCH

XTEA_XOR_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xtea-f-xor-pddt.o $(OBJ_PATH)xtea-xor-threshold-search.o $(OBJ_PATH)xtea-xor-threshold-search-tests.o

xtea-xor-threshold-search: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xtea-f-xor-pddt.o $(OBJ_PATH)xtea-xor-threshold-search.o $(OBJ_PATH)xtea-xor-threshold-search-tests.o
	$(CC) $(LFLAGS) $(XTEA_XOR_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)xtea-xor-threshold-search $(LIBS)

$(OBJ_PATH)xtea-f-xor-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-f-xor-pddt.cc -o $(OBJ_PATH)xtea-f-xor-pddt.o

$(OBJ_PATH)xtea-xor-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-xor-threshold-search.cc -o $(OBJ_PATH)xtea-xor-threshold-search.o

$(OBJ_PATH)xtea-xor-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xtea-xor-threshold-search-tests.cc -o $(OBJ_PATH)xtea-xor-threshold-search-tests.o

# --- XTEA-ADD-THRESHOLD-SEARCH

XTEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)xtea-f-add-pddt.o $(OBJ_PATH)xtea-add-threshold-search.o $(OBJ_PATH)xtea-add-threshold-search-tests.o

xtea-add-threshold-search: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)xtea-f-add-pddt.o $(OBJ_PATH)xtea-add-threshold-search.o $(OBJ_PATH)xtea-add-threshold-search-tests.o
	$(CC) $(LFLAGS) $(XTEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)xtea-add-threshold-search $(LIBS)

$(OBJ_PATH)xtea-f-add-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-f-add-pddt.cc -o $(OBJ_PATH)xtea-f-add-pddt.o

$(OBJ_PATH)xtea-add-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-add-threshold-search.cc -o $(OBJ_PATH)xtea-add-threshold-search.o

$(OBJ_PATH)xtea-add-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xtea-add-threshold-search-tests.cc -o $(OBJ_PATH)xtea-add-threshold-search-tests.o

# --- ADP-XTEA-F-FK ---

ADP_XTEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)adp-xtea-f-fk-tests.o

adp-xtea-f-fk-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)adp-xtea-f-fk-tests.o
	$(CC) $(LFLAGS) $(ADP_XTEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)adp-xtea-f-fk-tests $(LIBS)

$(OBJ_PATH)adp-xtea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xtea-f-fk.cc -o $(OBJ_PATH)adp-xtea-f-fk.o

$(OBJ_PATH)adp-xtea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xtea-f-fk-tests.cc -o $(OBJ_PATH)adp-xtea-f-fk-tests.o

# --- XDP-XTEA-F-FK ---

XDP_XTEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xdp-xtea-f-fk-tests.o

xdp-xtea-f-fk-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xdp-xtea-f-fk-tests.o
	$(CC) $(LFLAGS) $(XDP_XTEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)xdp-xtea-f-fk-tests $(LIBS)

$(OBJ_PATH)xdp-xtea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-xtea-f-fk.cc -o $(OBJ_PATH)xdp-xtea-f-fk.o

$(OBJ_PATH)xdp-xtea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-xtea-f-fk-tests.cc -o $(OBJ_PATH)xdp-xtea-f-fk-tests.o

$(OBJ_PATH)xtea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea.cc -o $(OBJ_PATH)xtea.o

# --- XDP-TEA-F-FK ---

XDP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)xdp-tea-f-fk.o $(OBJ_PATH)xdp-tea-f-fk-tests.o

xdp-tea-f-fk-tests: $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)xdp-tea-f-fk.o $(OBJ_PATH)xdp-tea-f-fk-tests.o
	$(CC) $(LFLAGS) $(XDP_TEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)xdp-tea-f-fk-tests $(LIBS)

$(OBJ_PATH)xdp-tea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-tea-f-fk.cc -o $(OBJ_PATH)xdp-tea-f-fk.o

$(OBJ_PATH)xdp-tea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-tea-f-fk-tests.cc -o $(OBJ_PATH)xdp-tea-f-fk-tests.o

# --- TEA-ADD-THRESHOLD-SEARCH

TEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-add-threshold-search.o $(OBJ_PATH)tea-add-threshold-search-tests.o

tea-add-threshold-search: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-add-threshold-search.o $(OBJ_PATH)tea-add-threshold-search-tests.o
	$(CC) $(LFLAGS) $(TEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)tea-add-threshold-search $(LIBS)

$(OBJ_PATH)tea-add-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-add-threshold-search.cc -o $(OBJ_PATH)tea-add-threshold-search.o

$(OBJ_PATH)tea-add-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-add-threshold-search-tests.cc -o $(OBJ_PATH)tea-add-threshold-search-tests.o

# --- TEA-F-ADD-PDDT ---

TEA_F_ADD_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-f-add-pddt-tests.o

tea-f-add-pddt-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-f-add-pddt-tests.o
	$(CC) $(LFLAGS) $(TEA_F_ADD_PDDT_TESTS_OBJ) -o $(BIN_PATH)tea-f-add-pddt-tests $(LIBS)

$(OBJ_PATH)tea-f-add-pddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-f-add-pddt-tests.cc -o $(OBJ_PATH)tea-f-add-pddt-tests.o

$(OBJ_PATH)tea-f-add-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-f-add-pddt.cc -o $(OBJ_PATH)tea-f-add-pddt.o

# --- TEA-ADD-DDT-SEARCH ---

TEA_ADD_DDT_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-ddt.o $(OBJ_PATH)tea-add-ddt-search.o $(OBJ_PATH)tea-add-ddt-search-tests.o

tea-add-ddt-search-tests: common.o tea.o adp-tea-f-fk-ddt.o tea-add-ddt-search.o tea-add-ddt-search-tests.o
	$(CC) $(LFLAGS) $(TEA_ADD_DDT_SEARCH_TESTS_OBJ) -o $(BIN_PATH)tea-add-ddt-search-tests $(LIBS)

tea-add-ddt-search.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-add-ddt-search.cc -o $(OBJ_PATH)tea-add-ddt-search.o

tea-add-ddt-search-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-add-ddt-search-tests.cc -o $(OBJ_PATH)tea-add-ddt-search-tests.o

# --- ADP-TEA-F-FK-DDT ---

ADP_TEA_F_FK_DDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-ddt.o $(OBJ_PATH)adp-tea-f-fk-ddt-tests.o

adp-tea-f-fk-ddt-tests: $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-ddt.o $(OBJ_PATH)adp-tea-f-fk-ddt-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_DDT_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-ddt-tests $(LIBS)

$(OBJ_PATH)adp-tea-f-fk-ddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk-ddt.cc -o $(OBJ_PATH)adp-tea-f-fk-ddt.o

$(OBJ_PATH)adp-tea-f-fk-ddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-ddt-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-ddt-tests.o

# --- ADP-TEA-F-FK-NOSHIFT ---

ADP_TEA_F_FK_NOSHIFT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-noshift.o $(OBJ_PATH)adp-tea-f-fk-noshift-tests.o

adp-tea-f-fk-noshift-tests: $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-noshift.o $(OBJ_PATH)adp-tea-f-fk-noshift-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_NOSHIFT_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-noshift-tests $(LIBS)

$(OBJ_PATH)adp-tea-f-fk-noshift.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk-noshift.cc -o $(OBJ_PATH)adp-tea-f-fk-noshift.o

$(OBJ_PATH)adp-tea-f-fk-noshift-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-noshift-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-noshift-tests.o

# --- ADP-TEA-F-FK ---

ADP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)adp-tea-f-fk-tests.o

adp-tea-f-fk-tests: $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)adp-tea-f-fk-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-tests $(LIBS)

$(OBJ_PATH)adp-tea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk.cc -o $(OBJ_PATH)adp-tea-f-fk.o

$(OBJ_PATH)adp-tea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-tests.o

# --- EADP-TEA-F ---

EADP_TEA_F_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-program.o
MAX_EADP_TEA_F_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)max-eadp-tea-f-program.o
EADP_TEA_F_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o  $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-tests.o

eadp-tea-f: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-program.o
	$(CC) $(LFLAGS) $(EADP_TEA_F_OBJ) -o $(BIN_PATH)eadp-tea-f $(LIBS)

max-eadp-tea-f: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)max-eadp-tea-f-program.o
	$(CC) $(LFLAGS) $(MAX_EADP_TEA_F_OBJ) -o $(BIN_PATH)max-eadp-tea-f $(LIBS)

eadp-tea-f-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-tests.o
	$(CC) $(LFLAGS) $(EADP_TEA_F_TESTS_OBJ) -o $(BIN_PATH)eadp-tea-f-tests $(LIBS)

$(OBJ_PATH)tea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea.cc -o $(OBJ_PATH)tea.o

$(OBJ_PATH)eadp-tea-f.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)eadp-tea-f.cc -o $(OBJ_PATH)eadp-tea-f.o

$(OBJ_PATH)eadp-tea-f-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)eadp-tea-f-program.cc -o $(OBJ_PATH)eadp-tea-f-program.o

$(OBJ_PATH)max-eadp-tea-f-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-eadp-tea-f-program.cc -o $(OBJ_PATH)max-eadp-tea-f-program.o

$(OBJ_PATH)eadp-tea-f-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)eadp-tea-f-tests.cc -o $(OBJ_PATH)eadp-tea-f-tests.o

# --- MAX-XDP-ADD ---

MAX_XDP_ADD_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-program.o
MAX_XDP_ADD_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-tests.o

max-xdp-add: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-program.o
	$(CC) $(LFLAGS) $(MAX_XDP_ADD_OBJ) -o $(BIN_PATH)max-xdp-add $(LIBS)

max-xdp-add-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-tests.o
	$(CC) $(LFLAGS) $(MAX_XDP_ADD_TESTS_OBJ) -o $(BIN_PATH)max-xdp-add-tests $(LIBS)

$(OBJ_PATH)max-xdp-add.o: $(SOURCE_PATH)max-xdp-add.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-xdp-add.cc -o $(OBJ_PATH)max-xdp-add.o

$(OBJ_PATH)max-xdp-add-program.o: $(SOURCE_PATH)max-xdp-add-program.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-xdp-add-program.cc -o $(OBJ_PATH)max-xdp-add-program.o

$(OBJ_PATH)max-xdp-add-tests.o: $(TESTS_PATH)max-xdp-add-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-xdp-add-tests.cc -o $(OBJ_PATH)max-xdp-add-tests.o

# --- XDP-ADD ---

XDP_ADD_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-program.o
XDP_ADD_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-tests.o

xdp-add: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-program.o 
	$(CC) $(LFLAGS) $(XDP_ADD_OBJ) -o $(BIN_PATH)xdp-add $(LIBS)

xdp-add-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-tests.o
	$(CC) $(LFLAGS) $(XDP_ADD_TESTS_OBJ) -o $(BIN_PATH)xdp-add-tests $(LIBS)

$(OBJ_PATH)xdp-add.o: $(SOURCE_PATH)xdp-add.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add.cc -o $(OBJ_PATH)xdp-add.o

$(OBJ_PATH)xdp-add-program.o: $(SOURCE_PATH)xdp-add-program.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-program.cc -o $(OBJ_PATH)xdp-add-program.o

$(OBJ_PATH)xdp-add-tests.o: $(TESTS_PATH)xdp-add-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-tests.cc -o $(OBJ_PATH)xdp-add-tests.o

# --- XLP-ADD ---

XLP_ADD_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)xlp-add-tests.o

xlp-add: $(OBJ_PATH)common.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)xlp-add-program.o 
	$(CC) $(LFLAGS) $(XLP_ADD_OBJ) -o $(BIN_PATH)xlp-add $(LIBS)

xlp-add-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xlp-add.o $(OBJ_PATH)xlp-add-tests.o
	$(CC) $(LFLAGS) $(XLP_ADD_TESTS_OBJ) -o $(BIN_PATH)xlp-add-tests $(LIBS)

$(OBJ_PATH)xlp-add.o: $(SOURCE_PATH)xlp-add.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xlp-add.cc -o $(OBJ_PATH)xlp-add.o

$(OBJ_PATH)xlp-add-tests.o: $(TESTS_PATH)xlp-add-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xlp-add-tests.cc -o $(OBJ_PATH)xlp-add-tests.o

# --- MAX-ADP-XOR-FI ---

MAX_ADP_XOR_FI_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-program.o
MAX_ADP_XOR_FI_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-tests.o

max-adp-xor-fi: $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_FI_OBJ) -o $(BIN_PATH)max-adp-xor-fi $(LIBS)

max-adp-xor-fi-tests: $(OBJ_PATH)common.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_FI_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor-fi-tests $(LIBS)

$(OBJ_PATH)max-adp-xor-fi.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-fi.cc -o $(OBJ_PATH)max-adp-xor-fi.o

$(OBJ_PATH)max-adp-xor-fi-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-fi-program.cc -o $(OBJ_PATH)max-adp-xor-fi-program.o

$(OBJ_PATH)max-adp-xor-fi-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor-fi-tests.cc -o $(OBJ_PATH)max-adp-xor-fi-tests.o

# --- ADP-XOR-FI ---

ADP_XOR_FI_OBJ = $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-program.o
ADP_XOR_FI_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-tests.o

adp-xor-fi: $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-program.o
	$(CC) $(LFLAGS) $(ADP_XOR_FI_OBJ) -o $(BIN_PATH)adp-xor-fi $(LIBS)

adp-xor-fi-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_FI_TESTS_OBJ) -o $(BIN_PATH)adp-xor-fi-tests $(LIBS)

$(OBJ_PATH)adp-xor-fi.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-fi.cc -o $(OBJ_PATH)adp-xor-fi.o

$(OBJ_PATH)adp-xor-fi-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-fi-program.cc -o $(OBJ_PATH)adp-xor-fi-program.o

$(OBJ_PATH)adp-xor-fi-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-fi-tests.cc -o $(OBJ_PATH)adp-xor-fi-tests.o

# --- ADP-XOR-FI-COUNT-ODIFF  ---

ADP_XOR_FI_COUNT_ODIFF_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-count-odiff.o $(OBJ_PATH)adp-xor-fi-count-odiff-tests.o

adp-xor-fi-count-odiff-tests: common.o adp-xor-fi.o adp-xor-fi-count-odiff.o adp-xor-fi-count-odiff-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_FI_COUNT_ODIFF_TESTS_OBJ) -o $(BIN_PATH)adp-xor-fi-count-odiff-tests $(LIBS)

adp-xor-fi-count-odiff-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-fi-count-odiff-tests.cc -o $(OBJ_PATH)adp-xor-fi-count-odiff-tests.o

adp-xor-fi-count-odiff.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-fi-count-odiff.cc -o $(OBJ_PATH)adp-xor-fi-count-odiff.o

# --- MAX-ADP-XOR3-SET ---

MAX_ADP_XOR3_SET_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)max-adp-xor3-set-tests.o

max-adp-xor3-set-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)max-adp-xor3-set-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_SET_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor3-set-tests $(LIBS)

$(OBJ_PATH)max-adp-xor3-set-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor3-set-tests.cc -o $(OBJ_PATH)max-adp-xor3-set-tests.o

$(OBJ_PATH)max-adp-xor3-set.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3-set.cc -o $(OBJ_PATH)max-adp-xor3-set.o

# --- MAX-ADP-XOR3 ---

MAX_ADP_XOR3_OBJ = $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-program.o
MAX_ADP_XOR3_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-tests.o

max-adp-xor3: $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_OBJ) -o $(BIN_PATH)max-adp-xor3 $(LIBS)

$(OBJ_PATH)max-adp-xor3-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3-program.cc -o $(OBJ_PATH)max-adp-xor3-program.o

max-adp-xor3-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor3-tests $(LIBS)

$(OBJ_PATH)max-adp-xor3-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor3-tests.cc -o $(OBJ_PATH)max-adp-xor3-tests.o

$(OBJ_PATH)max-adp-xor3.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3.cc -o $(OBJ_PATH)max-adp-xor3.o

# --- ADP-XOR3 ---

ADP_XOR3_OBJ = $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-program.o
ADP_XOR3_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-tests.o

adp-xor3: $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-program.o
	$(CC) $(LFLAGS) $(ADP_XOR3_OBJ) -o $(BIN_PATH)adp-xor3 $(LIBS)

adp-xor3-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR3_TESTS_OBJ) -o $(BIN_PATH)adp-xor3-tests $(LIBS)

$(OBJ_PATH)adp-xor3.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor3.cc -o $(OBJ_PATH)adp-xor3.o

$(OBJ_PATH)adp-xor3-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor3-program.cc -o $(OBJ_PATH)adp-xor3-program.o

$(OBJ_PATH)adp-xor3-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor3-tests.cc -o $(OBJ_PATH)adp-xor3-tests.o

# --- MAX-ADP-XOR ---

MAX_ADP_XOR_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-program.o
MAX_ADP_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-tests.o

max-adp-xor: $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_OBJ) -o $(BIN_PATH)max-adp-xor $(LIBS)

max-adp-xor-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor-tests $(LIBS)

$(OBJ_PATH)max-adp-xor.o: $(SOURCE_PATH)max-adp-xor.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor.cc -o $(OBJ_PATH)max-adp-xor.o

$(OBJ_PATH)max-adp-xor-program.o: $(SOURCE_PATH)max-adp-xor-program.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-program.cc -o $(OBJ_PATH)max-adp-xor-program.o

$(OBJ_PATH)max-adp-xor-tests.o: $(TESTS_PATH)max-adp-xor-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor-tests.cc -o $(OBJ_PATH)max-adp-xor-tests.o

# --- ADP-RSH-XOR ---

ADP_RSH_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-xor.o $(OBJ_PATH)adp-rsh-xor-tests.o

adp-rsh-xor-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-xor.o $(OBJ_PATH)adp-rsh-xor-tests.o
	$(CC) $(LFLAGS) $(ADP_RSH_XOR_TESTS_OBJ) -o $(BIN_PATH)adp-rsh-xor-tests $(LIBS)

$(OBJ_PATH)adp-rsh-xor.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rsh-xor.cc -o $(OBJ_PATH)adp-rsh-xor.o

$(OBJ_PATH)adp-rsh-xor-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-rsh-xor-tests.cc -o $(OBJ_PATH)adp-rsh-xor-tests.o

# --- ADP-SHIFT ---

ADP_LSH_OBJ = $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-lsh-program.o
ADP_RSH_OBJ = $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-program.o
ADP_SHIFT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-shift-tests.o

adp-lsh: $(OBJ_PATH)common.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-lsh-program.o
	$(CC) $(LFLAGS) $(ADP_LSH_OBJ) -o $(BIN_PATH)adp-lsh $(LIBS)

adp-rsh: $(OBJ_PATH)common.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-program.o
	$(CC) $(LFLAGS) $(ADP_RSH_OBJ) -o $(BIN_PATH)adp-rsh $(LIBS)

adp-shift-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-shift-tests.o
	$(CC) $(LFLAGS) $(ADP_SHIFT_TESTS_OBJ) -o $(BIN_PATH)adp-shift-tests $(LIBS)

$(OBJ_PATH)adp-lsh-program.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-lsh-program.cc -o $(OBJ_PATH)adp-lsh-program.o

$(OBJ_PATH)adp-rsh-program.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rsh-program.cc -o $(OBJ_PATH)adp-rsh-program.o

$(OBJ_PATH)adp-shift.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-shift.cc -o $(OBJ_PATH)adp-shift.o

$(OBJ_PATH)adp-shift-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-shift-tests.cc -o $(OBJ_PATH)adp-shift-tests.o

# --- XDP-ADD-PDDT ---

XDP_ADD_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-pddt.o $(OBJ_PATH)xdp-add-pddt-tests.o

xdp-add-pddt-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-pddt.o $(OBJ_PATH)xdp-add-pddt-tests.o
	$(CC) $(LFLAGS) $(XDP_ADD_PDDT_TESTS_OBJ) -o $(BIN_PATH)xdp-add-pddt-tests $(LIBS)

$(OBJ_PATH)xdp-add-pddt.o: $(SOURCE_PATH)xdp-add-pddt.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-pddt.cc -o $(OBJ_PATH)xdp-add-pddt.o

$(OBJ_PATH)xdp-add-pddt-tests.o: $(TESTS_PATH)xdp-add-pddt-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-pddt-tests.cc -o $(OBJ_PATH)xdp-add-pddt-tests.o

# --- ADP-XOR-PDDT ---

ADP_XOR_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-pddt.o $(OBJ_PATH)adp-xor-pddt-tests.o

adp-xor-pddt-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-pddt.o $(OBJ_PATH)adp-xor-pddt-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_PDDT_TESTS_OBJ) -o $(BIN_PATH)adp-xor-pddt-tests $(LIBS)

$(OBJ_PATH)adp-xor-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-pddt.cc -o $(OBJ_PATH)adp-xor-pddt.o

$(OBJ_PATH)adp-xor-pddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-pddt-tests.cc -o $(OBJ_PATH)adp-xor-pddt-tests.o

# --- ADP-ARX ---

ADP_ARX_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-arx.o $(OBJ_PATH)max-adp-arx.o $(OBJ_PATH)adp-arx-tests.o

adp-arx-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-arx.o $(OBJ_PATH)max-adp-arx.o $(OBJ_PATH)adp-arx-tests.o
	$(CC) $(LFLAGS) $(ADP_ARX_TESTS_OBJ) -o $(BIN_PATH)adp-arx-tests $(LIBS)

$(OBJ_PATH)adp-arx.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-arx.cc -o $(OBJ_PATH)adp-arx.o

$(OBJ_PATH)max-adp-arx.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-arx.cc -o $(OBJ_PATH)max-adp-arx.o

$(OBJ_PATH)adp-arx-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-arx-tests.cc -o $(OBJ_PATH)adp-arx-tests.o

# --- ADP-XOR ---

ADP_XOR_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-program.o
ADP_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-tests.o

adp-xor: $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-program.o
	$(CC) $(LFLAGS) $(ADP_XOR_OBJ) -o $(BIN_PATH)adp-xor $(LIBS)

adp-xor-tests: $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_TESTS_OBJ) -o $(BIN_PATH)adp-xor-tests $(LIBS)

$(OBJ_PATH)adp-xor.o: $(SOURCE_PATH)adp-xor.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor.cc -o $(OBJ_PATH)adp-xor.o

$(OBJ_PATH)adp-xor-program.o: $(SOURCE_PATH)adp-xor-program.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-program.cc -o $(OBJ_PATH)adp-xor-program.o

$(OBJ_PATH)adp-xor-tests.o: $(TESTS_PATH)adp-xor-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-tests.cc -o $(OBJ_PATH)adp-xor-tests.o

# --- ADP-XOR-COUNT-ODIFF ---

ADP_XOR_COUNT_ODIFF_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-count-odiff.o $(OBJ_PATH)adp-xor-count-odiff-tests.o

adp-xor-count-odiff-tests: common.o adp-xor.o adp-xor-count-odiff.o adp-xor-count-odiff-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_COUNT_ODIFF_TESTS_OBJ) -o $(BIN_PATH)adp-xor-count-odiff-tests $(LIBS)

adp-xor-count-odiff-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-count-odiff-tests.cc -o $(OBJ_PATH)adp-xor-count-odiff-tests.o

adp-xor-count-odiff.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-count-odiff.cc -o $(OBJ_PATH)adp-xor-count-odiff.o

# --- GRAPHVIZ-TEST ---

GRAPHVIZ_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)graphviz-tests.o

graphviz-tests: common.o graphviz-tests.o
	$(CC) $(LFLAGS) $(GRAPHVIZ_TESTS_OBJ) -o $(BIN_PATH)graphviz-tests $(LIBS)

graphviz-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)graphviz-tests.cc -o $(OBJ_PATH)graphviz-tests.o

# --- COMMON ---

$(OBJ_PATH)common.o: $(SOURCE_PATH)common.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)common.cc -o $(OBJ_PATH)common.o

clean:
	rm -v $(BIN_PATH)*; rm -v $(OBJ_PATH)*.o

# --- MORUS ---

MORUS_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)morus-tests.o

morus-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)morus-tests.o
	$(CC) $(LFLAGS) $(MORUS_TESTS_OBJ) -o $(BIN_PATH)morus-tests $(LIBS)

$(OBJ_PATH)morus-tests.o: $(TESTS_PATH)morus-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)morus-tests.cc -o $(OBJ_PATH)morus-tests.o

# --- LINEAR_CODE ---

LINEAR_CODE_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)linear-code-tests.o

linear-code-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)linear-code-tests.o
	$(CC) $(LFLAGS) $(LINEAR_CODE_TESTS_OBJ) -o $(BIN_PATH)linear-code-tests $(LIBS)

$(OBJ_PATH)linear-code-tests.o: $(TESTS_PATH)linear-code-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)linear-code-tests.cc -o $(OBJ_PATH)linear-code-tests.o

# --- NORX ---

NORX_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)norx-tests.o

norx-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-and.o $(OBJ_PATH)norx-tests.o
	$(CC) $(LFLAGS) $(NORX_TESTS_OBJ) -o $(BIN_PATH)norx-tests $(LIBS)

$(OBJ_PATH)norx-tests.o: $(TESTS_PATH)norx-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)norx-tests.cc -o $(OBJ_PATH)norx-tests.o

# --- NORX-BEST-DIFF-SEARCH ---

NORX_BEST_DIFF_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)norx-common.o $(OBJ_PATH)norx-best-diff-search-tests.o

.PHONY: norx-best-diff-search-tests
norx-best-diff-search-tests: $(BIN_PATH)norx-best-diff-search-tests

$(BIN_PATH)norx-best-diff-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)norx-common.o $(OBJ_PATH)norx-best-diff-search-tests.o
	$(CC) $(LFLAGS) $(NORX_BEST_DIFF_SEARCH_TESTS_OBJ) -o $(BIN_PATH)norx-best-diff-search-tests $(LIBS)

$(OBJ_PATH)norx-best-diff-search-tests.o: $(TESTS_PATH)norx-best-diff-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)norx-best-diff-search-tests.cc -o $(OBJ_PATH)norx-best-diff-search-tests.o

$(OBJ_PATH)norx-common.o: $(SOURCE_PATH)norx-common.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)norx-common.cc -o $(OBJ_PATH)norx-common.o


# --- NORX-LWC-SEARCH ---

NORX_LWC_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)norx-common.o $(OBJ_PATH)norx-lwc-search-tests.o -L../codingtool/lib/ 

.PHONY: norx-lwc-search-testsa
norx-lwc-search-tests: $(BIN_PATH)norx-lwc-search-tests

$(BIN_PATH)norx-lwc-search-tests: $(OBJ_PATH)common.o $(OBJ_PATH)norx-common.o $(OBJ_PATH)norx-lwc-search-tests.o
	$(CC) $(LFLAGS) $(NORX_LWC_SEARCH_TESTS_OBJ) -o $(BIN_PATH)norx-lwc-search-tests $(LIBS) -lCodingTool

$(OBJ_PATH)norx-lwc-search-tests.o: $(TESTS_PATH)norx-lwc-search-tests.cc
	$(CC) $(CFLAGS) -I$(INCLUDES) -I../codingtool/includes/ $(TESTS_PATH)norx-lwc-search-tests.cc -o $(OBJ_PATH)norx-lwc-search-tests.o

