CC = g++
DEBUG = -g
LFLAGS = -Wall
CFLAGS = -O3 -std=c++0x -Wall -c
GSL_LIB = -lgsl -lgslcblas -lgmpxx -lgmp
INCLUDES= ./include/
SOURCE_PATH = ./src/
BIN_PATH = ./bin/
OBJ_PATH = ./obj/
TESTS_PATH = ./tests/

#CFLAGS = -g -pg -std=c++0x -Wall -c
#LFLAGS = -Wall -pg
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
       adp-arx-tests 

# --- VA-TESTS ---

VA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)bsdr.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)va-tests.o

va-tests: common.o adp-xor.o xdp-add.o max-xdp-add.o bsdr.o xdp-add-diff-set.o va-tests.o
	$(CC) $(LFLAGS) $(VA_TESTS_OBJ) -o $(BIN_PATH)va-tests $(GSL_LIB)

va-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)va-tests.cc -o $(OBJ_PATH)va-tests.o

# --- ADP-MUL ---

ADP_MUL_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-mul.o $(OBJ_PATH)adp-mul-tests.o

adp-mul-tests: common.o adp-mul.o adp-mul-tests.o
	$(CC) $(LFLAGS) $(ADP_MUL_TESTS_OBJ) -o $(BIN_PATH)adp-mul-tests $(GSL_LIB)

adp-mul-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-mul-tests.cc -o $(OBJ_PATH)adp-mul-tests.o

adp-mul.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-mul.cc -o $(OBJ_PATH)adp-mul.o

# -- IDEA --

IDEA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)idea.o

idea: common.o idea.o
	$(CC) $(LFLAGS) $(ADP_MUL_TESTS_OBJ) -o $(BIN_PATH)idea $(GSL_LIB)

idea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)idea.cc -o $(OBJ_PATH)idea.o

# -- BSDR --

bsdr.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)bsdr.cc -o $(OBJ_PATH)bsdr.o

# --- XDP-ADD-DIFF-SET ---

XDP-ADD-DIFF-SET_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)xdp-add-diff-set-tests.o

xdp-add-diff-set-tests: common.o adp-xor.o xdp-add.o max-xdp-add.o xdp-add-diff-set.o xdp-add-diff-set-tests.o
	$(CC) $(LFLAGS) $(XDP-ADD-DIFF-SET_TESTS_OBJ) -o $(BIN_PATH)xdp-add-diff-set-tests $(GSL_LIB)

xdp-add-diff-set.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-diff-set.cc -o $(OBJ_PATH)xdp-add-diff-set.o

xdp-add-diff-set-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-diff-set-tests.cc -o $(OBJ_PATH)xdp-add-diff-set-tests.o

# --- THREEFISH ---

THREEFISH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)threefish.o $(OBJ_PATH)threefish-tests.o

threefish-tests: common.o xdp-add.o max-xdp-add.o xdp-add-diff-set.o threefish.o threefish-tests.o
	$(CC) $(LFLAGS) $(THREEFISH_TESTS_OBJ) -o $(BIN_PATH)threefish-tests $(GSL_LIB)

threefish-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)threefish-tests.cc -o $(OBJ_PATH)threefish-tests.o

threefish.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)threefish.cc -o $(OBJ_PATH)threefish.o

# --- SALSA ---

SALSA_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-diff-set.o $(OBJ_PATH)salsa.o $(OBJ_PATH)salsa-tests.o

salsa-tests: common.o xdp-add.o xdp-add-diff-set.o salsa.o salsa-tests.o
	$(CC) $(LFLAGS) $(SALSA_TESTS_OBJ) -o $(BIN_PATH)salsa-tests $(GSL_LIB)

salsa-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)salsa-tests.cc -o $(OBJ_PATH)salsa-tests.o

salsa.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)salsa.cc -o $(OBJ_PATH)salsa.o

# --- XTEA-XOR-THRESHOLD-SEARCH

XTEA_XOR_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xtea-f-xor-pddt.o $(OBJ_PATH)xtea-xor-threshold-search.o $(OBJ_PATH)xtea-xor-threshold-search-tests.o

xtea-xor-threshold-search: common.o xdp-add.o max-xdp-add.o xtea.o xdp-xtea-f-fk.o xtea-f-xor-pddt.o xtea-xor-threshold-search.o xtea-xor-threshold-search-tests.o
	$(CC) $(LFLAGS) $(XTEA_XOR_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)xtea-xor-threshold-search $(GSL_LIB)

xtea-f-xor-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-f-xor-pddt.cc -o $(OBJ_PATH)xtea-f-xor-pddt.o

xtea-xor-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-xor-threshold-search.cc -o $(OBJ_PATH)xtea-xor-threshold-search.o

xtea-xor-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xtea-xor-threshold-search-tests.cc -o $(OBJ_PATH)xtea-xor-threshold-search-tests.o

# --- XTEA-ADD-THRESHOLD-SEARCH

XTEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)xtea-f-add-pddt.o $(OBJ_PATH)xtea-add-threshold-search.o $(OBJ_PATH)xtea-add-threshold-search-tests.o

xtea-add-threshold-search: common.o adp-xor.o max-adp-xor.o adp-xor-fi.o max-adp-xor-fi.o adp-shift.o xtea.o adp-xtea-f-fk.o tea.o eadp-tea-f.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o adp-tea-f-fk.o tea-f-add-pddt.o xtea-f-add-pddt.o xtea-add-threshold-search.o xtea-add-threshold-search-tests.o
	$(CC) $(LFLAGS) $(XTEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)xtea-add-threshold-search $(GSL_LIB)

xtea-f-add-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-f-add-pddt.cc -o $(OBJ_PATH)xtea-f-add-pddt.o

xtea-add-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea-add-threshold-search.cc -o $(OBJ_PATH)xtea-add-threshold-search.o

xtea-add-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xtea-add-threshold-search-tests.cc -o $(OBJ_PATH)xtea-add-threshold-search-tests.o

# --- ADP-XTEA-F-FK ---

ADP_XTEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)xtea.o $(OBJ_PATH)adp-xtea-f-fk.o $(OBJ_PATH)adp-xtea-f-fk-tests.o

adp-xtea-f-fk-tests: common.o adp-xor.o max-adp-xor.o adp-xor-fi.o max-adp-xor-fi.o adp-shift.o xtea.o adp-xtea-f-fk.o adp-xtea-f-fk-tests.o
	$(CC) $(LFLAGS) $(ADP_XTEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)adp-xtea-f-fk-tests $(GSL_LIB)

adp-xtea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xtea-f-fk.cc -o $(OBJ_PATH)adp-xtea-f-fk.o

adp-xtea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xtea-f-fk-tests.cc -o $(OBJ_PATH)adp-xtea-f-fk-tests.o

# --- XDP-XTEA-F-FK ---

XDP_XTEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)xtea.o $(OBJ_PATH)xdp-xtea-f-fk.o $(OBJ_PATH)xdp-xtea-f-fk-tests.o

xdp-xtea-f-fk-tests: common.o xdp-add.o max-xdp-add.o xtea.o xdp-xtea-f-fk.o xdp-xtea-f-fk-tests.o
	$(CC) $(LFLAGS) $(XDP_XTEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)xdp-xtea-f-fk-tests $(GSL_LIB)

xdp-xtea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-xtea-f-fk.cc -o $(OBJ_PATH)xdp-xtea-f-fk.o

xdp-xtea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-xtea-f-fk-tests.cc -o $(OBJ_PATH)xdp-xtea-f-fk-tests.o

xtea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xtea.cc -o $(OBJ_PATH)xtea.o

# --- XDP-TEA-F-FK ---

XDP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)xdp-tea-f-fk.o $(OBJ_PATH)xdp-tea-f-fk-tests.o

xdp-tea-f-fk-tests: common.o tea.o xdp-tea-f-fk.o xdp-tea-f-fk-tests.o
	$(CC) $(LFLAGS) $(XDP_TEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)xdp-tea-f-fk-tests $(GSL_LIB)

xdp-tea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-tea-f-fk.cc -o $(OBJ_PATH)xdp-tea-f-fk.o

xdp-tea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-tea-f-fk-tests.cc -o $(OBJ_PATH)xdp-tea-f-fk-tests.o

# --- TEA-ADD-THRESHOLD-SEARCH

TEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-add-threshold-search.o $(OBJ_PATH)tea-add-threshold-search-tests.o

tea-add-threshold-search: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o adp-shift.o tea.o eadp-tea-f.o adp-tea-f-fk.o tea-f-add-pddt.o tea-add-threshold-search.o tea-add-threshold-search-tests.o
	$(CC) $(LFLAGS) $(TEA_ADD_THRESHOLD_SEARCH_TESTS_OBJ) -o $(BIN_PATH)tea-add-threshold-search $(GSL_LIB)

tea-add-threshold-search.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-add-threshold-search.cc -o $(OBJ_PATH)tea-add-threshold-search.o

tea-add-threshold-search-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-add-threshold-search-tests.cc -o $(OBJ_PATH)tea-add-threshold-search-tests.o

# --- TEA-F-ADD-PDDT ---

TEA_F_ADD_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)tea-f-add-pddt.o $(OBJ_PATH)tea-f-add-pddt-tests.o

tea-f-add-pddt-tests: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o tea.o adp-shift.o eadp-tea-f.o adp-tea-f-fk.o tea-f-add-pddt.o tea-f-add-pddt-tests.o
	$(CC) $(LFLAGS) $(TEA_F_ADD_PDDT_TESTS_OBJ) -o $(BIN_PATH)tea-f-add-pddt-tests $(GSL_LIB)

tea-f-add-pddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-f-add-pddt-tests.cc -o $(OBJ_PATH)tea-f-add-pddt-tests.o

tea-f-add-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-f-add-pddt.cc -o $(OBJ_PATH)tea-f-add-pddt.o

# --- TEA-ADD-DDT-SEARCH ---

TEA_ADD_DDT_SEARCH_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-ddt.o $(OBJ_PATH)tea-add-ddt-search.o $(OBJ_PATH)tea-add-ddt-search-tests.o

tea-add-ddt-search-tests: common.o tea.o adp-tea-f-fk-ddt.o tea-add-ddt-search.o tea-add-ddt-search-tests.o
	$(CC) $(LFLAGS) $(TEA_ADD_DDT_SEARCH_TESTS_OBJ) -o $(BIN_PATH)tea-add-ddt-search-tests $(GSL_LIB)

tea-add-ddt-search.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea-add-ddt-search.cc -o $(OBJ_PATH)tea-add-ddt-search.o

tea-add-ddt-search-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)tea-add-ddt-search-tests.cc -o $(OBJ_PATH)tea-add-ddt-search-tests.o

# --- ADP-TEA-F-FK-DDT ---

ADP_TEA_F_FK_DDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-ddt.o $(OBJ_PATH)adp-tea-f-fk-ddt-tests.o

adp-tea-f-fk-ddt-tests: common.o tea.o adp-tea-f-fk-ddt.o adp-tea-f-fk-ddt-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_DDT_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-ddt-tests $(GSL_LIB)

adp-tea-f-fk-ddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk-ddt.cc -o $(OBJ_PATH)adp-tea-f-fk-ddt.o

adp-tea-f-fk-ddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-ddt-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-ddt-tests.o

# --- ADP-TEA-F-FK-NOSHIFT ---

ADP_TEA_F_FK_NOSHIFT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk-noshift.o $(OBJ_PATH)adp-tea-f-fk-noshift-tests.o

adp-tea-f-fk-noshift-tests: common.o tea.o adp-tea-f-fk-noshift.o adp-tea-f-fk-noshift-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_NOSHIFT_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-noshift-tests $(GSL_LIB)

adp-tea-f-fk-noshift.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk-noshift.cc -o $(OBJ_PATH)adp-tea-f-fk-noshift.o

adp-tea-f-fk-noshift-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-noshift-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-noshift-tests.o

# --- ADP-TEA-F-FK ---

ADP_TEA_F_FK_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)tea.o $(OBJ_PATH)adp-tea-f-fk.o $(OBJ_PATH)adp-tea-f-fk-tests.o

adp-tea-f-fk-tests: common.o tea.o adp-tea-f-fk.o adp-tea-f-fk-tests.o
	$(CC) $(LFLAGS) $(ADP_TEA_F_FK_TESTS_OBJ) -o $(BIN_PATH)adp-tea-f-fk-tests $(GSL_LIB)

adp-tea-f-fk.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-tea-f-fk.cc -o $(OBJ_PATH)adp-tea-f-fk.o

adp-tea-f-fk-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-tea-f-fk-tests.cc -o $(OBJ_PATH)adp-tea-f-fk-tests.o

# --- EADP-TEA-F ---

EADP_TEA_F_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-program.o
MAX_EADP_TEA_F_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)max-eadp-tea-f-program.o
EADP_TEA_F_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o  $(OBJ_PATH)adp-shift.o $(OBJ_PATH)tea.o $(OBJ_PATH)eadp-tea-f.o $(OBJ_PATH)eadp-tea-f-tests.o

eadp-tea-f: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o adp-shift.o tea.o eadp-tea-f.o eadp-tea-f-program.o
	$(CC) $(LFLAGS) $(EADP_TEA_F_OBJ) -o $(BIN_PATH)eadp-tea-f $(GSL_LIB)

max-eadp-tea-f: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o adp-shift.o tea.o eadp-tea-f.o max-eadp-tea-f-program.o
	$(CC) $(LFLAGS) $(MAX_EADP_TEA_F_OBJ) -o $(BIN_PATH)max-eadp-tea-f $(GSL_LIB)

eadp-tea-f-tests: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o  adp-shift.o tea.o eadp-tea-f.o eadp-tea-f-tests.o
	$(CC) $(LFLAGS) $(EADP_TEA_F_TESTS_OBJ) -o $(BIN_PATH)eadp-tea-f-tests $(GSL_LIB)

tea.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)tea.cc -o $(OBJ_PATH)tea.o

eadp-tea-f.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)eadp-tea-f.cc -o $(OBJ_PATH)eadp-tea-f.o

eadp-tea-f-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)eadp-tea-f-program.cc -o $(OBJ_PATH)eadp-tea-f-program.o

max-eadp-tea-f-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-eadp-tea-f-program.cc -o $(OBJ_PATH)max-eadp-tea-f-program.o

eadp-tea-f-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)eadp-tea-f-tests.cc -o $(OBJ_PATH)eadp-tea-f-tests.o

# --- MAX-XDP-ADD ---

MAX_XDP_ADD_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-program.o
MAX_XDP_ADD_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)max-xdp-add.o $(OBJ_PATH)max-xdp-add-tests.o

max-xdp-add: common.o xdp-add.o max-xdp-add.o max-xdp-add-program.o
	$(CC) $(LFLAGS) $(MAX_XDP_ADD_OBJ) -o $(BIN_PATH)max-xdp-add $(GSL_LIB)

max-xdp-add-tests: common.o xdp-add.o max-xdp-add.o max-xdp-add-tests.o
	$(CC) $(LFLAGS) $(MAX_XDP_ADD_TESTS_OBJ) -o $(BIN_PATH)max-xdp-add-tests $(GSL_LIB)

max-xdp-add.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-xdp-add.cc -o $(OBJ_PATH)max-xdp-add.o

max-xdp-add-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-xdp-add-program.cc -o $(OBJ_PATH)max-xdp-add-program.o

max-xdp-add-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-xdp-add-tests.cc -o $(OBJ_PATH)max-xdp-add-tests.o

# --- XDP-ADD ---

XDP_ADD_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-program.o
XDP_ADD_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-tests.o

xdp-add: common.o xdp-add.o xdp-add-program.o 
	$(CC) $(LFLAGS) $(XDP_ADD_OBJ) -o $(BIN_PATH)xdp-add $(GSL_LIB)

xdp-add-tests: common.o xdp-add.o xdp-add-tests.o
	$(CC) $(LFLAGS) $(XDP_ADD_TESTS_OBJ) -o $(BIN_PATH)xdp-add-tests $(GSL_LIB)

xdp-add.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add.cc -o $(OBJ_PATH)xdp-add.o

xdp-add-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-program.cc -o $(OBJ_PATH)xdp-add-program.o

xdp-add-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-tests.cc -o $(OBJ_PATH)xdp-add-tests.o

# --- MAX-ADP-XOR-FI ---

MAX_ADP_XOR_FI_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-program.o
MAX_ADP_XOR_FI_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi.o $(OBJ_PATH)max-adp-xor-fi-tests.o

max-adp-xor-fi: adp-xor.o max-adp-xor.o adp-xor-fi.o max-adp-xor-fi.o max-adp-xor-fi-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_FI_OBJ) -o $(BIN_PATH)max-adp-xor-fi $(GSL_LIB)

max-adp-xor-fi-tests: common.o max-adp-xor.o adp-xor-fi.o max-adp-xor-fi.o max-adp-xor-fi-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_FI_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor-fi-tests $(GSL_LIB)

max-adp-xor-fi.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-fi.cc -o $(OBJ_PATH)max-adp-xor-fi.o

max-adp-xor-fi-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-fi-program.cc -o $(OBJ_PATH)max-adp-xor-fi-program.o

max-adp-xor-fi-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor-fi-tests.cc -o $(OBJ_PATH)max-adp-xor-fi-tests.o

# --- ADP-XOR-FI ---

ADP_XOR_FI_OBJ = $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-program.o
ADP_XOR_FI_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor-fi.o $(OBJ_PATH)adp-xor-fi-tests.o

adp-xor-fi: adp-xor-fi.o adp-xor-fi-program.o
	$(CC) $(LFLAGS) $(ADP_XOR_FI_OBJ) -o $(BIN_PATH)adp-xor-fi $(GSL_LIB)

adp-xor-fi-tests: common.o adp-xor-fi.o adp-xor-fi-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_FI_TESTS_OBJ) -o $(BIN_PATH)adp-xor-fi-tests $(GSL_LIB)

adp-xor-fi.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-fi.cc -o $(OBJ_PATH)adp-xor-fi.o

adp-xor-fi-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-fi-program.cc -o $(OBJ_PATH)adp-xor-fi-program.o

adp-xor-fi-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-fi-tests.cc -o $(OBJ_PATH)adp-xor-fi-tests.o

# --- MAX-ADP-XOR3-SET ---

MAX_ADP_XOR3_SET_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-set.o $(OBJ_PATH)max-adp-xor3-set-tests.o

max-adp-xor3-set-tests: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-set.o max-adp-xor3-set-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_SET_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor3-set-tests $(GSL_LIB)

max-adp-xor3-set-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor3-set-tests.cc -o $(OBJ_PATH)max-adp-xor3-set-tests.o

max-adp-xor3-set.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3-set.cc -o $(OBJ_PATH)max-adp-xor3-set.o

# --- MAX-ADP-XOR3 ---

MAX_ADP_XOR3_OBJ = $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-program.o
MAX_ADP_XOR3_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)max-adp-xor3.o $(OBJ_PATH)max-adp-xor3-tests.o

max-adp-xor3: adp-xor3.o max-adp-xor3.o max-adp-xor3-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_OBJ) -o $(BIN_PATH)max-adp-xor3 $(GSL_LIB)

max-adp-xor3-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3-program.cc -o $(OBJ_PATH)max-adp-xor3-program.o

max-adp-xor3-tests: common.o adp-xor3.o max-adp-xor3.o max-adp-xor3-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR3_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor3-tests $(GSL_LIB)

max-adp-xor3-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor3-tests.cc -o $(OBJ_PATH)max-adp-xor3-tests.o

max-adp-xor3.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor3.cc -o $(OBJ_PATH)max-adp-xor3.o

# --- ADP-XOR3 ---

ADP_XOR3_OBJ = $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-program.o
ADP_XOR3_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor3.o $(OBJ_PATH)adp-xor3-tests.o

adp-xor3: adp-xor3.o adp-xor3-program.o
	$(CC) $(LFLAGS) $(ADP_XOR3_OBJ) -o $(BIN_PATH)adp-xor3 $(GSL_LIB)

adp-xor3-tests: common.o adp-xor3.o adp-xor3-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR3_TESTS_OBJ) -o $(BIN_PATH)adp-xor3-tests $(GSL_LIB)

adp-xor3.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor3.cc -o $(OBJ_PATH)adp-xor3.o

adp-xor3-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor3-program.cc -o $(OBJ_PATH)adp-xor3-program.o

adp-xor3-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor3-tests.cc -o $(OBJ_PATH)adp-xor3-tests.o

# --- MAX-ADP-XOR ---

MAX_ADP_XOR_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-program.o
MAX_ADP_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)max-adp-xor.o $(OBJ_PATH)max-adp-xor-tests.o

max-adp-xor: adp-xor.o max-adp-xor.o max-adp-xor-program.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_OBJ) -o $(BIN_PATH)max-adp-xor $(GSL_LIB)

max-adp-xor-tests: common.o adp-xor.o max-adp-xor.o max-adp-xor-tests.o
	$(CC) $(LFLAGS) $(MAX_ADP_XOR_TESTS_OBJ) -o $(BIN_PATH)max-adp-xor-tests $(GSL_LIB)

max-adp-xor.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor.cc -o $(OBJ_PATH)max-adp-xor.o

max-adp-xor-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-xor-program.cc -o $(OBJ_PATH)max-adp-xor-program.o

max-adp-xor-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)max-adp-xor-tests.cc -o $(OBJ_PATH)max-adp-xor-tests.o

# --- ADP-RSH-XOR ---

ADP_RSH_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-xor.o $(OBJ_PATH)adp-rsh-xor-tests.o

adp-rsh-xor-tests: common.o adp-xor.o adp-shift.o adp-rsh-xor.o adp-rsh-xor-tests.o
	$(CC) $(LFLAGS) $(ADP_RSH_XOR_TESTS_OBJ) -o $(BIN_PATH)adp-rsh-xor-tests $(GSL_LIB)

adp-rsh-xor.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rsh-xor.cc -o $(OBJ_PATH)adp-rsh-xor.o

adp-rsh-xor-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-rsh-xor-tests.cc -o $(OBJ_PATH)adp-rsh-xor-tests.o

# --- ADP-SHIFT ---

ADP_LSH_OBJ = $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-lsh-program.o
ADP_RSH_OBJ = $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-rsh-program.o
ADP_SHIFT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-shift.o $(OBJ_PATH)adp-shift-tests.o

adp-lsh: common.o adp-shift.o adp-lsh-program.o
	$(CC) $(LFLAGS) $(ADP_LSH_OBJ) -o $(BIN_PATH)adp-lsh $(GSL_LIB)

adp-rsh: common.o adp-shift.o adp-rsh-program.o
	$(CC) $(LFLAGS) $(ADP_RSH_OBJ) -o $(BIN_PATH)adp-rsh $(GSL_LIB)

adp-shift-tests: common.o adp-shift.o adp-shift-tests.o
	$(CC) $(LFLAGS) $(ADP_SHIFT_TESTS_OBJ) -o $(BIN_PATH)adp-shift-tests $(GSL_LIB)

adp-lsh-program.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-lsh-program.cc -o $(OBJ_PATH)adp-lsh-program.o

adp-rsh-program.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-rsh-program.cc -o $(OBJ_PATH)adp-rsh-program.o

adp-shift.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-shift.cc -o $(OBJ_PATH)adp-shift.o

adp-shift-tests.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-shift-tests.cc -o $(OBJ_PATH)adp-shift-tests.o

# --- XDP-ADD-PDDT ---

XDP_ADD_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)xdp-add.o $(OBJ_PATH)xdp-add-pddt.o $(OBJ_PATH)xdp-add-pddt-tests.o

xdp-add-pddt-tests: common.o xdp-add.o xdp-add-pddt.o xdp-add-pddt-tests.o
	$(CC) $(LFLAGS) $(XDP_ADD_PDDT_TESTS_OBJ) -o $(BIN_PATH)xdp-add-pddt-tests $(GSL_LIB)

xdp-add-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)xdp-add-pddt.cc -o $(OBJ_PATH)xdp-add-pddt.o

xdp-add-pddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)xdp-add-pddt-tests.cc -o $(OBJ_PATH)xdp-add-pddt-tests.o

# --- ADP-XOR-PDDT ---

ADP_XOR_PDDT_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-pddt.o $(OBJ_PATH)adp-xor-pddt-tests.o

adp-xor-pddt-tests: common.o adp-xor.o adp-xor-pddt.o adp-xor-pddt-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_PDDT_TESTS_OBJ) -o $(BIN_PATH)adp-xor-pddt-tests $(GSL_LIB)

adp-xor-pddt.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-pddt.cc -o $(OBJ_PATH)adp-xor-pddt.o

adp-xor-pddt-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-pddt-tests.cc -o $(OBJ_PATH)adp-xor-pddt-tests.o

# --- ADP-ARX ---

ADP_ARX_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-arx.o $(OBJ_PATH)max-adp-arx.o $(OBJ_PATH)adp-arx-tests.o

adp-arx-tests: common.o adp-arx.o max-adp-arx.o adp-arx-tests.o
	$(CC) $(LFLAGS) $(ADP_ARX_TESTS_OBJ) -o $(BIN_PATH)adp-arx-tests $(GSL_LIB)

adp-arx.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-arx.cc -o $(OBJ_PATH)adp-arx.o

max-adp-arx.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)max-adp-arx.cc -o $(OBJ_PATH)max-adp-arx.o

adp-arx-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-arx-tests.cc -o $(OBJ_PATH)adp-arx-tests.o

# --- ADP-XOR ---

ADP_XOR_OBJ = $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-program.o
ADP_XOR_TESTS_OBJ = $(OBJ_PATH)common.o $(OBJ_PATH)adp-xor.o $(OBJ_PATH)adp-xor-tests.o

adp-xor: adp-xor.o adp-xor-program.o
	$(CC) $(LFLAGS) $(ADP_XOR_OBJ) -o $(BIN_PATH)adp-xor $(GSL_LIB)

adp-xor-tests: common.o adp-xor.o adp-xor-tests.o
	$(CC) $(LFLAGS) $(ADP_XOR_TESTS_OBJ) -o $(BIN_PATH)adp-xor-tests $(GSL_LIB)

adp-xor.o:
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor.cc -o $(OBJ_PATH)adp-xor.o

adp-xor-program.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)adp-xor-program.cc -o $(OBJ_PATH)adp-xor-program.o

adp-xor-tests.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(TESTS_PATH)adp-xor-tests.cc -o $(OBJ_PATH)adp-xor-tests.o

# --- COMMON ---

common.o: 
	$(CC) $(CFLAGS) -I$(INCLUDES) $(SOURCE_PATH)common.cc -o $(OBJ_PATH)common.o

clean:
	rm -v $(BIN_PATH)*; rm -v $(OBJ_PATH)*.o