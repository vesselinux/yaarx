/*
 *    Copyright (c) 2012-2013 Luxembourg University,
 *    Laboratory of Algorithmics, Cryptology and Security (LACS).
 *
 *    This file is part of the YAARX toolkit. YAARX stands for
 *    Yet Another ARX toolkit for analysis of ARX cryptographic algorithms.
 *
 *    YAARX is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    YAARX is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with YAARX.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * \file  speck-trails.h
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2014
 * \brief Differential trails for block cipher Speck found using the thershold search algorithm. 
 * \sa speck-xor-threshold-search-tests.cc 
 */ 
#ifndef SPECK_TRAILS_H
#define SPECK_TRAILS_H



// {---------------  RESULTS FROM speck-best-diff-search-tests.cc : 20150929 -------------

/*

Results from fill search (function speck_best_trail_search_full)

#--- [./tests/speck-xor-best-search-tests.cc:497] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:130] ndiffs 2^16
[./tests/speck-xor-best-search-tests.cc:131] rconst_1 3 rconst_2 2
[./tests/speck-xor-best-search-tests.cc:209] Best trail for 2 rounds (word size 4 bits) p 2^-1.00
8 0 -> 8 1.00
1 8 -> 9 0.50

real    0m0.010s
user    0m0.010s
sys     0m0.000s

#--- [./tests/speck-xor-best-search-tests.cc:509] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:142] ndiffs 2^20
[./tests/speck-xor-best-search-tests.cc:143] rconst_1 3 rconst_2 2
[./tests/speck-xor-best-search-tests.cc:221] Best trail for 3 rounds (word size 4 bits) p 2^-3.00
8 0 -> 8 1.00
1 8 -> 9 0.50
3 B -> E 0.25

real    0m0.099s
user    0m0.099s
sys     0m0.000s


#--- [./tests/speck-xor-best-search-tests.cc:208] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:64] ndiffs 2^24
[./tests/speck-xor-best-search-tests.cc:142] Best trail for 4 rounds (word size 4 bits) p 2^-4.00
8 0 -> 8 1.00
1 8 -> 9 0.50
3 B -> 6 0.25
C 8 -> C 0.50

real    0m1.896s
user    0m1.896s
sys     0m0.000s

#--- [./tests/speck-xor-best-search-tests.cc:208] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:64] ndiffs 2^28
[./tests/speck-xor-best-search-tests.cc:142] Best trail for 5 rounds (word size 4 bits) p 2^-6.00
F F -> E 0.50
D 1 -> 4 0.25
8 0 -> 8 1.00
1 8 -> 9 0.50
3 B -> E 0.25

real    0m39.516s
user    0m39.525s
sys     0m0.000s


#--- [./tests/speck-xor-best-search-tests.cc:239] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:94] ndiffs 2^32
[./tests/speck-xor-best-search-tests.cc:95] rconst_1 3 rconst_2 2
[./tests/speck-xor-best-search-tests.cc:173] Best trail for 6 rounds (word size 4 bits) p 2^-7.00
F F -> E 0.50
D 1 -> 4 0.25
8 0 -> 8 1.00
1 8 -> 9 0.50
3 B -> 6 0.25
C 8 -> C 0.50

real    12m17.662s
user    12m17.851s
sys     0m0.008s

#--- [./tests/speck-xor-best-search-tests.cc:255] Tests, WORD_SIZE  = 4, MASK =        F
[./tests/speck-xor-best-search-tests.cc:110] ndiffs 2^36
[./tests/speck-xor-best-search-tests.cc:111] rconst_1 3 rconst_2 2


[./tests/speck-xor-best-search-tests.cc:189] Best trail for 7 rounds (word size 4 bits) p 2^-9.00
8 8 -> 0 1.00
0 2 -> 2 0.50
4 A -> 6 0.25
C C -> 8 0.50
1 B -> A 0.25
5 4 -> F 0.25
F E -> F 0.50

real    234m11.566s
user    234m14.864s
sys     0m0.108s

[./tests/speck-xor-best-search-tests.cc:584] Best trail on 7 rounds (WORD_SIZE 16 bits):
[./tests/speck-xor-best-search-tests.cc:294] speck_print_trail()
 0:     C014     4205 ->      211 0.03 -5.00
 1:     2204      A04 ->     2800 0.06 -4.00
 2:       50       10 ->       40 0.25 -2.00
 3:     8000        0 ->     8000 1.00 0.00
 4:      100     8000 ->     8100 0.50 -1.00
 5:      102     8102 ->     8000 0.25 -2.00
 6:      100     840A ->     850A 0.06 -4.00
p_trail 0.000004 -18.00

real    383m54.665s
user    384m1.068s
sys     0m0.164s


[./tests/speck-xor-best-search-tests.cc:561] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:326] speck_print_trail()
 0:     8202     1202 ->     9000 0.06 -4.00
 1:       90       10 ->       80 0.25 -2.00
 2: 80000000        0 -> 80000000 1.00 0.00
 3:   800000 80000000 -> 80800000 0.50 -1.00
 4:   808000 80800004 -> 80008004 0.12 -3.00
 5:  4800080 84008020 -> 808080A0 0.03 -5.00
p_trail 0.000031 -15.00

[./tests/speck-xor-best-search-tests.cc:561] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:326] speck_print_trail()
 0:   401042   400240 ->     1202 0.03 -5.00
 1:  2000012  2000002 ->       10 0.12 -3.00
 2: 10000000 10000000 ->        0 0.50 -1.00
 3:        0 80000000 -> 80000000 1.00 0.00
 4:   800000 80000004 -> 80800004 0.25 -2.00
 5:  4808000 80800020 -> 84008020 0.06 -4.00
p_trail 0.000031 -15.00
[./tests/speck-xor-best-search-tests.cc:617] Best trail on 6 rounds (WORD_SIZE 32 bits):
[./tests/speck-xor-best-search-tests.cc:326] speck_print_trail()
 0:   401042   400240 ->     1202 0.03 -5.00
 1:  2000012  2000002 ->       10 0.12 -3.00
 2: 10000000 10000000 ->        0 0.50 -1.00
 3:        0 80000000 -> 80000000 1.00 0.00
 4:   800000 80000004 -> 80800004 0.25 -2.00
 5:  4808000 80800020 -> 84008020 0.06 -4.00
p_trail 0.000031 -15.00

real    1721m5.471s
user    1721m13.438s
sys     0m12.275s

vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w32-r6.bin
#--- [./tests/speck-xor-best-search-tests.cc:613] Tests, WORD_SIZE  32 NROUNDS 6 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:528] Update bound: -16.00 -> -16.00
[./tests/speck-xor-best-search-tests.cc:294] speck_print_trail()
 0: 82020000 12020000 -> 90000000 0.12 -3.00
 1:   900000   100000 ->   800000 0.25 -2.00
 2:     8000        0 ->     8000 0.50 -1.00
 3:       80     8000 ->     8080 0.25 -2.00
 4: 80000080    48080 -> 80048000 0.12 -3.00
 5:   800480 80208400 -> 80A08080 0.03 -5.00
p_trail 0.000015 -16.00

still running ...


[./tests/speck-xor-best-search-tests.cc:741] Best trail on 8 rounds (WORD_SIZE 16 bits):
[./tests/speck-xor-best-search-tests.cc:440] speck_print_trail()
 0:     C014     4205 ->      211 0.03 -5.00
 1:     2204      A04 ->     2800 0.06 -4.00
 2:       50       10 ->       40 0.25 -2.00
 3:     8000        0 ->     8000 1.00 0.00
 4:      100     8000 ->     8100 0.50 -1.00
 5:      102     8102 ->     8000 0.25 -2.00
 6:      100     840A ->     850A 0.06 -4.00
 7:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -24.00

real    276m49.878s
user    276m52.238s
sys     0m1.380s

*/

/*

vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w16-r9.bin
#--- [./tests/speck-xor-best-search-tests.cc:925] Tests, WORD_SIZE  16 NROUNDS 9 r1 7 r2 2
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     A900     A900 ->        0 0.12 -3.00
 1:        0     A402 ->     A402 0.12 -3.00
 2:      548     3408 ->     50C0 0.00 -8.00
 3:     80A1     80E0 ->      181 0.06 -4.00
 4:      203      203 ->        C 0.03 -5.00
 5:     1800      800 ->     2000 0.12 -3.00
 6:       40        0 ->       40 0.50 -1.00
 7:     8000       40 ->     8040 0.50 -1.00
 8:     8100     8140 ->       40 0.25 -2.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     90E8     B0F8 ->      1E0 0.03 -5.00
 1:     C003     C202 ->      20F 0.03 -5.00
 2:     1E04      A04 ->     2800 0.03 -5.00
 3:       50       10 ->       40 0.25 -2.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     B0E8     B0F8 ->      1E0 0.03 -5.00
 1:     C003     C202 ->      20F 0.03 -5.00
 2:     1E04      A04 ->     2800 0.03 -5.00
 3:       50       10 ->       40 0.25 -2.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     90F8     B0F8 ->      1E0 0.03 -5.00
 1:     C003     C202 ->      20F 0.03 -5.00
 2:     1E04      A04 ->     2800 0.03 -5.00
 3:       50       10 ->       40 0.25 -2.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     B0F8     B0F8 ->      1E0 0.03 -5.00
 1:     C003     C202 ->      20F 0.03 -5.00
 2:     1E04      A04 ->     2800 0.03 -5.00
 3:       50       10 ->       40 0.25 -2.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     14A8      120 ->     1488 0.02 -6.00
 1:     1029     1008 ->       21 0.06 -4.00
 2:     4200     4001 ->      601 0.06 -4.00
 3:      20C      604 ->     1800 0.02 -6.00
 4:       30       10 ->       40 0.12 -3.00
 5:     8000        0 ->     8000 1.00 0.00
 6:      100     8000 ->     8100 0.50 -1.00
 7:      102     8102 ->     8000 0.25 -2.00
 8:      100     840A ->     850A 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     15A8      120 ->     1488 0.02 -6.00
 1:     1029     1008 ->       21 0.06 -4.00
 2:     4200     4001 ->      601 0.06 -4.00
 3:      20C      604 ->     1800 0.02 -6.00
 4:       30       10 ->       40 0.12 -3.00
 5:     8000        0 ->     8000 1.00 0.00
 6:      100     8000 ->     8100 0.50 -1.00
 7:      102     8102 ->     8000 0.25 -2.00
 8:      100     840A ->     850A 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:      140      508 ->      448 0.06 -4.00
 1:     9008     1068 ->     80A0 0.03 -5.00
 2:     4101     C100 ->      207 0.02 -6.00
 3:      E04      604 ->     1800 0.03 -5.00
 4:       30       10 ->       40 0.12 -3.00
 5:     8000        0 ->     8000 1.00 0.00
 6:      100     8000 ->     8100 0.50 -1.00
 7:      102     8102 ->     8000 0.25 -2.00
 8:      100     840A ->     850A 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     2204      A04 ->     2800 0.06 -4.00
 1:       50       10 ->       40 0.25 -2.00
 2:     8000        0 ->     8000 1.00 0.00
 3:      100     8000 ->     8100 0.50 -1.00
 4:      102     8102 ->     8004 0.12 -3.00
 5:      900     840E ->     8532 0.00 -8.00
 6:     650A     9508 ->     5002 0.01 -7.00
 7:      4A0      420 ->       80 0.12 -3.00
 8:        1     1000 ->     1001 0.25 -2.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     814A       12 ->     8148 0.03 -5.00
 1:     9102     8100 ->     1002 0.12 -3.00
 2:      420     1400 ->     1060 0.06 -4.00
 3:     C020     4060 ->      180 0.03 -5.00
 4:        3        1 ->        4 0.12 -3.00
 5:      800        0 ->      800 0.50 -1.00
 6:       10      800 ->      810 0.25 -2.00
 7:     2010     2810 ->      800 0.12 -3.00
 8:       10     A840 ->     A850 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     815A       12 ->     8148 0.03 -5.00
 1:     9102     8100 ->     1002 0.12 -3.00
 2:      420     1400 ->     1060 0.06 -4.00
 3:     C020     4060 ->      180 0.03 -5.00
 4:        3        1 ->        4 0.12 -3.00
 5:      800        0 ->      800 0.50 -1.00
 6:       10      800 ->      810 0.25 -2.00
 7:     2010     2810 ->      800 0.12 -3.00
 8:       10     A840 ->     A850 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     540A     9000 ->     440A 0.03 -5.00
 1:     1488      408 ->     1080 0.06 -4.00
 2:       21       A0 ->       83 0.06 -4.00
 3:      601      203 ->        C 0.02 -6.00
 4:     1800      800 ->     2000 0.12 -3.00
 5:       40        0 ->       40 0.50 -1.00
 6:     8000       40 ->     8040 0.50 -1.00
 7:     8100     8140 ->       40 0.25 -2.00
 8:     8000      542 ->     8542 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     D40A     9000 ->     440A 0.03 -5.00
 1:     1488      408 ->     1080 0.06 -4.00
 2:       21       A0 ->       83 0.06 -4.00
 3:      601      203 ->        C 0.02 -6.00
 4:     1800      800 ->     2000 0.12 -3.00
 5:       40        0 ->       40 0.50 -1.00
 6:     8000       40 ->     8040 0.50 -1.00
 7:     8100     8140 ->       40 0.25 -2.00
 8:     8000      542 ->     8542 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     A000     8402 ->     2402 0.12 -3.00
 1:      448     3408 ->     50C0 0.01 -7.00
 2:     80A1     80E0 ->      181 0.06 -4.00
 3:      203      203 ->        C 0.03 -5.00
 4:     1800      800 ->     2000 0.12 -3.00
 5:       40        0 ->       40 0.50 -1.00
 6:     8000       40 ->     8040 0.50 -1.00
 7:     8100     8140 ->       40 0.25 -2.00
 8:     8000      542 ->     8542 0.06 -4.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:710] Update bound: -30.00 -> -30.00
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     1029     1008 ->       21 0.06 -4.00
 1:     4200     4001 ->      601 0.06 -4.00
 2:      20C      604 ->     1800 0.02 -6.00
 3:       30       10 ->       40 0.12 -3.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
[./tests/speck-xor-best-search-tests.cc:766] Best trail on 9 rounds (WORD_SIZE 16 bits):
[./tests/speck-xor-best-search-tests.cc:458] speck_print_trail()
 0:     1029     1008 ->       21 0.06 -4.00
 1:     4200     4001 ->      601 0.06 -4.00
 2:      20C      604 ->     1800 0.02 -6.00
 3:       30       10 ->       40 0.12 -3.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00

real    1206m6.976s
user    1206m30.159s
sys     0m0.312s

[./tests/speck-xor-best-search-tests.cc:967] Best trail on 7 rounds (WORD_SIZE 24 bits):
[./tests/speck-xor-best-search-tests.cc:657] speck_print_trail()
 0:   D24000   504200 ->   820200 0.03 -5.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3:   800000        0 ->   800000 1.00 0.00
 4:     8000   800000 ->   808000 0.50 -1.00
 5:     8080   808004 ->   800084 0.12 -3.00
 6:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000002 -19.00

real    618m13.254s
user    618m22.140s
sys     0m0.212s

*/

/*

[./tests/speck-xor-best-search-tests.cc:986] Best trail on 5 rounds (WORD_SIZE 48 bits):
[./tests/speck-xor-best-search-tests.cc:673] speck_print_trail()
 0:      20000000012      20000000002 ->               10 0.12 -3.00
 1:     100000000000     100000000000 ->                0 0.50 -1.00
 2:                0     800000000000 ->     800000000000 1.00 0.00
 3:       8000000000     800000000004 ->     808000000004 0.25 -2.00
 4:      48080000000     808000000020 ->     840080000020 0.06 -4.00
p_trail 0.000977 -10.00

real    7m16.842s
user    7m16.938s
sys     0m0.008s

 */



/*
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w24-r8.bin
#--- [./tests/speck-xor-best-search-tests.cc:1184] Tests, WORD_SIZE  24 NROUNDS 8 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   524000   504200 ->   820200 0.03 -5.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3:   800000        0 ->   800000 1.00 0.00
 4:     8000   800000 ->   808000 0.50 -1.00
 5:     8080   808004 ->   800084 0.12 -3.00
 6:   848000   8400A0 ->     80A0 0.06 -4.00
 7:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   524000   504200 ->   820200 0.03 -5.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3:   800000        0 ->   800000 1.00 0.00
 4:     8000   800000 ->   808000 0.50 -1.00
 5:     8080   808004 ->   800084 0.12 -3.00
 6:   848000   8400A0 ->     80A0 0.06 -4.00
 7:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   D24000   504200 ->   820200 0.03 -5.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3:   800000        0 ->   800000 1.00 0.00
 4:     8000   800000 ->   808000 0.50 -1.00
 5:     8080   808004 ->   800084 0.12 -3.00
 6:   848000   8400A0 ->     80A0 0.06 -4.00
 7:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   D24000   504200 ->   820200 0.03 -5.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3:   800000        0 ->   800000 1.00 0.00
 4:     8000   800000 ->   808000 0.50 -1.00
 5:     8080   808004 ->   800084 0.12 -3.00
 6:   848000   8400A0 ->     80A0 0.06 -4.00
 7:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:    20808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   820808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:    20818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:969] Update bound: -26.00 -> -26.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   820818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -26.00
[./tests/speck-xor-best-search-tests.cc:1025] Best trail on 8 rounds (WORD_SIZE 24 bits):
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   820818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -26.00

real    426m47.487s
user    426m52.919s
sys     0m0.260s

*/

/*

vpv@mazirat:~/exper$ date
Mon Sep 28 15:59:46 CEST 2015
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w32-r7.bin
#--- [./tests/speck-xor-best-search-tests.cc:1168] Tests, WORD_SIZE  32 NROUNDS 7 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:953] Update bound: -21.00 -> -21.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0: 40924000 40104200 ->   820200 0.02 -6.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3: 80000000        0 -> 80000000 1.00 0.00
 4:   800000 80000000 -> 80800000 0.50 -1.00
 5:   808000 80800004 -> 80008004 0.12 -3.00
 6:  4800080 84008020 -> 808080A0 0.03 -5.00
p_trail 0.000000 -21.00
[./tests/speck-xor-best-search-tests.cc:953] Update bound: -21.00 -> -21.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0: C0924000 40104200 ->   820200 0.02 -6.00
 1:     8202     1202 ->     9000 0.06 -4.00
 2:       90       10 ->       80 0.25 -2.00
 3: 80000000        0 -> 80000000 1.00 0.00
 4:   800000 80000000 -> 80800000 0.50 -1.00
 5:   808000 80800004 -> 80008004 0.12 -3.00
 6:  4800080 84008020 -> 808080A0 0.03 -5.00
p_trail 0.000000 -21.00
[./tests/speck-xor-best-search-tests.cc:953] Update bound: -21.00 -> -21.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0: 92400040 10420040 -> 82020000 0.03 -5.00
 1:   820200   120200 ->   900000 0.06 -4.00
 2:     9000     1000 ->     8000 0.25 -2.00
 3:       80        0 ->       80 0.50 -1.00
 4: 80000000       80 -> 80000080 0.50 -1.00
 5: 80800000 80000480 ->   800480 0.12 -3.00
 6: 80008004   802084 -> 8080A080 0.03 -5.00
p_trail 0.000000 -21.00
[./tests/speck-xor-best-search-tests.cc:1009] Best trail on 7 rounds (WORD_SIZE 32 bits):
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0: 92400040 10420040 -> 82020000 0.03 -5.00
 1:   820200   120200 ->   900000 0.06 -4.00
 2:     9000     1000 ->     8000 0.25 -2.00
 3:       80        0 ->       80 0.50 -1.00
 4: 80000000       80 -> 80000080 0.50 -1.00
 5: 80800000 80000480 ->   800480 0.12 -3.00
 6: 80008004   802084 -> 8080A080 0.03 -5.00
p_trail 0.000000 -21.00

real    278m46.963s
user    278m51.893s
sys     0m0.320s


*/


/*
vpv@mazirat:~/skcrypto/trunk/work/src/va$ time ./speck-best-diff-search-yann
-- Searching for 7 rounds (WORD_SIZE 32 bits):
# Update bound: -21 -> -21
#  0: 0x40924000 0x40104200 -> 0x00820200 -6
#  1: 0x00008202 0x00001202 -> 0x00009000 -4
#  2: 0x00000090 0x00000010 -> 0x00000080 -2
#  3: 0x80000000 0x00000000 -> 0x80000000 0
#  4: 0x00800000 0x80000000 -> 0x80800000 -1
#  5: 0x00808000 0x80800004 -> 0x80008004 -3
#  6: 0x04800080 0x84008020 -> 0x808080A0 -5
# p_trail -21
# Update bound: -21 -> -21
#  0: 0xC0924000 0x40104200 -> 0x00820200 -6
#  1: 0x00008202 0x00001202 -> 0x00009000 -4
#  2: 0x00000090 0x00000010 -> 0x00000080 -2
#  3: 0x80000000 0x00000000 -> 0x80000000 0
#  4: 0x00800000 0x80000000 -> 0x80800000 -1
#  5: 0x00808000 0x80800004 -> 0x80008004 -3
#  6: 0x04800080 0x84008020 -> 0x808080A0 -5
# p_trail -21
# Update bound: -21 -> -21
#  0: 0x92400040 0x10420040 -> 0x82020000 -5
#  1: 0x00820200 0x00120200 -> 0x00900000 -4
#  2: 0x00009000 0x00001000 -> 0x00008000 -2
#  3: 0x00000080 0x00000000 -> 0x00000080 -1
#  4: 0x80000000 0x00000080 -> 0x80000080 -1
#  5: 0x80800000 0x80000480 -> 0x00800480 -3
#  6: 0x80008004 0x00802084 -> 0x8080A080 -5
# p_trail -21
--------------------------------------------------------------------------------
Best trail on 7 rounds (WORD_SIZE 32 bits):
#  0: 0x92400040 0x10420040 -> 0x82020000 -5
#  1: 0x00820200 0x00120200 -> 0x00900000 -4
#  2: 0x00009000 0x00001000 -> 0x00008000 -2
#  3: 0x00000080 0x00000000 -> 0x00000080 -1
#  4: 0x80000000 0x00000080 -> 0x80000080 -1
#  5: 0x80800000 0x80000480 -> 0x00800480 -3
#  6: 0x80008004 0x00802084 -> 0x8080A080 -5
# p_trail -21

real    2568m58.366s
user    2569m58.217s
sys     0m0.008s

*/

/*
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w48-r6.bin
#--- [./tests/speck-xor-best-search-tests.cc:1168] Tests, WORD_SIZE  48 NROUNDS 6 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:953] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:             8202             1202 ->             9000 0.06 -4.00
 1:               90               10 ->               80 0.25 -2.00
 2:     800000000000                0 ->     800000000000 1.00 0.00
 3:       8000000000     800000000000 ->     808000000000 0.50 -1.00
 4:       8080000000     808000000004 ->     800080000004 0.12 -3.00
 5:      48000800000     840080000020 ->     808080800020 0.03 -5.00
p_trail 0.000031 -15.00
[./tests/speck-xor-best-search-tests.cc:953] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:       4000001042       4000000240 ->             1202 0.03 -5.00
 1:      20000000012      20000000002 ->               10 0.12 -3.00
 2:     100000000000     100000000000 ->                0 0.50 -1.00
 3:                0     800000000000 ->     800000000000 1.00 0.00
 4:       8000000000     800000000004 ->     808000000004 0.25 -2.00
 5:      48080000000     808000000020 ->     840080000020 0.06 -4.00
p_trail 0.000031 -15.00
[./tests/speck-xor-best-search-tests.cc:1009] Best trail on 6 rounds (WORD_SIZE 48 bits):
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:       4000001042       4000000240 ->             1202 0.03 -5.00
 1:      20000000012      20000000002 ->               10 0.12 -3.00
 2:     100000000000     100000000000 ->                0 0.50 -1.00
 3:                0     800000000000 ->     800000000000 1.00 0.00
 4:       8000000000     800000000004 ->     808000000004 0.25 -2.00
 5:      48080000000     808000000020 ->     840080000020 0.06 -4.00
p_trail 0.000031 -15.00

real    115m53.522s
user    115m53.546s
sys     0m1.480s

*/

/*

vpv@mazirat:~/exper$ date
Mon Sep 28 16:22:39 CEST 2015
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w64-r6.bin
#--- [./tests/speck-xor-best-search-tests.cc:1183] Tests, WORD_SIZE  64 NROUNDS 6 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:968] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:             8202             1202 ->             9000 0.06 -4.00
 1:               90               10 ->               80 0.25 -2.00
 2: 8000000000000000                0 -> 8000000000000000 1.00 0.00
 3:   80000000000000 8000000000000000 -> 8080000000000000 0.50 -1.00
 4:   80800000000000 8080000000000004 -> 8000800000000004 0.12 -3.00
 5:  480008000000000 8400800000000020 -> 8080808000000020 0.03 -5.00
p_trail 0.000031 -15.00
[./tests/speck-xor-best-search-tests.cc:968] Update bound: -15.00 -> -15.00
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   40000000001042   40000000000240 ->             1202 0.03 -5.00
 1:  200000000000012  200000000000002 ->               10 0.12 -3.00
 2: 1000000000000000 1000000000000000 ->                0 0.50 -1.00
 3:                0 8000000000000000 -> 8000000000000000 1.00 0.00
 4:   80000000000000 8000000000000004 -> 8080000000000004 0.25 -2.00
 5:  480800000000000 8080000000000020 -> 8400800000000020 0.06 -4.00
p_trail 0.000031 -15.00
[./tests/speck-xor-best-search-tests.cc:1024] Best trail on 6 rounds (WORD_SIZE 64 bits):
[./tests/speck-xor-best-search-tests.cc:686] speck_print_trail()
 0:   40000000001042   40000000000240 ->             1202 0.03 -5.00
 1:  200000000000012  200000000000002 ->               10 0.12 -3.00
 2: 1000000000000000 1000000000000000 ->                0 0.50 -1.00
 3:                0 8000000000000000 -> 8000000000000000 1.00 0.00
 4:   80000000000000 8000000000000004 -> 8080000000000004 0.25 -2.00
 5:  480800000000000 8080000000000020 -> 8400800000000020 0.06 -4.00
p_trail 0.000031 -15.00

real    506m39.601s
user    506m47.258s
sys     0m2.177s

*/

/*

vpv@mazirat:~/exper$ date
Mit Sep 30 09:50:46 CEST 2015
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w24-r9.bin
#--- [./tests/speck-xor-best-search-tests.cc:787] Tests, WORD_SIZE  24 NROUNDS 9 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    20808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    20808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:   820808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:   820808   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    20818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    20818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:   820818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808424 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:   820818   42084A ->   400052 0.01 -7.00
 1:   524000   504200 ->   820200 0.03 -5.00
 2:     8202     1202 ->     9000 0.06 -4.00
 3:       90       10 ->       80 0.25 -2.00
 4:   800000        0 ->   800000 1.00 0.00
 5:     8000   800000 ->   808000 0.50 -1.00
 6:     8080   808004 ->   800084 0.12 -3.00
 7:   848000   8400A0 ->     80A0 0.06 -4.00
 8:   A00080   2085A4 ->   808524 0.01 -7.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    14809    94009 ->    80802 0.01 -7.00
 1:    20808   42084A ->   400052 0.01 -7.00
 2:   524000   504200 ->   820200 0.03 -5.00
 3:     8202     1202 ->     9000 0.06 -4.00
 4:       90       10 ->       80 0.25 -2.00
 5:   800000        0 ->   800000 1.00 0.00
 6:     8000   800000 ->   808000 0.50 -1.00
 7:     8080   808004 ->   800084 0.12 -3.00
 8:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:572] Update bound: -33.00 -> -33.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    1480B    94009 ->    80802 0.01 -7.00
 1:    20808   42084A ->   400052 0.01 -7.00
 2:   524000   504200 ->   820200 0.03 -5.00
 3:     8202     1202 ->     9000 0.06 -4.00
 4:       90       10 ->       80 0.25 -2.00
 5:   800000        0 ->   800000 1.00 0.00
 6:     8000   800000 ->   808000 0.50 -1.00
 7:     8080   808004 ->   800084 0.12 -3.00
 8:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -33.00
[./tests/speck-xor-best-search-tests.cc:628] Best trail on 9 rounds (WORD_SIZE 24 bits):
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:    1480B    94009 ->    80802 0.01 -7.00
 1:    20808   42084A ->   400052 0.01 -7.00
 2:   524000   504200 ->   820200 0.03 -5.00
 3:     8202     1202 ->     9000 0.06 -4.00
 4:       90       10 ->       80 0.25 -2.00
 5:   800000        0 ->   800000 1.00 0.00
 6:     8000   800000 ->   808000 0.50 -1.00
 7:     8080   808004 ->   800084 0.12 -3.00
 8:   848000   8400A0 ->     80A0 0.06 -4.00
p_trail 0.000000 -33.00

real    2641m31.912s
user    2641m59.901s
sys     0m4.105s


*/


/*

vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w48-r7.bin
#--- [./tests/speck-xor-best-search-tests.cc:785] Tests, WORD_SIZE  48 NROUNDS 7 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:570] Update bound: -21.00 -> -21.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:     400000924000     400000104200 ->           820200 0.02 -6.00
 1:             8202             1202 ->             9000 0.06 -4.00
 2:               90               10 ->               80 0.25 -2.00
 3:     800000000000                0 ->     800000000000 1.00 0.00
 4:       8000000000     800000000000 ->     808000000000 0.50 -1.00
 5:       8080000000     808000000004 ->     800080000004 0.12 -3.00
 6:      48000800000     840080000020 ->     808080800020 0.03 -5.00
p_trail 0.000000 -21.00
[./tests/speck-xor-best-search-tests.cc:570] Update bound: -21.00 -> -21.00
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:     C00000924000     400000104200 ->           820200 0.02 -6.00
 1:             8202             1202 ->             9000 0.06 -4.00
 2:               90               10 ->               80 0.25 -2.00
 3:     800000000000                0 ->     800000000000 1.00 0.00
 4:       8000000000     800000000000 ->     808000000000 0.50 -1.00
 5:       8080000000     808000000004 ->     800080000004 0.12 -3.00
 6:      48000800000     840080000020 ->     808080800020 0.03 -5.00
p_trail 0.000000 -21.00

[./tests/speck-xor-best-search-tests.cc:626] Best trail on 7 rounds (WORD_SIZE 48 bits):
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:     C00000924000     400000104200 ->           820200 0.02 -6.00
 1:             8202             1202 ->             9000 0.06 -4.00
 2:               90               10 ->               80 0.25 -2.00
 3:     800000000000                0 ->     800000000000 1.00 0.00
 4:       8000000000     800000000000 ->     808000000000 0.50 -1.00
 5:       8080000000     808000000004 ->     800080000004 0.12 -3.00
 6:      48000800000     840080000020 ->     808080800020 0.03 -5.00
p_trail 0.000000 -21.00

real    4804m48.948s
user    4805m56.007s
sys     0m7.834s
vpv@mazirat:~/exper$

*/

/*
Mit Sep 30 09:53:44 CEST 2015
vpv@mazirat:~/exper$ time ./speck-xor-best-search-tests-w32-r8.bin
#--- [./tests/speck-xor-best-search-tests.cc:788] Tests, WORD_SIZE  32 NROUNDS 8 r1 8 r2 3
[./tests/speck-xor-best-search-tests.cc:629] Best trail on 8 rounds (WORD_SIZE 32 bits):
[./tests/speck-xor-best-search-tests.cc:287] speck_print_trail()
 0:        0        0 ->        0 0.00 -inf
speck-xor-best-search-tests-w32-r8.bin: ./tests/speck-xor-best-search-tests.cc:297: void speck_print_trail(differential_3d_t*): Assertion `p_tmp == T[i].p' failed.
Aborted (core dumped)

real    9125m27.374s
user    9127m26.841s
sys     0m23.766s
vpv@mazirat:~/exper$

*/

/*
[./tests/speck-best-diff-search-tests.cc:616] Best trail on 9 rounds (WORD_SIZE 16 bits):
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
 0:     1029     1008 ->       21 0.06 -4.00
 1:     4200     4001 ->      601 0.06 -4.00
 2:      20C      604 ->     1800 0.02 -6.00
 3:       30       10 ->       40 0.12 -3.00
 4:     8000        0 ->     8000 1.00 0.00
 5:      100     8000 ->     8100 0.50 -1.00
 6:      102     8102 ->     8000 0.25 -2.00
 7:      100     840A ->     850A 0.06 -4.00
 8:     150A     9520 ->     802A 0.02 -6.00
p_trail 0.000000 -30.00
differential_3d_t g_T[NROUNDS] = {
{    1029,     1008,       21, (1.0 / (double)(1ULL <<  4))},
{    4200,     4001,      601, (1.0 / (double)(1ULL <<  4))},
{     20C,      604,     1800, (1.0 / (double)(1ULL <<  6))},
{      30,       10,       40, (1.0 / (double)(1ULL <<  3))},
{    8000,        0,     8000, (1.0 / (double)(1ULL <<  0))},
{     100,     8000,     8100, (1.0 / (double)(1ULL <<  1))},
{     102,     8102,     8000, (1.0 / (double)(1ULL <<  2))},
{     100,     840A,     850A, (1.0 / (double)(1ULL <<  4))},
{    150A,     9520,     802A, (1.0 / (double)(1ULL <<  6))},
};
real    284m2.608s
user    284m7.306s
sys     0m0.312s
vpv@mazirat:~/exper/speck-bins$

*/

/*
[./tests/speck-best-diff-search-tests.cc:616] Best trail on 6 rounds (WORD_SIZE 32 bits):
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
 0:   401042   400240 ->     1202 0.03 -5.00
 1:  2000012  2000002 ->       10 0.12 -3.00
 2: 10000000 10000000 ->        0 0.50 -1.00
 3:        0 80000000 -> 80000000 1.00 0.00
 4:   800000 80000004 -> 80800004 0.25 -2.00
 5:  4808000 80800020 -> 84008020 0.06 -4.00
p_trail 0.000031 -15.00
differential_3d_t g_T[NROUNDS] = {
{  401042,   400240,     1202, (1.0 / (double)(1ULL <<  5))},
{ 2000012,  2000002,       10, (1.0 / (double)(1ULL <<  3))},
{10000000, 10000000,        0, (1.0 / (double)(1ULL <<  1))},
{       0, 80000000, 80000000, (1.0 / (double)(1ULL <<  0))},
{  800000, 80000004, 80800004, (1.0 / (double)(1ULL <<  2))},
{ 4808000, 80800020, 84008020, (1.0 / (double)(1ULL <<  4))},
};
real    166m29.172s
user    166m31.882s
sys     0m0.596s

*/

/*
[./tests/speck-best-diff-search-tests.cc:621] Best trail on 5 rounds (WORD_SIZE 48 bits):
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
 0:      20000000012      20000000002 ->               10 0.12 -3.00
 1:     100000000000     100000000000 ->                0 0.50 -1.00
 2:                0     800000000000 ->     800000000000 1.00 0.00
 3:       8000000000     800000000004 ->     808000000004 0.25 -2.00
 4:      48080000000     808000000020 ->     840080000020 0.06 -4.00
p_trail 0.000977 -10.00
differential_3d_t g_T[NROUNDS] = {
{     20000000012,      20000000002,               10, (1.0 / (double)(1ULL <<  3))},
{    100000000000,     100000000000,                0, (1.0 / (double)(1ULL <<  1))},
{               0,     800000000000,     800000000000, (1.0 / (double)(1ULL <<  0))},
{      8000000000,     800000000004,     808000000004, (1.0 / (double)(1ULL <<  2))},
{     48080000000,     808000000020,     840080000020, (1.0 / (double)(1ULL <<  4))},
};
real    33m9.655s
user    33m10.355s
sys     0m0.020s

*/


/*
[./tests/speck-best-diff-search-tests.cc:621] Best trail on 5 rounds (WORD_SIZE 64 bits):
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
 0:  200000000000012  200000000000002 ->               10 0.12 -3.00
 1: 1000000000000000 1000000000000000 ->                0 0.50 -1.00
 2:                0 8000000000000000 -> 8000000000000000 1.00 0.00
 3:   80000000000000 8000000000000004 -> 8080000000000004 0.25 -2.00
 4:  480800000000000 8080000000000020 -> 8400800000000020 0.06 -4.00
p_trail 0.000977 -10.00
differential_3d_t g_T[NROUNDS] = {
{ 200000000000012,  200000000000002,               10, (1.0 / (double)(1ULL <<  3))},
{1000000000000000, 1000000000000000,                0, (1.0 / (double)(1ULL <<  1))},
{               0, 8000000000000000, 8000000000000000, (1.0 / (double)(1ULL <<  0))},
{  80000000000000, 8000000000000004, 8080000000000004, (1.0 / (double)(1ULL <<  2))},
{ 480800000000000, 8080000000000020, 8400800000000020, (1.0 / (double)(1ULL <<  4))},
};
real    140m37.539s
user    140m40.701s
sys     0m0.000s

*/

/*

[./tests/speck-best-diff-search-tests.cc:621] Best trail on 6 rounds (WORD_SIZE 48 bits):
[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
[./tests/speck-best-[./tests/speck-best-diff-search-tests.cc:259] speck_print_diff_trail()
 0:       4000001042       4000000240 ->             1202 0.03 -5.00
 1:      20000000012      20000000002 ->               10 0.12 -3.00
 2:     100000000000     100000000000 ->                0 0.50 -1.00
 3:                0     800000000000 ->     800000000000 1.00 0.00
 4:       8000000000     800000000004 ->     808000000004 0.25 -2.00
 5:      48080000000     808000000020 ->     840080000020 0.06 -4.00
p_trail 0.000031 -15.00
differential_3d_t g_T[NROUNDS] = {
{      4000001042,       4000000240,             1202, (1.0 / (double)(1ULL <<  5))},
{     20000000012,      20000000002,               10, (1.0 / (double)(1ULL <<  3))},
{    100000000000,     100000000000,                0, (1.0 / (double)(1ULL <<  1))},
{               0,     800000000000,     800000000000, (1.0 / (double)(1ULL <<  0))},
{      8000000000,     800000000004,     808000000004, (1.0 / (double)(1ULL <<  2))},
{     48080000000,     808000000020,     840080000020, (1.0 / (double)(1ULL <<  4))},
};
real    2882m25.538s
user    2883m25.673s
sys     0m1.268s

*/

/*

vpv@mazirat:~/exper/speck-bins$ time ./speck-best-diff-search-tests-w48-r6.bin
#--- [./tests/speck-best-diff-search-tests.cc:1336] Tests, WORD_SIZE  48 NROUNDS 6 r1 8 r2 3 g_Bn 2^-15.00
# Update bound: -15 -> -15
differential_3d_t g_T[NROUNDS] = {
{            8202,             1202,             9000, (1.0 / (double)(1ULL <<  4))},
{              90,               10,               80, (1.0 / (double)(1ULL <<  2))},
{    800000000000,                0,     800000000000, (1.0 / (double)(1ULL <<  0))},
{      8000000000,     800000000000,     808000000000, (1.0 / (double)(1ULL <<  1))},
{      8080000000,     808000000004,     800080000004, (1.0 / (double)(1ULL <<  3))},
{     48000800000,     840080000020,     808080800020, (1.0 / (double)(1ULL <<  5))},
};
# Update bound: -15 -> -15
differential_3d_t g_T[NROUNDS] = {
{      4000001042,       4000000240,             1202, (1.0 / (double)(1ULL <<  5))},
{     20000000012,      20000000002,               10, (1.0 / (double)(1ULL <<  3))},
{    100000000000,     100000000000,                0, (1.0 / (double)(1ULL <<  1))},
{               0,     800000000000,     800000000000, (1.0 / (double)(1ULL <<  0))},
{      8000000000,     800000000004,     808000000004, (1.0 / (double)(1ULL <<  2))},
{     48080000000,     808000000020,     840080000020, (1.0 / (double)(1ULL <<  4))},
};
[./tests/speck-best-diff-search-tests.cc:1092] Best trail on 6 rounds (WORD_SIZE 48 bits):

%------------------------trail start----------------------------------------
\begin{table}[ht]
\caption{Best differential trail for word size 48 rounds 6}
\begin{center}
\begin{tabular}{c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}}
\toprule
$r$ & $\alpha$ & $\beta$ & $\gamma$ & $\mathrm{log}_2 p$\\
\midrule
$ 0$ & \texttt{      4000001042} & \texttt{      4000000240} & \texttt{            1202} & $-inf$ \\
$ 1$ & \texttt{     20000000012} & \texttt{     20000000002} & \texttt{              10} & $-inf$ \\
$ 2$ & \texttt{    100000000000} & \texttt{    100000000000} & \texttt{               0} & $-inf$ \\
$ 3$ & \texttt{               0} & \texttt{    800000000000} & \texttt{    800000000000} & $-inf$ \\
$ 4$ & \texttt{      8000000000} & \texttt{    800000000004} & \texttt{    808000000004} & $-inf$ \\
$ 5$ & \texttt{     48080000000} & \texttt{    808000000020} & \texttt{    840080000020} & $-inf$ \\
\bottomrule
\end{tabular}
\end{center}
\end{table}
%------------------------trail end----------------------------------------

real    1970m38.225s
user    1971m15.429s
sys     0m1.724s
vpv@mazirat:~/exper/speck-bins$


*/

/*
vpv@mazirat:~/exper/speck-bins$ time ./speck-best-diff-search-tests-w32-r7-yann.bin
-- Searching for 7 rounds (WORD_SIZE 32 bits):
-- g_Bn = -15 ... no trail found! [0 s] {34944 nodes -> nan nodes/s}
-- g_Bn = -16 ... no trail found! [0 s] {1546616 nodes -> nan nodes/s}
-- g_Bn = -17 ... no trail found! [1 s] {28484303 nodes -> 2.84843e+07 nodes/s}
-- g_Bn = -18 ... no trail found! [7 s] {690371969 nodes -> 9.86246e+07 nodes/s}
-- g_Bn = -19 ... no trail found! [218 s] {21222356510 nodes -> 9.73503e+07 nodes/s}
-- g_Bn = -20 ... no trail found! [7036 s] {622653038087 nodes -> 8.84953e+07 nodes/s}
-- g_Bn = -21 ...
#  0: 0x40924000 0x40104200 -> 0x  820200 -6 <-6>
#  1: 0x    8202 0x    1202 -> 0x    9000 -4 <-10>
#  2: 0x      90 0x      10 -> 0x      80 -2 <-12>
#  3: 0x80000000 0x       0 -> 0x80000000 +0 <-12>
#  4: 0x  800000 0x80000000 -> 0x80800000 -1 <-13>
#  5: 0x  808000 0x80800004 -> 0x80008004 -3 <-16>
#  6: 0x 4800080 0x84008020 -> 0x808080A0 -5 <-21>
# p_trail -21

real    535m44.166s
user    535m49.257s
sys     0m0.636s

*/

/*
vpv@mazirat:~/exper/speck-bins$ time ./speck-best-diff-search-tests-w32-r7.bin
#--- [./tests/speck-best-diff-search-tests.cc:1328] Tests, WORD_SIZE  32 NROUNDS 7 r1 8 r2 3 g_Bn 2^-21.00
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{40924000, 40104200,   820200, (1.0 / (double)(1ULL <<  6))},
{    8202,     1202,     9000, (1.0 / (double)(1ULL <<  4))},
{      90,       10,       80, (1.0 / (double)(1ULL <<  2))},
{80000000,        0, 80000000, (1.0 / (double)(1ULL <<  0))},
{  800000, 80000000, 80800000, (1.0 / (double)(1ULL <<  1))},
{  808000, 80800004, 80008004, (1.0 / (double)(1ULL <<  3))},
{ 4800080, 84008020, 808080A0, (1.0 / (double)(1ULL <<  5))},
};
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{C0924000, 40104200,   820200, (1.0 / (double)(1ULL <<  6))},
{    8202,     1202,     9000, (1.0 / (double)(1ULL <<  4))},
{      90,       10,       80, (1.0 / (double)(1ULL <<  2))},
{80000000,        0, 80000000, (1.0 / (double)(1ULL <<  0))},
{  800000, 80000000, 80800000, (1.0 / (double)(1ULL <<  1))},
{  808000, 80800004, 80008004, (1.0 / (double)(1ULL <<  3))},
{ 4800080, 84008020, 808080A0, (1.0 / (double)(1ULL <<  5))},
};
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{92400040, 10420040, 82020000, (1.0 / (double)(1ULL <<  5))},
{  820200,   120200,   900000, (1.0 / (double)(1ULL <<  4))},
{    9000,     1000,     8000, (1.0 / (double)(1ULL <<  2))},
{      80,        0,       80, (1.0 / (double)(1ULL <<  1))},
{80000000,       80, 80000080, (1.0 / (double)(1ULL <<  1))},
{80800000, 80000480,   800480, (1.0 / (double)(1ULL <<  3))},
{80008004,   802084, 8080A080, (1.0 / (double)(1ULL <<  5))},
};

*/


/*
vpv@mazirat:~/exper/speck-bins$ time ./speck-best-diff-search-tests-w32-r7.bin
#--- [./tests/speck-best-diff-search-tests.cc:1328] Tests, WORD_SIZE  32 NROUNDS 7 r1 8 r2 3 g_Bn 2^-21.00
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{40924000, 40104200,   820200, (1.0 / (double)(1ULL <<  6))},
{    8202,     1202,     9000, (1.0 / (double)(1ULL <<  4))},
{      90,       10,       80, (1.0 / (double)(1ULL <<  2))},
{80000000,        0, 80000000, (1.0 / (double)(1ULL <<  0))},
{  800000, 80000000, 80800000, (1.0 / (double)(1ULL <<  1))},
{  808000, 80800004, 80008004, (1.0 / (double)(1ULL <<  3))},
{ 4800080, 84008020, 808080A0, (1.0 / (double)(1ULL <<  5))},
};
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{C0924000, 40104200,   820200, (1.0 / (double)(1ULL <<  6))},
{    8202,     1202,     9000, (1.0 / (double)(1ULL <<  4))},
{      90,       10,       80, (1.0 / (double)(1ULL <<  2))},
{80000000,        0, 80000000, (1.0 / (double)(1ULL <<  0))},
{  800000, 80000000, 80800000, (1.0 / (double)(1ULL <<  1))},
{  808000, 80800004, 80008004, (1.0 / (double)(1ULL <<  3))},
{ 4800080, 84008020, 808080A0, (1.0 / (double)(1ULL <<  5))},
};
# Update bound: -21 -> -21
differential_3d_t g_T[NROUNDS] = {
{92400040, 10420040, 82020000, (1.0 / (double)(1ULL <<  5))},
{  820200,   120200,   900000, (1.0 / (double)(1ULL <<  4))},
{    9000,     1000,     8000, (1.0 / (double)(1ULL <<  2))},
{      80,        0,       80, (1.0 / (double)(1ULL <<  1))},
{80000000,       80, 80000080, (1.0 / (double)(1ULL <<  1))},
{80800000, 80000480,   800480, (1.0 / (double)(1ULL <<  3))},
{80008004,   802084, 8080A080, (1.0 / (double)(1ULL <<  5))},
};

[./tests/speck-best-diff-search-tests.cc:1084] Best trail on 7 rounds (WORD_SIZE 32 bits):

%------------------------trail start----------------------------------------
\begin{table}[ht]
\caption{Best differential trail for word size 32 rounds 7}
\begin{center}
\begin{tabular}{c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}c@{\hspace{0.4cm}}}
\toprule
$r$ & $\alpha$ & $\beta$ & $\gamma$ & $\mathrm{log}_2 p$\\
\midrule
$ 0$ & \texttt{92400040} & \texttt{10420040} & \texttt{82020000} & $-5$ \\
$ 1$ & \texttt{  820200} & \texttt{  120200} & \texttt{  900000} & $-4$ \\
$ 2$ & \texttt{    9000} & \texttt{    1000} & \texttt{    8000} & $-2$ \\
$ 3$ & \texttt{      80} & \texttt{       0} & \texttt{      80} & $-1$ \\
$ 4$ & \texttt{80000000} & \texttt{      80} & \texttt{80000080} & $-1$ \\
$ 5$ & \texttt{80800000} & \texttt{80000480} & \texttt{  800480} & $-3$ \\
$ 6$ & \texttt{80008004} & \texttt{  802084} & \texttt{8080A080} & $-5$ \\
\bottomrule
\end{tabular}
\end{center}
\end{table}
%------------------------trail end----------------------------------------

real    7244m11.529s
user    7246m28.448s
sys     0m4.458s
vpv@mazirat:~/exper/speck-bins$

*/

/*

Time to find all trails for all versions: (20151107)

vpv@mazirat:~/skcrypto/trunk/work/src/va/speck-best-diff-search-opt/build$ time ../scripts/find_all_trails.sh

real    4829m27.294s
user    10774m31.274s
sys     0m17.942s
vpv@mazirat:~/skcrypto/trunk/work/src/va/speck-best-diff-search-opt/build$


*/


// ---------------  RESULTS FROM speck-best-diff-search-tests.cc : 20150929 -------------}

// {---------------  RESULTS FROM speck-best-linear--search-tests.cc : 20151015 -------------

/*
linear-search-tests.cc:615] Best linear trail on 3 rounds (WORD_SIZE 24 bits):
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     2000       34 1.00 2^0.00
 1: M_LR        0       20 0.50 2^-1.00  | m_abc 20 30 -> 20 0.50
 2: M_LR      100      100 1.00 2^0.00  | m_abc 0 0 -> 0 1.00
 3: M_LR      809      808 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
corr_trail 0.500000 -1.00
differential_t g_T[NROUNDS + 1] = {
{    2000,       34, 0, (1.0 / (double)(1ULL <<  0))},
{       0,       20, 0, (1.0 / (double)(1ULL <<  -1))},
{     100,      100, 0, (1.0 / (double)(1ULL <<  0))},
{     809,      808, 0, (1.0 / (double)(1ULL <<  0))},
};
real    8m34.033s
user    8m34.227s
sys     0m0.000s

*/

/*
[./tests/speck-best-linear-search-tests.cc:615] Best linear trail on 5 rounds (WORD_SIZE 16 bits):
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       A0     3021 1.00 2^0.00
 1: M_LR       80     4081 0.50 2^-1.00  | m_abc 4001 6001 -> 4001 0.50
 2: M_LR      200      201 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 3: M_LR      818      81C 0.50 2^-1.00  | m_abc 4 6 -> 4 0.50
 4: M_LR     8000     A010 0.25 2^-2.00  | m_abc 3010 2018 -> 2010 0.25
 5: M_LR     85C2     8442 0.50 2^-1.00  | m_abc 100 100 -> 180 0.50
corr_trail 0.031250 -5.00

real    55m1.290s
user    55m2.337s
sys     0m0.036s

*/

/*
[./tests/speck-best-linear-search-tests.cc:615] Best linear trail on 6 rounds (WORD_SIZE 16 bits):
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     4080     40C9 1.00 2^0.00
 1: M_LR       A0       21 0.50 2^-1.00  | m_abc 81 C1 -> 81 0.50
 2: M_LR       80     4081 0.25 2^-2.00  | m_abc 4001 5001 -> 4001 0.25
 3: M_LR      200      201 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      818      81C 0.50 2^-1.00  | m_abc 4 6 -> 4 0.50
 5: M_LR     8000     A010 0.25 2^-2.00  | m_abc 3010 2018 -> 2010 0.25
 6: M_LR     85C2     8442 0.50 2^-1.00  | m_abc 100 100 -> 180 0.50
corr_trail 0.007812 -7.00
differential_t g_T[NROUNDS + 1] = {
{    4080,     40C9, 0, (1.0 / (double)(1ULL <<  0))},
{      A0,       21, 0, (1.0 / (double)(1ULL <<  -1))},
{      80,     4081, 0, (1.0 / (double)(1ULL <<  -2))},
{     200,      201, 0, (1.0 / (double)(1ULL <<  0))},
{     818,      81C, 0, (1.0 / (double)(1ULL <<  -1))},
{    8000,     A010, 0, (1.0 / (double)(1ULL <<  -2))},
{    85C2,     8442, 0, (1.0 / (double)(1ULL <<  -1))},
};
real    31m24.575s
user    31m25.106s
sys     0m0.024s

*/

/*

vpv@mazirat:~/skcrypto/trunk/work/src/yaarx$ time ./bin/speck-best-linear-search-tests
#--- [./tests/speck-best-linear-search-tests.cc:786] Tests, WORD_SIZE  16 NROUNDS 4 r1 7 r2 2 g_Bn 2^-3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     3080     5071 1.00 2^0.00
 1: M_LR     4080     40C1 0.50 2^-1.00  | m_abc 61 41 -> 41 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc 81 C1 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      E00      C00 0.50 2^-1.00  | m_abc 200 300 -> 200 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     3080     5071 1.00 2^0.00
 1: M_LR     4080     40C1 0.50 2^-1.00  | m_abc 61 41 -> 41 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc 81 C1 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      B00      800 0.50 2^-1.00  | m_abc 200 200 -> 300 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     2080     5051 1.00 2^0.00
 1: M_LR     4080     40C1 0.50 2^-1.00  | m_abc 41 61 -> 41 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc 81 C1 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      E00      C00 0.50 2^-1.00  | m_abc 200 300 -> 200 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR     2080     5051 1.00 2^0.00
 1: M_LR     4080     40C1 0.50 2^-1.00  | m_abc 41 61 -> 41 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc 81 C1 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      B00      800 0.50 2^-1.00  | m_abc 200 200 -> 300 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       98     7021 1.00 2^0.00
 1: M_LR     6080     4081 0.50 2^-1.00  | m_abc 3001 2001 -> 2001 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc C1 81 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      E00      C00 0.50 2^-1.00  | m_abc 200 300 -> 200 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       98     7021 1.00 2^0.00
 1: M_LR     6080     4081 0.50 2^-1.00  | m_abc 3001 2001 -> 2001 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc C1 81 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      B00      800 0.50 2^-1.00  | m_abc 200 200 -> 300 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       90     6021 1.00 2^0.00
 1: M_LR     6080     4081 0.50 2^-1.00  | m_abc 2001 3001 -> 2001 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc C1 81 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      E00      C00 0.50 2^-1.00  | m_abc 200 300 -> 200 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:550] Update bound: -3.00 -> -3.00
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       90     6021 1.00 2^0.00
 1: M_LR     6080     4081 0.50 2^-1.00  | m_abc 2001 3001 -> 2001 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc C1 81 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      B00      800 0.50 2^-1.00  | m_abc 200 200 -> 300 0.50
corr_trail 0.125000 -3.00
[./tests/speck-best-linear-search-tests.cc:618] Best linear trail on 4 rounds (WORD_SIZE 16 bits):
[./tests/speck-best-linear-search-tests.cc:98] speck_print_linear_trail()
 0: M_LR       90     6021 1.00 2^0.00
 1: M_LR     6080     4081 0.50 2^-1.00  | m_abc 2001 3001 -> 2001 0.50
 2: M_LR       80        1 0.50 2^-1.00  | m_abc C1 81 -> 81 0.50
 3: M_LR        1        0 1.00 2^0.00  | m_abc 1 1 -> 1 1.00
 4: M_LR      B00      800 0.50 2^-1.00  | m_abc 200 200 -> 300 0.50
corr_trail 0.125000 -3.00
differential_t g_T[NROUNDS + 1] = {
{      90,     6021, 0, (1.0 / (double)(1ULL <<  0))},
{    6080,     4081, 0, (1.0 / (double)(1ULL <<  -1))},
{      80,        1, 0, (1.0 / (double)(1ULL <<  -1))},
{       1,        0, 0, (1.0 / (double)(1ULL <<  0))},
{     B00,      800, 0, (1.0 / (double)(1ULL <<  -1))},
};
real    4m51.457s
user    4m51.546s
sys     0m0.004s


*/


// ---------------  RESULTS FROM speck-best-linear--search-tests.cc : 20151015 -------------}


// -------------------------  SPECK64 14R -60 (new) --------------------------------

uint32_t g_nrounds_n32_best = 14;//13;

double g_bounds_n32_best[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  7)), // 4
  (1.0 / (double)(1ULL << 13)), // 5
  (1.0 / (double)(1ULL << 21)), // 6
  (1.0 / (double)(1ULL << 27)), // 7
  (1.0 / (double)(1ULL << 32)), // 8
  (1.0 / (double)(1ULL << 36)), // 9
  (1.0 / (double)(1ULL << 40)), // 10
  (1.0 / (double)(1ULL << 44)), // 11
  (1.0 / (double)(1ULL << 47)), // 12
  (1.0 / (double)(1ULL << 52)), // 13
  (1.0 / (double)(1ULL << 60)), // 14
  0.0 								  // dummy
};

differential_t g_trail_n32_best[SPECK_TRAIL_LEN] = {
  {       0x9,  0x1000000, 0, 1.000000},  // input difference
  { 0x8000000,        0x0, 0, 0.250000}, // (2^-2.000000)
  {   0x80000,    0x80000, 0, 0.500000}, // (2^-1.000000)
  {   0x80800,   0x480800, 0, 0.250000}, // (2^-2.000000)
  {  0x480008,  0x2084008, 0, 0.062500}, // (2^-4.000000)
  { 0x6080808, 0x164A0848, 0, 0.007812}, // (2^-7.000000)
  {0xF2400040, 0x40104200, 0, 0.000122}, // (2^-13.000000)
  {  0x820200,     0x1202, 0, 0.003906}, // (2^-8.000000)
  {    0x9000,       0x10, 0, 0.062500}, // (2^-4.000000)
  {      0x80,        0x0, 0, 0.250000}, // (2^-2.000000)
  {0x80000000, 0x80000000, 0, 1.000000}, // (2^0.000000)
  {0x80800000, 0x80800004, 0, 0.500000}, // (2^-1.000000)
  {0x80008004, 0x84008020, 0, 0.125000}, // (2^-3.000000)
  {0x808080A0, 0xA08481A4, 0, 0.031250}, // (2^-5.000000)
  {   0x40024,  0x4200D01, 0, 0.003906}, // (2^-8.000000)
  {0, 0, 0, 0.0}						 // dummy
};										  // 2^-60


// -------------------------  SPECK32 9R -30, 10R -34 (new) --------------------------------

/*
Used two tables: 2^32 for the first round and 2^25 HWays for intermediate rounds

[./tests/speck-xor-threshold-search-tests.cc:1255] WORD_SIZE 16 NROUNDS 10 SPECK_P_THRES 0.007812 2^-7.000000 SPECK_MAX_DIFF_CNT 33554432 2^25.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 0 SPECK_MAX_HW 7  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-15.00

real    240m59.465s
user    240m29.450s
sys     0m7.748s
*/

uint32_t g_nrounds_n16_best = 9; // 10

double g_bounds_n16_best[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  5)), // 4
  (1.0 / (double)(1ULL <<  9)), // 5
  (1.0 / (double)(1ULL << 13)), // 6
  (1.0 / (double)(1ULL << 18)), // 7
  (1.0 / (double)(1ULL << 24)), // 8
  (1.0 / (double)(1ULL << 30)), // 9
  (1.0 / (double)(1ULL << 34)), // 10
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0  								  // dummy
};

differential_t g_trail_n16_best[SPECK_TRAIL_LEN] = {
  {0x8054, 0xA900, 0, 1.000000}, // 0 : input difference, p = 1
  {   0x0, 0xA402, 0, 0.125000}, //2^(-3.000000)
  {0xA402, 0x3408, 0, 0.125000}, //2^(-3.000000)
  {0x50C0, 0x80E0, 0, 0.003906}, //2^(-8.000000)
  { 0x181,  0x203, 0, 0.062500}, //2^(-4.000000)
  {   0xC,  0x800, 0, 0.031250}, //2^(-5.000000)
  {0x2000,    0x0, 0, 0.125000}, //2^(-3.000000)
  {  0x40,   0x40, 0, 0.500000}, //2^(-1.000000)
  {0x8040, 0x8140, 0, 0.500000}, //2^(-1.000000)
  {  0x40,  0x542, 0, 0.250000}, //2^(-2.000000)
  {0x8542, 0x904A, 0, 0.062500}, //2^(-4.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};



// -------------------------  SPECK32 9R -31 --------------------------------

/*
Found with parameters: 
[./tests/speck-xor-threshold-search-tests.cc:158] WORD_SIZE 16 NROUNDS 9 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 1073741824 2^30.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-15.00
*/
//[./src/speck-xor-threshold-search.cc:1148] Found 1 trails:
//[    1] A60 4205 211 A04 2800 10 40 0 8000 8000 8100 8102 8000 840A 850A 9520 802A D4A8 A8 520B  | 2^-31.000000 
//Probability of differential: 2^-31.000000

uint32_t g_nrounds_n16_1 = 9;

double g_bounds_n16_1[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  5)), // 4
  (1.0 / (double)(1ULL <<  9)), // 5
  (1.0 / (double)(1ULL << 13)), // 6
  (1.0 / (double)(1ULL << 18)), // 7
  (1.0 / (double)(1ULL << 24)), // 8
  (1.0 / (double)(1ULL << 31)), // 9
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0  								  // dummy
};

differential_t g_trail_n16_1[SPECK_TRAIL_LEN] = {
  { 0xA60, 0x4205, 0, 1.0}, // 0 : input difference, p = 1
  { 0x211,  0xA04, 0, 0.031250}, //(2^-5.000000)
  {0x2800,   0x10, 0, 0.062500}, //(2^-4.000000)
  {  0x40,    0x0, 0, 0.250000}, //(2^-2.000000)
  {0x8000, 0x8000, 0, 1.000000}, //(2^0.000000)
  {0x8100, 0x8102, 0, 0.500000}, //(2^-1.000000)
  {0x8000, 0x840A, 0, 0.250000}, //(2^-2.000000)
  {0x850A, 0x9520, 0, 0.062500}, //(2^-4.000000)
  {0x802A, 0xD4A8, 0, 0.015625}, //(2^-6.000000)
  {  0xA8, 0x520B, 0, 0.007812},  //(2^-7.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};

// -------------------------  SPECK48 10R -45 --------------------------------

/*
Found with parameters: 

Time: Sat Nov  9 23:51:01 2013
[./tests/speck-xor-threshold-search-tests.cc:158] WORD_SIZE 24 NROUNDS 10 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4294967296 2^32.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 7  SPECK_CLUSTER_MAX_HW 7 SPECK_EPS 2^-15.00

[./src/speck-xor-threshold-search.cc:1273] Found 1 trails:
[    1] 88A 484008 424000 4042 202 20012 10 100080 80 800480 480 2084 802080 8124A0 A480 98184 888020 C48C00 240480 6486 800082 8324B2  | 2^-45.000000 
Probability of differential: 2^-45.000000
Probability of differential: 2^-43.873998
[./src/speck-xor-threshold-search.cc:1311] 10 R (     88A   484008) -> (  800082   8324B2) : [        30 trails]  2^-43.873998

*/
uint32_t g_nrounds_n24_1 = 10;

double g_bounds_n24_1[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 10)), // 5
  (1.0 / (double)(1ULL << 14)), // 6
  (1.0 / (double)(1ULL << 19)), // 7
  (1.0 / (double)(1ULL << 26)), // 8
  (1.0 / (double)(1ULL << 35)), // 9
  (1.0 / (double)(1ULL << 45)),  // 10
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n24_1[SPECK_TRAIL_LEN] = {
  {   0x88A, 0x484008, 0, 1.0}, // 0 : input difference, p = 1
  {0x424000,   0x4042, 0, 0.031250}, //(2^2^-5.000000)
  {   0x202,  0x20012, 0, 0.062500}, //(2^2^-4.000000)
  {    0x10, 0x100080, 0, 0.125000}, //(2^2^-3.000000)
  {    0x80, 0x800480, 0, 0.250000}, //(2^2^-2.000000)
  {   0x480,   0x2084, 0, 0.250000}, //(2^2^-2.000000)
  {0x802080, 0x8124A0, 0, 0.125000}, //(2^2^-3.000000)
  {  0xA480,  0x98184, 0, 0.015625}, //(2^2^-6.000000)
  {0x888020, 0xC48C00, 0, 0.007812}, //(2^2^-7.000000)
  {0x240480,   0x6486, 0, 0.007812}, //(2^2^-7.000000)
  {0x800082, 0x8324B2, 0, 0.015625}, //(2^2^-6.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};												// total p = 2^-45


// -------------------------  SPECK48 10R -40 (new) --------------------------------

/*
  Found with start-from-the-middle threshold search
*/

uint32_t g_nrounds_n24_2 = 10;

double g_bounds_n24_2[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  4)), // 3
  (1.0 / (double)(1ULL <<  8)), // 4
  (1.0 / (double)(1ULL << 15)), // 5
  (1.0 / (double)(1ULL << 17)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 26)), // 8
  (1.0 / (double)(1ULL << 33)), // 9
  (1.0 / (double)(1ULL << 40)),  // 10
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n24_2[SPECK_TRAIL_LEN] = {
  {0x480901,  0x94009, 0, 1.000000}, // 0 : input difference, p = 1
  { 0x80802, 0x42084A, 0, 0.007812}, // (2^-7.000000)
  {0x400052, 0x504200, 0, 0.007812}, // (2^-7.000000)
  {0x820200,   0x1202, 0, 0.031250}, // (2^-5.000000)
  {  0x9000,     0x10, 0, 0.062500}, // (2^-4.000000)
  {    0x80,      0x0, 0, 0.250000}, // (2^-2.000000)
  {0x800000, 0x800000, 0, 1.000000}, // (2^-0.000000)
  {0x808000, 0x808004, 0, 0.500000}, // (2^-1.000000)
  {0x800084, 0x8400A0, 0, 0.125000}, // (2^-3.000000)
  {  0x80A0, 0x2085A4, 0, 0.062500}, // (2^-4.000000)
  {0x808424, 0x84A905, 0, 0.007812}, // (2^-7.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};												// total p = 2^-45

// -------------------------  SPECK48 11R -47 (new) --------------------------------

/*
  Found with start-from-the-middle threshold search
*/

uint32_t g_nrounds_n24_best = 11;

double g_bounds_n24_best[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  4)), // 3
  (1.0 / (double)(1ULL <<  8)), // 4
  (1.0 / (double)(1ULL << 15)), // 5
  (1.0 / (double)(1ULL << 17)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 26)), // 8
  (1.0 / (double)(1ULL << 33)), // 9
  (1.0 / (double)(1ULL << 40)),  // 10
  (1.0 / (double)(1ULL << 47)),  // 11
  0.0,								  // dummy
  0.0,								  // dummy
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n24_best[SPECK_TRAIL_LEN] = {
  {0x202040,  0x82921, 0, 1.000000}, // 0 : input difference, p = 1
  {0x480901,  0x94009, 0, 0.007812}, // (2^-7.000000)
  { 0x80802, 0x42084A, 0, 0.007812}, // (2^-7.000000)
  {0x400052, 0x504200, 0, 0.007812}, // (2^-7.000000)
  {0x820200,   0x1202, 0, 0.031250}, // (2^-5.000000)
  {  0x9000,     0x10, 0, 0.062500}, // (2^-4.000000)
  {    0x80,      0x0, 0, 0.250000}, // (2^-2.000000)
  {0x800000, 0x800000, 0, 1.000000}, // (2^0.000000)
  {0x808000, 0x808004, 0, 0.500000}, // (2^-1.000000)
  {0x800084, 0x8400A0, 0, 0.125000}, // (2^-3.000000)
  {  0x80A0, 0x2085A4, 0, 0.062500}, // (2^-4.000000)
  {0x808424, 0x84A905, 0, 0.007812}, // (2^-7.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};											// total p = 2^-47

// -------------------------  SPECK64 13 -63 --------------------------------

uint32_t g_nrounds_n32_1 = 13;

double g_bounds_n32_1[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 11)), // 5
  (1.0 / (double)(1ULL << 16)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 29)), // 8
  (1.0 / (double)(1ULL << 34)), // 9
  (1.0 / (double)(1ULL << 38)), // 10
  (1.0 / (double)(1ULL << 44)), // 11
  (1.0 / (double)(1ULL << 51)), // 12
  (1.0 / (double)(1ULL << 58)), // 13
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n32_1[SPECK_TRAIL_LEN] = {
  {0x50400092, 0x10404000, 0, 1.000000},
  {0x82100000,   0x120000, 0, 0.031250}, //(2^-5.000000)
  {  0x901000,     0x1000, 0, 0.062500}, //(2^-4.000000)
  {    0x8010,       0x10, 0, 0.125000}, //(2^-3.000000)
  {0x10000090, 0x10000010, 0, 0.125000}, //(2^-3.000000)
  {0x80100010,   0x100090, 0, 0.125000}, //(2^-3.000000)
  {0x10901090, 0x10101410, 0, 0.015625}, //(2^-6.000000)
  {0x80008400,   0x802480, 0, 0.015625}, //(2^-6.000000)
  {    0x2404,  0x4010004, 0, 0.031250}, //(2^-5.000000)
  {   0x10020, 0x20090000, 0, 0.062500}, //(2^-4.000000)
  {   0x90100,   0x410101, 0, 0.062500}, //(2^-4.000000)
  {  0x410800,  0x2490008, 0, 0.031250}, //(2^-5.000000)
  { 0x2494100, 0x10014140, 0, 0.007812}, //(2^-7.000000)
  {0x10010801, 0x900B0201, 0, 0.003906}, //(2^-8.000000)
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};										  // 2^-63

// -------------------------  SPECK64 13R -58 --------------------------------

/*
Found with parameters: 
[   48] 802490 10800004 83808020 7808000 3C000080 40080 80200080 80000480 802480 800084 808080A0 84808480 24000400 42004 202000 12020 10000 80100 80000 480800 480000 2084000 2080800 124A0800 12480008 80184008 880A0808 88C8084C  | 2^-68.000000

Probability of differential: 2^-57.697796
[./src/speck-xor-threshold-search.cc:1216] 13 R (  802490 10800004) -> (880A0808 88C8084C) : [        48 trails]  2^-57.697796
   [./tests/speck-xor-threshold-search-tests.cc:165] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4194304 2^22.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-5.00

{--------- new ---------
  [./tests/speck-xor-threshold-search-tests.cc:1055] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4194304 2^22.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-5.00

  [./tests/speck-xor-threshold-search-tests.cc:1055] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.007812 2^-7.000000 SPECK_MAX_DIFF_CNT 4194304 2^22.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 0 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-15.00
--------- new ---------}


[
[./src/speck-xor-threshold-search.cc:1316] 13 R (  802490 10800004) -> (880A0808 88C8084C) : [       728 trails]  2^-57.8633224925  <--- eps 2^-35
[./tests/speck-xor-threshold-search-tests.cc:156] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 33554432 2^25.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 7 SPECK_EPS 2^-35.00
*/
//uint32_t g_nrounds_n32_2 = 13;
uint32_t g_nrounds_n32_best_old = 13;

double g_bounds_n32_best_old[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 11)), // 5
  (1.0 / (double)(1ULL << 16)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 29)), // 8
  (1.0 / (double)(1ULL << 34)), // 9
  (1.0 / (double)(1ULL << 38)), // 10
  (1.0 / (double)(1ULL << 44)), // 11
  (1.0 / (double)(1ULL << 51)), // 12
  (1.0 / (double)(1ULL << 58)),  // 13
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n32_best_old[SPECK_TRAIL_LEN] = {
  {  0x802490, 0x10800004, 0, 1.0}, // 0 : input difference, p = 1
  {0x80808020,  0x4808000, 0, 0.031250}, //2^(-5.000000) //1 
  {0x24000080,    0x40080, 0, 0.031250}, //2^(-5.000000) //2
  {0x80200080, 0x80000480, 0, 0.125000}, //2^(-3.000000) //3
  {  0x802480,   0x800084, 0, 0.062500}, //2^(-4.000000) //4
  {0x808080A0, 0x84808480, 0, 0.031250}, //2^(-5.000000) //5
  {0x24000400,    0x42004, 0, 0.015625}, //2^(-6.000000) //6
  {  0x202000,    0x12020, 0, 0.062500}, //2^(-4.000000) //7
  {   0x10000,    0x80100, 0, 0.125000}, //2^(-3.000000) //8
  {   0x80000,   0x480800, 0, 0.250000}, //2^(-2.000000) //9
  {  0x480000,  0x2084000, 0, 0.125000}, //2^(-3.000000) //10
  { 0x2080800, 0x124A0800, 0, 0.062500}, //2^(-4.000000) //11
  {0x12480008, 0x80184008, 0, 0.007812}, //2^(-7.000000) //12
  {0x880A0808, 0x88C8084C, 0, 0.007812}, //2^(-7.000000)  //13
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};													  // total: 2^-58
//trail: 802490 10800004 80808020 4808000 24000080 40080 80200080 80000480 802480 800084 808080A0 84808480 24000400 42004 202000 12020 10000 80100 80000 480800 480000 2084000 2080800 124A0800 12480008 80184008 880A0808 88C8084C  | 2^-58.000000 

// -------------------------  SPECK64 13R -58 --------------------------------

/*
  Prob. of differential: 2^-57.68
  [./src/speck-xor-threshold-search.cc:1803] Initial trail: 13 R (50400092 10404000) -> ( 8010041    10249) : [         1 trails]  2^-58.000000
  [./src/speck-xor-threshold-search.cc:1714] this: 2^-72.000000 (best: 2^-58.000000)  10249) : [        13 trails]  2^-57.6882516850
  [./tests/speck-xor-threshold-search-tests.cc:165] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4194304 2^22.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 6  SPECK_CLUSTER_MAX_HW 6 SPECK_EPS 2^-5.00
*/
uint32_t g_nrounds_n32_3 = 13;

double g_bounds_n32_3[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 11)), // 5
  (1.0 / (double)(1ULL << 16)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 29)), // 8
  (1.0 / (double)(1ULL << 34)), // 9
  (1.0 / (double)(1ULL << 38)), // 10
  (1.0 / (double)(1ULL << 44)), // 11
  (1.0 / (double)(1ULL << 51)), // 12
  (1.0 / (double)(1ULL << 58)), // 13
  0.0,								  // dummy
  0.0 								  // dummy
};

differential_t g_trail_n32_3[SPECK_TRAIL_LEN] = {
  {0x50400092, 0x10404000, 0, 1.000000},
  {0x82100000,   0x120000, 0, (1.0 / (double)(1ULL << 5))},
  {  0x901000,     0x1000, 0, (1.0 / (double)(1ULL << 4))},
  {    0x8010,       0x10, 0, (1.0 / (double)(1ULL << 3))},
  {0x10000090, 0x10000010, 0, (1.0 / (double)(1ULL << 3))},
  {0x80100010,   0x100090, 0, (1.0 / (double)(1ULL << 3))},
  {0x10901090, 0x10101410, 0, (1.0 / (double)(1ULL << 6))},
  {0x8000BC00,   0x801C80, 0, (1.0 / (double)(1ULL << 7))},
  {    0xE404,  0x4000004, 0, (1.0 / (double)(1ULL << 12))},
  {      0x20, 0x20000000, 0, (1.0 / (double)(1ULL << 5))},
  {       0x0,        0x1, 0, (1.0 / (double)(1ULL << 1))},
  {       0x1,        0x9, 0, (1.0 / (double)(1ULL << 1))},
  { 0x1000009,  0x1000041, 0, (1.0 / (double)(1ULL << 3))},
  { 0x8010041,    0x10249, 0, (1.0 / (double)(1ULL << 5))},
  {0, 0, 0, 0.0},						 // dummy
  {0, 0, 0, 0.0}						 // dummy
};										  // 2^-58
//#endif


#endif  // #ifndef SPECK_TRAILS_H
