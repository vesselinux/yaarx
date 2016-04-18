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
 * \file  speck-xor-best-trails.hh
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief best found trails for Speck using threshold search
 */ 
#ifndef SPECK_XOR_BEST_TRAILS_H
#define SPECK_XOR_BEST_TRAILS_H

/*
Found with parameters: 
[./tests/speck-xor-threshold-search-tests.cc:158] WORD_SIZE 16 NROUNDS 9 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 1073741824 2^30.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-15.00
*/

// Speck32, 9R, -31
differential_t g_speck32_trail_9r[SPECK_TRAIL_LEN_MAX] = {
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
  {0, 0, 0, 0.0},					 // dummy
  {0, 0, 0, 0.0},					 // dummy
  {0, 0, 0, 0.0},					 // dummy
  {0, 0, 0, 0.0}					 // dummy
};

/*
[./tests/speck-xor-threshold-search-tests.cc:158] WORD_SIZE 24 NROUNDS 10 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4294967296 2^32.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 7  SPECK_CLUSTER_MAX_HW 7 SPECK_EPS 2^-15.00
*/
// Speck48, 10R, -45
differential_t g_speck48_trail_10r[SPECK_TRAIL_LEN_MAX] = {
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
  {0, 0, 0, 0.0},					 // dummy
  {0, 0, 0, 0.0},					 // dummy
  {0, 0, 0, 0.0}					 // dummy
};												// total p = 2^-45

/*
[./tests/speck-xor-threshold-search-tests.cc:165] WORD_SIZE 32 NROUNDS 13 SPECK_P_THRES 0.031250 2^-5.000000 SPECK_MAX_DIFF_CNT 4194304 2^22.00 SPECK_BACK_TO_HWAY 0 SPECK_GREEDY_SEARCH 1 SPECK_MAX_HW 9  SPECK_CLUSTER_MAX_HW 9 SPECK_EPS 2^-5.00
*/

// Speck64, 13R, -58
differential_t g_speck64_trail_13r[SPECK_TRAIL_LEN_MAX] = {
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
  {0x880A0808, 0x88C8084C, 0, 0.007812}  //2^(-7.000000)  //13
};

#endif  // #ifndef SPECK_XOR_BEST_TRAILS_H
