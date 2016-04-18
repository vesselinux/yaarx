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
 * \file  speck-xor-threshold-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for automatic search for XOR differentials in block cipher Speck .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "xdp-add.hh"
#endif
#ifndef XDP_ADD_PDDT_H
#include "xdp-add-pddt.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif
#ifndef SPECK_XOR_THRESHOLD_SEARCH_H
#include "speck-xor-threshold-search.hh"
#endif
#ifndef SPECK_XOR_BEST_TRAILS_H
#include "speck-xor-best-trails.hh"
#endif
#ifndef SPECK_TRAILS_H
#include "speck-trails.hh"
#endif


// {----- Lucks et al.: fixed trails used for verification purpouses -----
#if 0

#if 1									  // Lucks et al. 2^-56
double g_B[14] = {
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
  (1.0 / (double)(1ULL << 58))  // 13
};

/* Not possible to verify:

(40104200 40024000 ->   120200) 0.031250 2^-5.00
(    1202      202 ->     1000) 0.125000 2^-3.00
(      10       10 ->        0) 0.500000 2^-1.00  <- 40000000 !=       80
(       0 40000000 -> 40000000) 0.500000 2^-1.00  <- 40000000 != 40000002
(  400000 40000000 -> 40400000) 0.250000 2^-2.00
(  404000 40400002 -> 40004002) 0.062500 2^-4.00
( 2400040 42004010 -> 404040D0) 0.007812 2^-7.00
(D0404040 50424052 -> 80020092) 0.001953 2^-9.00
(92800200  2100200 -> 90900000) 0.031250 2^-5.00
(  909000 80101000 -> 80808000) 0.062500 2^-4.00
(  808080 80000004 -> 80808084) 0.062500 2^-4.00
(84808080 808080A0 ->  4000020) 0.031250 2^-5.00
(20040000    40524 -> 20000524) 0.015625 2^-6.00
p_tot = 0.000000000000000 = 2^-56.000000
*/
differential_t g_trail[SPECK_TRAIL_LEN] = {
  {0x10420040, 0x40024000, 0, 0.0},		  // 0: input
  {  0x120200,      0x202, 0, 0.0},		  // 1
  {    0x1000,       0x10, 0, 0.0},		  // 2
  {       0x0,       0x80, 0, 0.0},		  // 3 : wrong (original)
  //{       0x0, 0x40000000, 0, 0.0},		  // 3 : corrected?
  {0x40000000, 0x40000000, 0, 0.0},		  // 4
  {0x40400000, 0x40400002, 0, 0.0},		  // 5
  {0x40004002, 0x42004010, 0, 0.0},		  // 6
  {0x404040D0, 0x50424052, 0, 0.0},		  // 7
  {0x80020092,  0x2100200, 0, 0.0},		  // 8
  {0x90900000, 0x80101000, 0, 0.0},		  // 9
  {0x80808000, 0x80000004, 0, 0.0},		  // 10
  {0x80808084, 0x808080A0, 0, 0.0},		  // 11
  {0x04000020,    0x40524, 0, 0.0},		  // 12
  {0x20000524, 0x20202C04, 0, 0.0}		  // 13
};										  // 2^-56
#endif

#if 0									  // p 2^-61
// Probability of differential: 2^-60.908828
//[./src/speck-xor-threshold-search.cc:1176] 13 R (40020092 10420000) -> (22202820 32232021) : [       204 trails]  2^-60.908828

double g_B[SPECK_TRAIL_LEN] = {
  1.0,								  // 0: input diff
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  7)), // 4
  (1.0 / (double)(1ULL << 13)), // 5
  (1.0 / (double)(1ULL << 21)), // 6
  (1.0 / (double)(1ULL << 27)), // 7
  (1.0 / (double)(1ULL << 32)), // 8
  (1.0 / (double)(1ULL << 37)), // 9
  (1.0 / (double)(1ULL << 43)), // 10
  (1.0 / (double)(1ULL << 53)), // 11
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 4))), // 2^-64
  ((1.0 / (double)(1ULL << 60)) * (1.0 / (double)(1ULL << 13))) // 2^-73
};

differential_t g_trail[SPECK_TRAIL_LEN] = {
 {0x40020092, 0x10420000, 0, (1.0 / (double)(1ULL << 0))}, // 0 : input difference, p = 1
  {0x82020200,   0x120200, 0, (1.0 / (double)(1ULL << 5))}, // 1
  {  0x900002,     0x1002, 0, (1.0 / (double)(1ULL << 5))}, // 2
  { 0x2008002,  0x2000012, 0, (1.0 / (double)(1ULL << 4))}, // 3
  {   0x20092, 0x10020002, 0, (1.0 / (double)(1ULL << 5))}, // 4
  {0x82020202,  0x2120212, 0, (1.0 / (double)(1ULL << 5))}, // 5
  {  0x900010, 0x10001080, 0, (1.0 / (double)(1ULL << 7))}, // 6
  {    0x8080, 0x80000480, 0, (1.0 / (double)(1ULL << 4))}, // 7
  {     0x400,     0x2004, 0, (1.0 / (double)(1ULL << 2))}, // 8
  {    0x2000,    0x12020, 0, (1.0 / (double)(1ULL << 2))}, // 9
  {   0x12000,    0x82100, 0, (1.0 / (double)(1ULL << 3))}, // 10
  {   0x82020,   0x492820, 0, (1.0 / (double)(1ULL << 4))}, // 11
  {0x20492000, 0x22006100, 0, (1.0 / (double)(1ULL << 7))}, // 12
  {0x22202820, 0x32232021, 0, (1.0 / (double)(1ULL << 8))}	// 13
};																					// total: 2^-61
#endif																			// #if 0

#if 0									  // Lucks et. al best

double g_B[14] = {
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
  (1.0 / (double)(1ULL << 58))  // 13
};

differential_t g_trail[SPECK_TRAIL_LEN] = {
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
  { 0x8010041,    0x10249, 0, (1.0 / (double)(1ULL << 5))}
};										  // 2^-58
#endif

#endif  // #if 0


/**
 * Cluster multiple trails starting from one fixed trail
 * possibly found using threshold search.
 */
void speck_cluster_trails(differential_t input_trail[SPECK_TRAIL_LEN_MAX], 
								  double input_bounds[SPECK_TRAIL_LEN_MAX],
								  uint32_t input_trail_len,
								  uint32_t word_size)
{
  assert(word_size == WORD_SIZE);
  assert(input_trail_len <= SPECK_TRAIL_LEN_MAX);
  assert(NROUNDS <= SPECK_TRAIL_LEN_MAX);
  assert(input_trail_len == NROUNDS);

  double B[NROUNDS] = {0.0}; 
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t dx_input = input_trail[0].dx;
  uint32_t dy_input = input_trail[0].dy;

  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail[i] = input_trail[i+1];
	 B[i] = input_bounds[i+1];
  }

#if 1									  // DEBUG
  printf("Input diffs: %8X %8X\n", dx_input, dy_input);
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("B[%2d] 2^%f | %8X %8X 2^%f\n", i, log2(B[i]), trail[i].dx, trail[i].dy, log2(trail[i].p));
#else
	 printf("B[%2d] 2^%f | %16llX %16llX 2^%f\n", i, log2(B[i]), (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, log2(trail[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
  }
#endif  // #if 0

  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p;	 // Dp

  double p_thres = SPECK_P_THRES;
  uint64_t max_cnt = SPECK_MAX_DIFF_CNT;
  uint32_t hw_thres = SPECK_MAX_HW;//SPECK_CLUSTER_MAX_HW
  speck_xdp_add_pddt(WORD_SIZE, p_thres, hw_thres, max_cnt, &diff_set_dx_dy_dz, &diff_mset_p);

  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to> trails_hash_map;
  uint32_t trail_len = NROUNDS;

  speck_trail_cluster_search_boost(&trails_hash_map, &diff_mset_p, &diff_set_dx_dy_dz, dx_input, dy_input, B, trail, trail_len);
}

void test_speck_cluster_trails()
{
#if (WORD_SIZE <= 32)
  uint32_t word_size = WORD_SIZE;
#if(WORD_SIZE == 16)
  speck_cluster_trails(g_trail_n16_best, g_bounds_n16_best, g_nrounds_n16_best, word_size);
#endif  // #if(WORD_SIZE == 16)
#if(WORD_SIZE == 24)
  speck_cluster_trails(g_trail_n24_best, g_bounds_n24_best, g_nrounds_n24_best, word_size);
#endif  // #if(WORD_SIZE == 16)
#if(WORD_SIZE == 32)
  speck_cluster_trails(g_trail_n32_best, g_bounds_n32_best, g_nrounds_n32_best, word_size);
#endif  // #if(WORD_SIZE == 16)
#endif // #if (WORD_SIZE <= 32)
}


#if(WORD_SIZE == 32)
#if 0
differential_t g_lucks_trail[14] = {
  {0x10420040, 0x40024000, 0, 1.000000},		  // 0: input
  {  0x120200,      0x202, 0, 1.000000},		  // 1
  {    0x1000,       0x10, 0, 1.000000},		  // 2
  {       0x0,       0x80, 0, 1.000000},		  // 3 : wrong
  // {       0x0, 0x40000000, 0, 1.000000},		  // 3 : corrected
  {0x40000000, 0x40000000, 0, 1.000000},		  // 4
  {0x40400000, 0x40400002, 0, 1.000000},		  // 5
  {0x40004002, 0x42004010, 0, 1.000000},		  // 6
  {0x404040D0, 0x50424052, 0, 1.000000},		  // 7
  {0x80020092,  0x2100200, 0, 1.000000},		  // 8
  {0x90900000, 0x80101000, 0, 1.000000},		  // 9
  {0x80808000, 0x80000004, 0, 1.000000},		  // 10
  {0x80808084, 0x808080A0, 0, 1.000000},		  // 11
  {0x04000020,    0x40524, 0, 1.000000},		  // 12
  {0x20000524, 0x20202C04, 0, 1.000000}		  // 13
};
#endif
#if 1
differential_t g_lucks_trail[14] = {
  // {       0x0, 0x40000000, 0, 1.000000},		  // 3 : corrected
  {       0x0,       0x80, 0, 1.000000},		  // 3 : wrong
  {0x40000000, 0x40000000, 0, 1.000000},		  // 4
  {0x40400000, 0x40400002, 0, 1.000000},		  // 5
  {0x40004002, 0x42004010, 0, 1.000000},		  // 6
  {0x404040D0, 0x50424052, 0, 1.000000},		  // 7
  {0x80020092,  0x2100200, 0, 1.000000},		  // 8
  {0x90900000, 0x80101000, 0, 1.000000},		  // 9
  {0x80808000, 0x80000004, 0, 1.000000},		  // 10
  {0x80808084, 0x808080A0, 0, 1.000000},		  // 11
  {0x04000020,    0x40524, 0, 1.000000},		  // 12
  {0x20000524, 0x20202C04, 0, 1.000000},		  // 13
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0}										  // dummy
};
differential_t g_lucks_trail_inv[14] = {
  //  {       0x0, 0x40000000, 0, 1.000000},		  // 3 : corrected
  {       0x0,       0x80, 0, 1.000000},		  // 3 : wrong
  {    0x1000,       0x10, 0, 1.000000},		  // 2
  {  0x120200,      0x202, 0, 1.000000},		  // 1
  {0x10420040, 0x40024000, 0, 1.000000},		  // 0: input
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0}										  // dummy
};
#endif
#elif(WORD_SIZE == 24)
#if 0
differential_t g_lucks_trail[11] = {
  {0x480B01,  0x94009, 0, 1.000000},		  // 0: input
  //  {0x4A0901,  0x94209, 0, 1.000000},		  // 0: corrected input 
  { 0x81802, 0x42084A, 0, 1.000000},	     // 1
  {0x400052, 0x504200, 0, 1.000000},		  // 2
  {0x820200,   0x1202, 0, 1.000000},		  // 3
  {  0x9000,     0x10, 0, 1.000000},		  // 4
  {    0x80,      0x0, 0, 1.000000},		  // 5
  {0x800000, 0x800000, 0, 1.000000},		  // 6
  {0x808000, 0x808004, 0, 1.000000},		  // 7
  {0x800084, 0x8400A0, 0, 1.000000},		  // 8
  {  0x80A0, 0x2085A4, 0, 1.000000},		  // 9
  //  {  0x8524, 0x84A805, 0, 1.000000}		     // 10
  {0x808424, 0x84A905, 0, 1.000000}			  // 10 <- corrected
 };
differential_t g_lucks_trail_inv[11] = {
  //  {  0x8524, 0x84A805, 0, 1.000000},	     // 10
  {0x808424, 0x84A905, 0, 1.000000},			  // 10 <- corrected
  {  0x80A0, 0x2085A4, 0, 1.000000},		  // 9
  {0x800084, 0x8400A0, 0, 1.000000},		  // 8
  {0x808000, 0x808004, 0, 1.000000},		  // 7
  {0x800000, 0x800000, 0, 1.000000},		  // 6
  {    0x80,      0x0, 0, 1.000000},		  // 5
  {  0x9000,     0x10, 0, 1.000000},		  // 4
  {0x820200,   0x1202, 0, 1.000000},		  // 3
  {0x400052, 0x504200, 0, 1.000000},		  // 2
  { 0x81802, 0x42084A, 0, 1.000000},		  // 1
  {0x480B01,  0x94009, 0, 1.000000}		  // 0: input
  //  {0x4A0901,  0x94209, 0, 1.000000}		  // 0: corrected input 
};
#endif
#if 1
differential_t g_lucks_trail[11] = {	 // encrypt
  {    0x80,      0x0, 0, 1.000000},		  // 5
  {0x800000, 0x800000, 0, 1.000000},		  // 6
  {0x808000, 0x808004, 0, 1.000000},		  // 7
  {0x800084, 0x8400A0, 0, 1.000000},		  // 8
  {  0x80A0, 0x2085A4, 0, 1.000000},		  // 9
  //  {  0x8524, 0x84A805, 0, 1.000000},		  // 10 <- impossible
  {0x808524, 0x84A805, 0, 1.000000},		  // 10 <- Eik corrected
  //  {0x808424, 0x84A905, 0, 1.000000},			  // 10 <- my corrected
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  //  {0, 0, 0, 0.0}	  								  // dummy
};
differential_t g_lucks_trail_inv[11] = { // decrypt
  //  {0x800000, 0x800000, 0, 1.000000},		  // 6
  {    0x80,      0x0, 0, 1.000000},		  // 5
  {  0x9000,     0x10, 0, 1.000000},		  // 4
  {0x820200,   0x1202, 0, 1.000000},		  // 3
  {0x400052, 0x504200, 0, 1.000000},		  // 2
  { 0x81802, 0x42084A, 0, 1.000000},		  // 1
  {0x480B01,  0x94009, 0, 1.000000},		  // 0: input
  //  {0x4A0901,  0x94209, 0, 1.000000},		  // 0: my corrected input 
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0}										  // dummy
};
#endif
#if 0
differential_t g_lucks_trail[11] = {	 // encrypt
  {  0x9000,     0x10, 0, 1.000000},		  // 4
  {    0x80,      0x0, 0, 1.000000},		  // 5
  {0x800000, 0x800000, 0, 1.000000},		  // 6
  {0x808000, 0x808004, 0, 1.000000},		  // 7
  {0x800084, 0x8400A0, 0, 1.000000},		  // 8
  {  0x80A0, 0x2085A4, 0, 1.000000},		  // 9
  {  0x8524, 0x84A805, 0, 1.000000},		     // 10
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0}	  								  // dummy
};
differential_t g_lucks_trail_inv[11] = { // decrypt
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0},										  // dummy
  {0, 0, 0, 0.0}										  // dummy
};
#endif
#endif

// Verify the trail on Speck64 by Lucks et al, Table 7
void test_verify_lucks_trail()
{
#if 0//((WORD_SIZE == 24) || (WORD_SIZE == 32))
  assert((WORD_SIZE == 32) || (WORD_SIZE == 24));
  if(WORD_SIZE == 32) {
	 assert(NROUNDS == 13);
  }
  if(WORD_SIZE == 24) {
	 assert(NROUNDS == 10);
  }

  uint32_t npairs = SPECK_NPAIRS;
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  differential_t trail_inv[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;

  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  uint32_t dx_init = g_lucks_trail[0].dx;
  uint32_t dy_init = g_lucks_trail[0].dy;

  assert(SPECK_TRAIL_LEN >= NROUNDS);

#if 1									  // DEBUG
  printf("[%s:%d] Lucks trail BEFORE:\n", __FILE__, __LINE__);
  printf("%2d: %8X %8X %f\n", 0, dx_init, dy_init, 1.0);
  for(uint32_t i = 0; i < SPECK_TRAIL_LEN; i++) {
	 printf("%2d: %8X %8X %f (2^%f)\n", i, g_lucks_trail[i].dx, g_lucks_trail[i].dy, g_lucks_trail[i].p, log2(g_lucks_trail[i].p));
  }
#endif  // #if 0									  // DEBUG

  printf("\n");

  // ENCRYPT
  double p_tot = 1.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 //	 uint32_t dx = RROT(g_lucks_trail[i].dx, right_rot_const);
	 uint32_t dx = RROT(g_lucks_trail[i].dx, right_rot_const);
	 uint32_t dy = g_lucks_trail[i].dy;
	 uint32_t dz = g_lucks_trail[i+1].dx;
	 double p = xdp_add_lm(dx, dy, dz);
	 //	 uint32_t dz_max = 0;
	 //	 double p_max = max_xdp_add_lm(dx, dy, &dz_max);
	 //	 printf("%8X %8X -> (%8X %f 2^%4.2f) (%8X %f 2^%4.2f)\n", dx, dy, dz, p, log2(p), dz_max, p_max, log2(p_max));
	 //	 trail[i].p = p_max;
	 trail[i] = g_lucks_trail[i+1];
	 trail[i].p = p;
	 p_tot *= trail[i].p;

	 if(i == 4) {					  // for the 5-th round compute greedy
	 //	 if(0) {					  // for the 5-th round compute greedy
		uint32_t dx = RROT(g_lucks_trail[i].dx, right_rot_const);
		uint32_t dy = g_lucks_trail[i].dy;
		uint32_t dz_max = 0;
#if 1									  // DEBUG
		printf("[%s:%d] [%d] %8X %8X\n", __FILE__, __LINE__, i, g_lucks_trail[i].dx, g_lucks_trail[i].dy);
#endif
		//		assert(1 == 0);
		double p_max = max_xdp_add_lm(dx, dy, &dz_max);
		trail[i].dx = dz_max;
		trail[i].dy = LROT(dy, left_rot_const) ^ trail[i].dx;
		trail[i].p = p_max;
	 //	 printf("%8X %8X -> (%8X %f 2^%4.2f) (%8X %f 2^%4.2f)\n", dx, dy, dz, p, log2(p), dz_max, p_max, log2(p_max));
	 //	 trail[i].p = p_max;
	 }

#if 0
	 printf("(%8X %8X -> %8X) %f 2^%4.2f ", dx, dy, dz, p, log2(p));
	 uint32_t dyy = LROT(dy, left_rot_const) ^ dz;
	 //	 assert(dyy == g_lucks_trail[i+1].dy);
	 if(!(dyy == g_lucks_trail[i+1].dy)) {
		printf(" <- %8X != %8X ", g_lucks_trail[i+1].dy, dyy);
	 }
	 if(p == 0.0) {
		uint32_t dz_max = 0;
		double p_max = max_xdp_add_lm(dx, dy, &dz_max);
		printf(" |  -> %8X %f", dz_max, p_max);
		trail[i+1].dx = dz_max;
		trail[i].p = p_max;
	 }
	 printf("\n");
#endif
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));

#if 1									  // DEBUG
  printf("[%s:%d] Lucks trail AFTER:\n", __FILE__, __LINE__);
  printf("%2d: %8X %8X %f\n", 0, dx_init, dy_init, 1.0);
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 printf("%2d: %8X %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
  }
#endif  // #if 0									  // DEBUG

  uint32_t dx_init_inv = g_lucks_trail_inv[0].dx;
  uint32_t dy_init_inv = g_lucks_trail_inv[0].dy;

  // DECRYPT
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_inv[i] = g_lucks_trail_inv[i+1];
	 //	 trail_inv[i] = trail[NROUNDS - i - 1];
	 //	 if(i == 4) {					  // for the 5-th round compute greedy
	 if(0) {					  // for the 5-th round compute greedy
		uint32_t dx = g_lucks_trail_inv[i].dx;
		uint32_t dy = RROT((g_lucks_trail_inv[i].dy ^ dx), left_rot_const); // -dy
		//		uint32_t dx = RROT(g_lucks_trail_inv[i].dx, right_rot_const);
		//		uint32_t dy = g_lucks_trail_inv[i].dy;
		uint32_t dz_max = 0;
#if 1									  // DEBUG
		printf("[%s:%d] [%d] %8X %8X\n", __FILE__, __LINE__, i, g_lucks_trail_inv[i].dx, g_lucks_trail_inv[i].dy);
#endif
		//		assert(1 == 0);
		double p_max = max_xdp_add_lm(dx, dy, &dz_max);
		double p_test = xdp_add_lm(dz_max, dy, dx);

		assert(p_test > 0.0);

		trail_inv[i].dx = LROT(dz_max, right_rot_const);
		trail_inv[i].dy = dy;
		trail_inv[i].p = p_max;
	 //	 printf("%8X %8X -> (%8X %f 2^%4.2f) (%8X %f 2^%4.2f)\n", dx, dy, dz, p, log2(p), dz_max, p_max, log2(p_max));
	 //	 trail_inv[i].p = p_max;
	 }
  }

#if 0								  // DEBUG
  printf("[%s:%d] Lucks trail AFTER:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  printf("%2d: %8X -> %8X %f\n", 0, dx_init, dy_init, 1.0);
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i+1, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG

#if 0									  // DEBUG
  speck_verify_xor_trail(NROUNDS, npairs, key, trail, dx_init, dy_init, right_rot_const, left_rot_const);
#endif  // #if 0									  // DEBUG

  printf("\n[%s:%d] --- ENCRYPT ---\n", __FILE__, __LINE__);
  speck_verify_xor_differential(NROUNDS, npairs, key, trail, dx_init, dy_init, right_rot_const, left_rot_const);

  printf("\n[%s:%d] --- DECRYPT ---\n", __FILE__, __LINE__);
  speck_verify_xor_differential_decrypt(NROUNDS, npairs, key, trail_inv, dx_init_inv, dy_init_inv, right_rot_const, left_rot_const);

#endif  // #if ((WORD_SIZE == 24) || (WORD_SIZE == 32))
}

// ----- Fixed trails used for verification purpouses -----}

void test_speck_xor_trail_search()
{
  double B[NROUNDS] = {0.0};
  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  WORD_T dx_input = 0;
  WORD_T dy_input = 0;

  uint32_t nrounds = NROUNDS;
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
 
  //  printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
#if 1
  uint32_t nrounds_full = speck_xor_trail_search(key, B, &dx_input, &dy_input, trail, nrounds);
#else
  //  uint32_t nrounds_full = speck_xor_trail_search_encrypt(key, B, &dx_input, &dy_input, trail, nrounds);
  uint32_t nrounds_full = speck_xor_trail_search_decrypt(key, B, &dx_input, &dy_input, trail, nrounds);
#endif

  printf("\n[%s:%d] End search\n", __FILE__, __LINE__);
#if 1									  // DEBUG
  printf("[%s:%d] Final bounds:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("B[%2d] = 2^%f\n", i, log2(B[i]));
  }
#endif
  double p_tot = 1.0;
#if 1									  // DEBUG
  printf("[%s:%d] Final trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
#if (WORD_SIZE <= 32) // DEBUG
  printf("%2d: %8X -> %8X %f\n", 0, dx_input, dy_input, 1.0);
#else
  printf("%2d: %16llX -> %16llX %f\n", 0, (WORD_MAX_T)dx_input, (WORD_MAX_T)dy_input, 1.0);
#endif // #if (WORD_SIZE <= 32) // DEBUG
  for(uint32_t i = 0; i < nrounds_full; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i+1, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
#else
	 printf("%2d: %16llX -> %16llX %f (2^%f)\n", i+1, (WORD_MAX_T)trail[i].dx, (WORD_MAX_T)trail[i].dy, trail[i].p, log2(trail[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG
#if 0
  differential_t round_diffs[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  round_diffs[0] = {dx_input, dy_input, 0, 1.0};

  for(uint32_t i = 0; i < nrounds_full; i++) {
	 round_diffs[i+1].dx = trail[i].dx;
	 round_diffs[i+1].dy = trail[i].dy;
	 round_diffs[i+1].p = trail[i].p;
  }

  printf("[%s:%d] key\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("key[%d] = 0x%X;\n", i, key[i]);
  }
  printf("[%s:%d] Print in LaTeX in file log.txt:\n", __FILE__, __LINE__);
  FILE* fp = fopen("log.txt", "a");
  speck_print_round_diffs_latex(fp, (nrounds_full + 1), key, round_diffs);
  fclose(fp);
#endif
}

/*
 * Search middle to top (decrypt) and middle to bottom (encrypt)
 */
void test_speck_xor_trail_search_encrypt_decrypt()
{
  uint32_t nrounds_enc = 1;//4;//13;//NROUNDS - 1;
  uint32_t nrounds_dec = 1;//10;//13;//6;//NROUNDS;
  uint32_t nrounds_full = nrounds_enc + nrounds_dec;

  assert(NROUNDS == nrounds_full);

  //  uint32_t nrounds = NROUNDS;
  double p_tot = 1.0;
  uint32_t word_size = WORD_SIZE;
  uint64_t max_cnt = SPECK_MAX_DIFF_CNT;
  double p_thres = SPECK_P_THRES;

  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz; // Dxy
  std::multiset<differential_3d_t, struct_comp_diff_3d_p> diff_mset_p;	 // Dp

  // Compute pDDT
  uint32_t hw_thres = SPECK_MAX_HW;
  speck_xdp_add_pddt(word_size, p_thres, hw_thres, max_cnt, &diff_set_dx_dy_dz, &diff_mset_p);
  assert(diff_set_dx_dy_dz.size() == diff_mset_p.size());

  // fixed middle differences
  //  const uint32_t dx_input = 0x80;
  //  const uint32_t dy_input = 0;

  // 80000000 ->        0
  // 0:     1000 ->        0 1.000000 : -64, 13R
  // 0:        0 ->      800 1.000000 : -63, 13R
  // 0: 10000000 -> 80100000          : -60, 13R, -67 14R
  // 0:  2000000 -> 10020000          : -62, 13R
  // 0:   400000 ->     4000 1.000000 : > -64
  // 0:    10000 ->    80100 // from our paper : -58, 13R; -65, 14R
  //	 const uint32_t dx_input = 0x10000;
  //	 const uint32_t dy_input = 0x80100;
  //  bool b_found = false;
  //  uint32_t N = (1UL << 12);
  //  for(uint32_t i = 0; i < N; i++) {

	 const uint32_t dx_input = 0x10000;
	 const uint32_t dy_input = 0x80100;
#if 0
	 uint32_t max_hw = 16;
	 const uint32_t dx_input = gen_sparse(max_hw, WORD_SIZE);
	 const uint32_t dy_input = gen_sparse(max_hw, WORD_SIZE);
	 if((dx_input == 0) && (dy_input == 0))
		continue;
#endif
	 // array of bounds
	 double B_enc[NROUNDS] = {0.0};
	 double B_dec[NROUNDS] = {0.0};
	 double B_full[NROUNDS + NROUNDS] = {0.0};

	 // trails
	 differential_t trail_enc[NROUNDS] = {{0, 0, 0, 0.0}};
	 differential_t trail_dec[NROUNDS] = {{0, 0, 0, 0.0}};
	 differential_t trail_full[NROUNDS + NROUNDS] = {{0, 0, 0, 0.0}};

	 printf("\n[%s:%d] --- ENCRYPT | Search ---\n", __FILE__, __LINE__);
	 speck_xor_trail_search_encrypt(key, B_enc, dx_input, dy_input, trail_enc, nrounds_enc, &diff_set_dx_dy_dz, &diff_mset_p, A);

	 printf("\n[%s:%d] --- DECRYPT | Search ---\n", __FILE__, __LINE__);
	 speck_xor_trail_search_decrypt(key, B_dec, dx_input, dy_input, trail_dec, nrounds_dec, &diff_set_dx_dy_dz, &diff_mset_p, A);

#if 1									  // DEBUG
	 printf("[%s:%d] ENCRYPT | Final bounds:\n", __FILE__, __LINE__);
	 for(uint32_t i = 0; i < nrounds_enc; i++) {
		printf("B[%2d] = 2^%f\n", i, log2(B_enc[i]));
	 }
#endif
#if 1									  // DEBUG
	 printf("\n[%s:%d] DECRYPT | Final bounds:\n", __FILE__, __LINE__);
	 for(uint32_t i = 0; i < nrounds_dec; i++) {
		printf("B[%2d] = 2^%f\n", i, log2(B_enc[i]));
	 }
#endif

#if 1									  // DEBUG
	 printf("[%s:%d] ENCRYPT | Final trail:\n", __FILE__, __LINE__);
	 p_tot = 1.0;
	 printf("%2d: %8X -> %8X %f\n", 0, dx_input, dy_input, 1.0);
	 for(uint32_t i = 0; i < nrounds_enc; i++) {
		p_tot *= trail_enc[i].p;
#if (WORD_SIZE <= 32) // DEBUG
		printf("%2d: %8X -> %8X %f (2^%2.0f) | 2^%2.0f\n", i+1, trail_enc[i].dx, trail_enc[i].dy, trail_enc[i].p, log2(trail_enc[i].p), log2(p_tot));
#else
		printf("%2d: %16llX -> %16llX %f (2^%2.0f) | 2^%2.0f\n", i+1, (WORD_MAX_T)trail_enc[i].dx, (WORD_MAX_T)trail_enc[i].dy, trail_enc[i].p, log2(trail_enc[i].p), log2(p_tot));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 }
	 printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
	 if(log2(p_tot) > -100.0) {
		//		b_found = true;
		//		printf("%f %f\n", log2(p_tot), -100.0);
	 }
#endif  // #if 0									  // DEBUG

#if 1									  // DEBUG
	 printf("[%s:%d] DECRYPT | Final trail:\n", __FILE__, __LINE__);
	 p_tot = 1.0;
	 printf("%2d: %8X -> %8X %f\n", 0, dx_input, dy_input, 1.0);
	 for(uint32_t i = 0; i < nrounds_dec; i++) {
		p_tot *= trail_dec[i].p;
#if (WORD_SIZE <= 32) // DEBUG
		printf("%2d: %8X -> %8X %f (2^%2.0f) | 2^%2.0f\n", i+1, trail_dec[i].dx, trail_dec[i].dy, trail_dec[i].p, log2(trail_dec[i].p), log2(p_tot));
#else
		printf("%2d: %16llX -> %16llX %f (2^%2.0f) | 2^%2.0f\n", i+1, (WORD_MAX_T)trail_dec[i].dx, (WORD_MAX_T)trail_dec[i].dy, trail_dec[i].p, log2(trail_dec[i].p), log2(p_tot));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 }
	 printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
	 if(log2(p_tot) > -100.0) {
		//		b_found = true;
		//		printf("%f %f\n", log2(p_tot), -100.0);
	 }
#endif  // #if 0									  // DEBUG

	 //	 sleep(5);
#if 0
	 if(b_found) {
		b_found = false;
		char enter = 0;
		printf("[%s:%d] Press ENTER to continue...\n", __FILE__, __LINE__);
		while (enter != '\r' && enter != '\n') { 
		  enter = getchar(); 
		}
	 }
#endif
	 //  } // for()

#if 1

  // construct full trail
  uint32_t dx_input_full = trail_dec[nrounds_dec - 1].dx;
  uint32_t dy_input_full = trail_dec[nrounds_dec - 1].dy;
  for(uint32_t i = 1; i < nrounds_dec; i++) { // top
	 trail_full[i - 1] = trail_dec[nrounds_dec - i - 1];
	 trail_full[i - 1].p = trail_dec[nrounds_dec - i].p;
  }
  trail_full[nrounds_dec - 1] = {dx_input, dy_input, 0, 1.0}; // middle
  trail_full[nrounds_dec - 1].p = trail_dec[0].p;
  for(uint32_t i = 0; i < nrounds_enc; i++) {					  // bottom
	 trail_full[nrounds_dec + i] = trail_enc[i];
  }

  // construct bounds for full trail
  //	 B_full[i] = B_dec[nrounds_dec - i - 1];
  //	 B_full[nrounds_dec + i] = B_enc[i];
  for(uint32_t i = 0; i < nrounds_enc; i++) {					  // bottom
	 B_full[i] = B_enc[i];
  }
  for(uint32_t i = 0; i < nrounds_dec; i++) {					  // bottom
	 B_full[nrounds_enc + i] = B_full[nrounds_enc + i - 1] * trail_dec[i].p;
  }

#if 1									  // DEBUG
  printf("\n[%s:%d] FULL | Final bounds:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("B[%2d] = 2^%f\n", i, log2(B_full[i]));
  }
#endif
#if 1									  // DEBUG
  printf("[%s:%d] FULL | Final trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  printf("%2d: %8X -> %8X %f\n", 0, dx_input_full, dy_input_full, 1.0);
  for(uint32_t i = 0; i < nrounds_full; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i+1, trail_full[i].dx, trail_full[i].dy, trail_full[i].p, log2(trail_full[i].p));
#else
	 printf("%2d: %16llX -> %16llX %f (2^%f)\n", i+1, (WORD_MAX_T)trail_full[i].dx, (WORD_MAX_T)trail_full[i].dy, trail_full[i].p, log2(trail_full[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= trail_full[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG

#if 0
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;
  uint32_t npairs = SPECK_NPAIRS;
  printf("[%s:%d] ---- FULL ---\n", __FILE__, __LINE__);
  speck_verify_xor_trail(nrounds_full, npairs, key, trail_full, dx_input_full, dy_input_full, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds_full, npairs, key, trail_full, dx_input_full, dy_input_full, right_rot_const, left_rot_const);
#endif  

  // cluster trails
#if 0
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to> trails_hash_map;
  speck_trail_cluster_search_boost(&trails_hash_map, &diff_mset_p, &diff_set_dx_dy_dz, dx_input_full, dy_input_full, B_full, trail_full, nrounds_full);
#endif

#endif  // #if 0

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

void speck_best_trails_latex_3(differential_t trail_1[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_1,
										 differential_t trail_2[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_2,
										 differential_t trail_3[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_3)
{
#if (WORD_SIZE <= 32) // DEBUG
  assert(trail_len_1 <= trail_len_2);
  assert(trail_len_2 <= trail_len_3);
  double p_1 = 1.0;
  double p_2 = 1.0;
  double p_3 = 1.0;

  uint32_t max_trail_len = trail_len_3;
  double p_diff_1 = -30;
  uint32_t ntrails_1 = 1;
  uint64_t nhways_1 = (1ULL << 30);
  double p_thres_1 = -5;
  uint32_t ntime_1 = 240;		  // minutes
  uint32_t max_hw_1 = 7;		  // bits

  double p_diff_2 = -46.48;//-43.87;
  uint32_t ntrails_2 = 384;//30;
  uint64_t nhways_2 = (1ULL << 30);
  double p_thres_2 = -5;
  uint32_t ntime_2 = 260;		  // minutes
  uint32_t max_hw_2 = 7;//8;		  // bits

  double p_diff_3 = -59.11;
  uint32_t ntrails_3 = 125;
  uint64_t nhways_3 = (1ULL << 30);
  double p_thres_3 = -5;
  uint32_t ntime_3 = 207;		  // minutes
  uint32_t max_hw_3 = 7;		  // bits

  FILE* fp = fopen(SPECK_BEST_TRAILS_LATEX_FILE, "w");
  fprintf(fp, "\\begin{table}[htp!]\n");
  fprintf(fp, "\\caption{Differential trails for \\textsc{Speck32}, \\textsc{Speck48} and \\textsc{Speck64}.}\n");
  fprintf(fp, "\\label{table:speck-trails}\n");
  fprintf(fp, "\\centering\n");
  fprintf(fp, "\\begin{tabular}{c|ccc|ccc|ccc}\n");
  fprintf(fp, "\n%%------------------------ START TABLE ---------------\n");
  fprintf(fp, "\\toprule\n");
  fprintf(fp, "  & & \\textsc{Speck32} & & ");
  fprintf(fp, "  & \\textsc{Speck48} & & ");
  fprintf(fp, "  & \\textsc{Speck64} & \\\\\n");
  fprintf(fp, "\\midrule\n");
  fprintf(fp, "$r$ & $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ & ");
  fprintf(fp, " $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ & ");
  fprintf(fp, " $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ \\\\\n");
  fprintf(fp, "\\midrule\n");
  for(uint32_t i = 0; i < max_trail_len; i++) {
	 if(i < trail_len_1) {
		if(trail_1[i].p != 1.0) {
		  fprintf(fp, "$%2d$ & \\texttt{%X} & \\texttt{%X} & $%2.0f$ & ", i, trail_1[i].dx, trail_1[i].dy, log2(trail_1[i].p));
		} else {
		  fprintf(fp, "$%2d$ & \\texttt{%X} & \\texttt{%X} & $-%2.0f$ & ", i, trail_1[i].dx, trail_1[i].dy, log2(trail_1[i].p));
		}
		p_1 *= trail_1[i].p;
	 } else {
		fprintf(fp, "$%2d$ & & & & ", i);
	 }
	 if(i < trail_len_2) {
		if(trail_2[i].p != 1.0) {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $%2.0f$ & ", trail_2[i].dx, trail_2[i].dy, log2(trail_2[i].p));
		} else {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $-%2.0f$ & ", trail_2[i].dx, trail_2[i].dy, log2(trail_2[i].p));
		}
		p_2 *= trail_2[i].p;
	 } else {
		fprintf(fp, " & & & ");
	 }
	 if(i < trail_len_3) {
		if(trail_3[i].p != 1.0) {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $%2.0f$ \\\\\n", trail_3[i].dx, trail_3[i].dy, log2(trail_3[i].p));
		} else {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $-%2.0f$ \\\\\n", trail_3[i].dx, trail_3[i].dy, log2(trail_3[i].p));
		}
		p_3 *= trail_3[i].p;
	 } else {
		fprintf(fp, " & & \\\\\n");
	 }
  }
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\sum_{r}\\mathrm{log}_2 p_r$ & & & $%2.0f$ &", log2(p_1));
  fprintf(fp, " & & $%2.0f$ &", log2(p_2));
  fprintf(fp, " & & $%2.0f$ \\\\\n", log2(p_3));

  fprintf(fp, " $\\mathrm{log}_2 p_{\\mathrm{diff}}$ & & & $%4.2f$ &", p_diff_1);
  fprintf(fp, " & & $%4.2f$ &", p_diff_2);
  fprintf(fp, " & & $%4.2f$ \\\\\n", p_diff_3);

  fprintf(fp, " $\\#{\\mathrm{trails}}$ & & & $%d$ &", ntrails_1);
  fprintf(fp, " & & $%d$ &", ntrails_2);
  fprintf(fp, " & & $%d$ \\\\\n", ntrails_3);

  fprintf(fp, "max HW & & & $%d$ &", max_hw_1);
  fprintf(fp, " & & $%d$ &", max_hw_2);
  fprintf(fp, " & & $%d$ \\\\\n", max_hw_3);

  fprintf(fp, "\\midrule\n");

  fprintf(fp, " $\\mathrm{log}_2 p_{\\mathrm{thres}}$ & & & $%4.2f$ &", p_thres_1);
  fprintf(fp, " & & $%4.2f$ &", p_thres_2);
  fprintf(fp, " & & $%4.2f$ \\\\\n", p_thres_3);

  fprintf(fp, " $\{\\mathrm{pDDT}}$ & & & $2^{%2.0f}$ &", log2(nhways_1));
  fprintf(fp, " & & $2^{%2.0f}$ &", log2(nhways_2));
  fprintf(fp, " & & $2^{%2.0f}$ \\\\\n", log2(nhways_3));

  fprintf(fp, " Time: & & & $\\approx %d$ min. &", ntime_1);
  fprintf(fp, " & & $\\approx %d$ min. &", ntime_2);
  fprintf(fp, " & & $\\approx %d$ min. \\\\\n", ntime_3);

  fprintf(fp, "\\bottomrule\n");

  fprintf(fp, "%%------------------------ END TABLE ---------------\n");
  fprintf(fp, "\\end{tabular}\n");
  fprintf(fp, "\\end{table}\n");
  fclose(fp);

#endif // #if (WORD_SIZE <= 32) // DEBUG
}

void test_speck_best_trails_latex_3()
{
#if (WORD_SIZE <= 32) // DEBUG
  assert(SPECK_TRAIL_LEN_MAX >= NROUNDS);

  uint32_t nrounds = 0;
  double p_tot = 1.0;

  nrounds = g_nrounds_n16_best;
  differential_t speck32_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck32_dx_input = g_trail_n16_best[0].dx;
  uint32_t speck32_dy_input = g_trail_n16_best[0].dy;

  for(uint32_t i = 0; i < g_nrounds_n16_best; i++) {
	 speck32_trail[i] = g_trail_n16_best[i+1];
  }

  nrounds = g_nrounds_n24_best;
  differential_t speck48_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck48_dx_input = g_trail_n24_best[0].dx;
  uint32_t speck48_dy_input = g_trail_n24_best[0].dy;
  for(uint32_t i = 0; i < nrounds; i++) {
	 speck48_trail[i] = g_trail_n24_best[i+1];
  }

  nrounds = g_nrounds_n32_best;
  differential_t speck64_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck64_dx_input = g_trail_n32_best[0].dx;
  uint32_t speck64_dy_input = g_trail_n32_best[0].dy;
  for(uint32_t i = 0; i < nrounds; i++) {
	 speck64_trail[i] = g_trail_n32_best[i+1];
  }

#if 0									  // verify trails
  uint32_t npairs = SPECK_NPAIRS;
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;

  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

#if(WORD_SIZE == 16)									  // DEBUG
  nrounds = g_nrounds_n16_best;
  uint32_t right_rot_const_16bits = SPECK_RIGHT_ROT_CONST_16BITS; 
  uint32_t left_rot_const_16bits = SPECK_LEFT_ROT_CONST_16BITS;
  speck_verify_xor_trail(nrounds, npairs, key, speck32_trail, speck32_dx_input, speck32_dy_input, right_rot_const_16bits, left_rot_const_16bits);
  speck_verify_xor_differential(nrounds, npairs, key, speck32_trail, speck32_dx_input, speck32_dy_input, right_rot_const_16bits, left_rot_const_16bits);

#elif(WORD_SIZE == 24)									  // DEBUG
  nrounds = g_nrounds_n24_best;
  speck_verify_xor_trail(nrounds, npairs, key, speck48_trail, speck48_dx_input, speck48_dy_input, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds, npairs, key, speck48_trail, speck48_dx_input, speck48_dy_input, right_rot_const, left_rot_const);

#elif(WORD_SIZE == 32)									  // DEBUG
  nrounds = g_nrounds_n32_best;
  speck_verify_xor_trail(nrounds, npairs, key, speck64_trail, speck64_dx_input, speck64_dy_input, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds, npairs, key, speck64_trail, speck64_dx_input, speck64_dy_input, right_rot_const, left_rot_const);
#endif   // #if(WORD_SIZE == 16)									  // DEBUG
#endif //#if 0									  // verify trails

  //#endif  // #if 0									  // verify trails
  nrounds = g_nrounds_n16_best;
  p_tot = 1.0;
  printf("Input diffs: %8X %8X\n", speck32_dx_input, speck32_dy_input);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck32_trail[i].dx, speck32_trail[i].dy, log2(speck32_trail[i].p));
	 p_tot *= speck32_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

  nrounds = g_nrounds_n24_best;
  p_tot = 1.0;
  printf("\nInput diffs: %8X %8X\n", speck48_dx_input, speck48_dy_input);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck48_trail[i].dx, speck48_trail[i].dy, log2(speck48_trail[i].p));
	 p_tot *= speck48_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

  nrounds = g_nrounds_n32_best;
  printf("\nInput diffs: %8X %8X\n", speck64_dx_input, speck64_dy_input);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck64_trail[i].dx, speck64_trail[i].dy, log2(speck64_trail[i].p));
	 p_tot *= speck64_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

#if 1									  // three trails
  uint32_t speck32_len = g_nrounds_n16_best + 1;
  uint32_t speck48_len = g_nrounds_n24_best + 1;
  uint32_t speck64_len = g_nrounds_n32_best + 1;

  speck_best_trails_latex_3(g_trail_n16_best, speck32_len, g_trail_n24_best, speck48_len, g_trail_n32_best, speck64_len);
#endif  // #if 0

#endif // #if (WORD_SIZE <= 32) // DEBUG
}

void speck_best_trails_latex_4(differential_t trail_1[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_1,
										 differential_t trail_2[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_2,
										 differential_t trail_3[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_3,
										 differential_t trail_4[SPECK_TRAIL_LEN_MAX], uint32_t trail_len_4)
{
#if (WORD_SIZE <= 32) // DEBUG
  assert(trail_len_1 <= trail_len_2);
  assert(trail_len_2 <= trail_len_3);
  double p_1 = 1.0;
  double p_2 = 1.0;
  double p_3 = 1.0;
  double p_4 = 1.0;

  assert(trail_len_3 == 14);
  assert(trail_len_4 == 15);

  uint32_t max_trail_len = trail_len_4;
  double p_diff_1 = -30;
  uint32_t ntrails_1 = 1;
  uint64_t nhways_1 = (1ULL << 30);
  double p_thres_1 = -5;
  uint32_t ntime_1 = 240;		  // minutes
  uint32_t max_hw_1 = 7;		  // bits

  double p_diff_2 = -46.48;//-43.87;
  uint32_t ntrails_2 = 384;//30;
  uint64_t nhways_2 = (1ULL << 30);
  double p_thres_2 = -5;
  uint32_t ntime_2 = 260;		  // minutes
  uint32_t max_hw_2 = 7;//8;		  // bits

  double p_diff_3 = -57.70;
  uint32_t ntrails_3 = 48;
  uint64_t nhways_3 = (1ULL << 30);
  double p_thres_3 = -5;
  uint32_t ntime_3 = 200;		  // minutes
  uint32_t max_hw_3 = 7;		  // bits

  double p_diff_4 = -59.11;
  uint32_t ntrails_4 = 125;
  uint64_t nhways_4 = (1ULL << 30);
  double p_thres_4 = -5;
  uint32_t ntime_4 = 207;		  // minutes
  uint32_t max_hw_4 = 7;		  // bits

  FILE* fp = fopen(SPECK_BEST_TRAILS_LATEX_FILE, "w");
  fprintf(fp, "\\begin{table}[htp!]\n");
  fprintf(fp, "\\caption{Differential trails for \\textsc{Speck32}, \\textsc{Speck48} and \\textsc{Speck64}.}\n");
  fprintf(fp, "\\label{table:speck-trails}\n");
  fprintf(fp, "\\centering\n");
  fprintf(fp, "\\begin{tabular}{c|ccc|ccc|ccc|ccc}\n");
  fprintf(fp, "\n%%------------------------ START TABLE ---------------\n");
  fprintf(fp, "\\toprule\n");
  fprintf(fp, "  & & \\textsc{Speck32} & & ");
  fprintf(fp, "  & \\textsc{Speck48} & & ");
  fprintf(fp, "  & \\textsc{Speck64} & & ");
  fprintf(fp, "  & \\textsc{Speck64} & \\\\\n");
  fprintf(fp, "\\midrule\n");
  fprintf(fp, "$r$ & $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ & ");
  fprintf(fp, " $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ & ");
  fprintf(fp, " $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ & ");
  fprintf(fp, " $\\Delta_{\\mathrm{L}}$ & $\\Delta_{\\mathrm{R}}$ & $\\mathrm{log}_2 p$ \\\\\n");
  fprintf(fp, "\\midrule\n");
  for(uint32_t i = 0; i < max_trail_len; i++) {
	 if(i < trail_len_1) {
		if(trail_1[i].p != 1.0) {
		  fprintf(fp, "$%2d$ & \\texttt{%X} & \\texttt{%X} & $%2.0f$ & ", i, trail_1[i].dx, trail_1[i].dy, log2(trail_1[i].p));
		} else {
		  fprintf(fp, "$%2d$ & \\texttt{%X} & \\texttt{%X} & $-%2.0f$ & ", i, trail_1[i].dx, trail_1[i].dy, log2(trail_1[i].p));
		}
		p_1 *= trail_1[i].p;
	 } else {
		fprintf(fp, "$%2d$ & & & & ", i);
	 }
	 if(i < trail_len_2) {
		if(trail_2[i].p != 1.0) {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $%2.0f$ & ", trail_2[i].dx, trail_2[i].dy, log2(trail_2[i].p));
		} else {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $-%2.0f$ & ", trail_2[i].dx, trail_2[i].dy, log2(trail_2[i].p));
		}
		p_2 *= trail_2[i].p;
	 } else {
		fprintf(fp, " & & & ");
	 }
	 if(i < trail_len_3) {
		if(trail_3[i].p != 1.0) {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $%2.0f$ & ", trail_3[i].dx, trail_3[i].dy, log2(trail_3[i].p));
		} else {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $-%2.0f$ & ", trail_3[i].dx, trail_3[i].dy, log2(trail_3[i].p));
		}
		p_3 *= trail_3[i].p;
	 } else {
		fprintf(fp, " & & & ");
	 }
	 if(i < trail_len_4) {
		if(trail_4[i].p != 1.0) {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $%2.0f$ \\\\\n", trail_4[i].dx, trail_4[i].dy, log2(trail_4[i].p));
		} else {
		  fprintf(fp, "\\texttt{%X} & \\texttt{%X} & $-%2.0f$ \\\\\n", trail_4[i].dx, trail_4[i].dy, log2(trail_4[i].p));
		}
		p_4 *= trail_4[i].p;
	 } else {
		fprintf(fp, " & & \\\\\n");
	 }
  }
  fprintf(fp, "\\midrule\n");
  fprintf(fp, " $\\sum_{r}\\mathrm{log}_2 p_r$ & & & $%2.0f$ &", log2(p_1));
  fprintf(fp, " & & $%2.0f$ &", log2(p_2));
  fprintf(fp, " & & $%2.0f$ &", log2(p_3));
  fprintf(fp, " & & $%2.0f$ \\\\\n", log2(p_4));

  fprintf(fp, " $\\mathrm{log}_2 p_{\\mathrm{diff}}$ & & & $%4.2f$ &", p_diff_1);
  fprintf(fp, " & & $%4.2f$ &", p_diff_2);
  fprintf(fp, " & & $%4.2f$ &", p_diff_3);
  fprintf(fp, " & & $%4.2f$ \\\\\n", p_diff_4);

  fprintf(fp, " $\\#{\\mathrm{trails}}$ & & & $%d$ &", ntrails_1);
  fprintf(fp, " & & $%d$ &", ntrails_2);
  fprintf(fp, " & & $%d$ &", ntrails_3);
  fprintf(fp, " & & $%d$ \\\\\n", ntrails_4);

  fprintf(fp, "max HW & & & $%d$ &", max_hw_1);
  fprintf(fp, " & & $%d$ &", max_hw_2);
  fprintf(fp, " & & $%d$ &", max_hw_3);
  fprintf(fp, " & & $%d$ \\\\\n", max_hw_4);

  fprintf(fp, "\\midrule\n");

  fprintf(fp, " $\\mathrm{log}_2 p_{\\mathrm{thres}}$ & & & $%4.2f$ &", p_thres_1);
  fprintf(fp, " & & $%4.2f$ &", p_thres_2);
  fprintf(fp, " & & $%4.2f$ &", p_thres_3);
  fprintf(fp, " & & $%4.2f$ \\\\\n", p_thres_4);

  fprintf(fp, " $\{\\mathrm{pDDT}}$ & & & $2^{%2.0f}$ &", log2(nhways_1));
  fprintf(fp, " & & $2^{%2.0f}$ &", log2(nhways_2));
  fprintf(fp, " & & $2^{%2.0f}$ &", log2(nhways_3));
  fprintf(fp, " & & $2^{%2.0f}$ \\\\\n", log2(nhways_4));

  fprintf(fp, " Time: & & & $\\approx %d$ min. &", ntime_1);
  fprintf(fp, " & & $\\approx %d$ min. &", ntime_2);
  fprintf(fp, " & & $\\approx %d$ min. &", ntime_3);
  fprintf(fp, " & & $\\approx %d$ min. \\\\\n", ntime_4);

  fprintf(fp, "\\bottomrule\n");

  fprintf(fp, "%%------------------------ END TABLE ---------------\n");
  fprintf(fp, "\\end{tabular}\n");
  fprintf(fp, "\\end{table}\n");
  fclose(fp);
#endif // #if (WORD_SIZE <= 32) // DEBUG
}
 
void test_speck_best_trails_latex_4()
{
  assert(SPECK_TRAIL_LEN_MAX >= NROUNDS);

  uint32_t nrounds = 0;
  double p_tot = 1.0;

  nrounds = g_nrounds_n16_best;
  differential_t speck32_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck32_dx_input = g_trail_n16_best[0].dx;
  uint32_t speck32_dy_input = g_trail_n16_best[0].dy;

  for(uint32_t i = 0; i < g_nrounds_n16_best; i++) {
	 speck32_trail[i] = g_trail_n16_best[i+1];
  }

  nrounds = g_nrounds_n24_best;
  differential_t speck48_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck48_dx_input = g_trail_n24_best[0].dx;
  uint32_t speck48_dy_input = g_trail_n24_best[0].dy;
  for(uint32_t i = 0; i < nrounds; i++) {
	 speck48_trail[i] = g_trail_n24_best[i+1];
  }

  nrounds = g_nrounds_n32_best_old;
  differential_t speck64_trail_old[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck64_dx_input_old = g_trail_n32_best_old[0].dx;
  uint32_t speck64_dy_input_old = g_trail_n32_best_old[0].dy;
  for(uint32_t i = 0; i < nrounds; i++) {
	 speck64_trail_old[i] = g_trail_n32_best_old[i+1];
  }

  nrounds = g_nrounds_n32_best;
  differential_t speck64_trail[SPECK_TRAIL_LEN_MAX] = {{0, 0, 0, 0.0}};
  uint32_t speck64_dx_input = g_trail_n32_best[0].dx;
  uint32_t speck64_dy_input = g_trail_n32_best[0].dy;
  for(uint32_t i = 0; i < nrounds; i++) {
	 speck64_trail[i] = g_trail_n32_best[i+1];
  }

#if 0									  // verify trails
  uint32_t npairs = SPECK_NPAIRS;
  uint32_t right_rot_const = SPECK_RIGHT_ROT_CONST; 
  uint32_t left_rot_const = SPECK_LEFT_ROT_CONST;

  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

#if(WORD_SIZE == 16)									  // DEBUG
  nrounds = g_nrounds_n16_best;
  uint32_t right_rot_const_16bits = SPECK_RIGHT_ROT_CONST_16BITS; 
  uint32_t left_rot_const_16bits = SPECK_LEFT_ROT_CONST_16BITS;
  speck_verify_xor_trail(nrounds, npairs, key, speck32_trail, speck32_dx_input, speck32_dy_input, right_rot_const_16bits, left_rot_const_16bits);
  speck_verify_xor_differential(nrounds, npairs, key, speck32_trail, speck32_dx_input, speck32_dy_input, right_rot_const_16bits, left_rot_const_16bits);

#elif(WORD_SIZE == 24)									  // DEBUG
  nrounds = g_nrounds_n24_best;
  speck_verify_xor_trail(nrounds, npairs, key, speck48_trail, speck48_dx_input, speck48_dy_input, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds, npairs, key, speck48_trail, speck48_dx_input, speck48_dy_input, right_rot_const, left_rot_const);

#elif(WORD_SIZE == 32)									  // DEBUG
  // best old trail
  nrounds = g_nrounds_n32_best_old;
  speck_verify_xor_trail(nrounds, npairs, key, speck64_trail_old, speck64_dx_input_old, speck64_dy_input_old, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds, npairs, key, speck64_trail_old, speck64_dx_input_old, speck64_dy_input_old, right_rot_const, left_rot_const);
  // best trail
  nrounds = g_nrounds_n32_best;
  speck_verify_xor_trail(nrounds, npairs, key, speck64_trail, speck64_dx_input, speck64_dy_input, right_rot_const, left_rot_const);
  speck_verify_xor_differential(nrounds, npairs, key, speck64_trail, speck64_dx_input, speck64_dy_input, right_rot_const, left_rot_const);
#endif   // #if(WORD_SIZE == 16)									  // DEBUG
#endif //#if 0									  // verify trails

  //#endif  // #if 0									  // verify trails
  nrounds = g_nrounds_n16_best;
  p_tot = 1.0;
  printf("Input diffs: %8X %8X\n", speck32_dx_input, speck32_dy_input);
  for(uint32_t i = 0; i < nrounds; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck32_trail[i].dx, speck32_trail[i].dy, log2(speck32_trail[i].p));
#else
	 printf("%2d: %16llX %16llX 2^%f\n", i+1, (WORD_MAX_T)speck32_trail[i].dx, (WORD_MAX_T)speck32_trail[i].dy, log2(speck32_trail[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= speck32_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

  nrounds = g_nrounds_n24_best;
  p_tot = 1.0;
  printf("\nInput diffs: %8X %8X\n", speck48_dx_input, speck48_dy_input);
  for(uint32_t i = 0; i < nrounds; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck48_trail[i].dx, speck48_trail[i].dy, log2(speck48_trail[i].p));
#else
	 printf("%2d: %16llX %16llX 2^%f\n", i+1, (WORD_MAX_T)speck48_trail[i].dx, (WORD_MAX_T)speck48_trail[i].dy, log2(speck48_trail[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= speck48_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

  nrounds = g_nrounds_n32_best_old;
  printf("\nInput diffs: %8X %8X\n", speck64_dx_input_old, speck64_dy_input_old);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck64_trail_old[i].dx, speck64_trail_old[i].dy, log2(speck64_trail_old[i].p));
#else
	 printf("%2d: %16llX %16llX 2^%f\n", i+1, (WORD_MAX_T)speck64_trail_old[i].dx, (WORD_MAX_T)speck64_trail_old[i].dy, log2(speck64_trail_old[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= speck64_trail_old[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

  nrounds = g_nrounds_n32_best;
  printf("\nInput diffs: %8X %8X\n", speck64_dx_input, speck64_dy_input);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {
#if (WORD_SIZE <= 32) // DEBUG
	 printf("%2d: %8X %8X 2^%f\n", i+1, speck64_trail[i].dx, speck64_trail[i].dy, log2(speck64_trail[i].p));
#else
	 printf("%2d: %16llX %16llX 2^%f\n", i+1, (WORD_MAX_T)speck64_trail[i].dx, (WORD_MAX_T)speck64_trail[i].dy, log2(speck64_trail[i].p));
#endif // #if (WORD_SIZE <= 32) // DEBUG
	 p_tot *= speck64_trail[i].p;
  }
  printf("p_tot 2^%f\n", log2(p_tot));

#if 1									  // four trails
  uint32_t speck32_len = g_nrounds_n16_best + 1;
  uint32_t speck48_len = g_nrounds_n24_best + 1;
  uint32_t speck64_len_old = g_nrounds_n32_best_old + 1;
  uint32_t speck64_len = g_nrounds_n32_best + 1;

  assert(speck64_len_old == 14);
  assert(speck64_len == 15);

  speck_best_trails_latex_4(g_trail_n16_best, speck32_len, g_trail_n24_best, speck48_len, g_trail_n32_best_old, speck64_len_old, g_trail_n32_best, speck64_len);
#endif  // #if 0
}

/**
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));

  time_t rawtime;
  time(&rawtime);

  FILE* fp = fopen(SPECK_LOG_FILE, "w");
  fprintf(fp, "\nTime: %s", ctime (&rawtime));

  printf("[%s:%d] WORD_SIZE %d NROUNDS %d SPECK_P_THRES %f 2^%f SPECK_MAX_DIFF_CNT %lld 2^%4.2f SPECK_BACK_TO_HWAY %d SPECK_GREEDY_SEARCH %d SPECK_MAX_HW %d  SPECK_CLUSTER_MAX_HW %d SPECK_EPS 2^%4.2f\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS, SPECK_P_THRES, log2(SPECK_P_THRES), SPECK_MAX_DIFF_CNT, log2(SPECK_MAX_DIFF_CNT), SPECK_BACK_TO_HWAY, SPECK_GREEDY_SEARCH, SPECK_MAX_HW, SPECK_CLUSTER_MAX_HW, log2(SPECK_EPS));
  fprintf(fp, "[%s:%d] WORD_SIZE %d NROUNDS %d SPECK_P_THRES %f 2^%f SPECK_MAX_DIFF_CNT %lld 2^%4.2f SPECK_BACK_TO_HWAY %d SPECK_GREEDY_SEARCH %d SPECK_MAX_HW %d  SPECK_CLUSTER_MAX_HW %d SPECK_EPS 2^%4.2f\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS, SPECK_P_THRES, log2(SPECK_P_THRES), SPECK_MAX_DIFF_CNT, log2(SPECK_MAX_DIFF_CNT), SPECK_BACK_TO_HWAY, SPECK_GREEDY_SEARCH, SPECK_MAX_HW, SPECK_CLUSTER_MAX_HW, log2(SPECK_EPS));
  fclose(fp);

  //  test_speck_best_trails_latex_3(); // three trails
  //  test_speck_best_trails_latex_4(); // four trails
  //  test_verify_lucks_trail(); // check trails by Lucks et al.
  //  test_speck_cluster_trails(); // cluster trails starting from a fixed trail
  test_speck_xor_trail_search(); // threshold search
  //  test_speck_xor_trail_search_encrypt_decrypt(); // threshold search from the middle to top and from middle to bottom

  printf("\n[%s:%d] WORD_SIZE %d NROUNDS %d SPECK_P_THRES %f 2^%f SPECK_MAX_DIFF_CNT %lld 2^%4.2f SPECK_BACK_TO_HWAY %d SPECK_GREEDY_SEARCH %d SPECK_MAX_HW %d  SPECK_CLUSTER_MAX_HW %d SPECK_EPS 2^%4.2f\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS, SPECK_P_THRES, log2(SPECK_P_THRES), SPECK_MAX_DIFF_CNT, log2(SPECK_MAX_DIFF_CNT), SPECK_BACK_TO_HWAY, SPECK_GREEDY_SEARCH, SPECK_MAX_HW, SPECK_CLUSTER_MAX_HW, log2(SPECK_EPS));
  return 0;
}
