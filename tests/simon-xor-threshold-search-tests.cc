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
 * \file  simon-xor-threshold-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for automatic search for XOR differentials in block cipher Simon.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif
#ifndef XDP_ROT_AND_H
#include "xdp-rot-and.hh"
#endif
#ifndef SIMON_H
#include "simon.hh"
#endif
#ifndef SIMON_XOR_THRESHOLD_SEARCH_H
#include "simon-xor-threshold-search.hh"
#endif
#ifndef SIMON_XOR_DDT_SEARCH_H
#include "simon-xor-ddt-search.hh"
#endif
#ifndef SIMON_XOR_BEST_TRAILS_H
#include "simon-xor-best-trails.hh"
#endif

#define SIMON_DDT_FILE_NAME "ddt.txt"
#define SIMON_LOG_FILE_NAME "simon.log"

/*
Actual best trail on n = 16 bits using full DDT search, memory ~224 GB RAM, time: real  714m28.825s ~= 12 hours

B[ 0] = 2^0.000000
B[ 1] = 2^-4.000000
B[ 2] = 2^-4.000000
B[ 3] = 2^-6.000000
B[ 4] = 2^-8.000000
B[ 5] = 2^-12.000000
B[ 6] = 2^-14.000000
B[ 7] = 2^-18.000000
B[ 8] = 2^-20.000000
B[ 9] = 2^-25.000000
B[10] = 2^-30.000000
0:     A000 ->     8002 0.125000 (2^-3.000000)
1:     2200 ->     2800 0.062500 (2^-4.000000)
2:     2800 ->     8200 0.125000 (2^-3.000000)
3:     8200 ->     2080 0.062500 (2^-4.000000)
4:     2080 ->       20 0.062500 (2^-4.000000)
5:       20 ->        0 0.250000 (2^-2.000000)
6:        0 ->       20 1.000000 (2^0.000000)
7:       20 ->       80 0.250000 (2^-2.000000)
8:       80 ->      220 0.250000 (2^-2.000000)
9:      220 ->      800 0.062500 (2^-4.000000)
10:      800 ->     2220 0.250000 (2^-2.000000)
p_tot = 0.000000000931323 = 2^-30.000000, Bn = 0.000000 = 2^-30.000000
*/
uint32_t g_best_trail_n16_len = 11;

differential_t g_best_trail_n16[11] = {
  {0xA000, 0x8002, 0, 0.125000},
  {0x2200, 0x2800, 0, 0.062500},
  {0x2800, 0x8200, 0, 0.125000},
  {0x8200, 0x2080, 0, 0.062500},
  {0x2080,   0x20, 0, 0.062500},
  {  0x20,    0x0, 0, 0.250000},
  {   0x0,   0x20, 0, 1.000000},
  {  0x20,   0x80, 0, 0.250000},
  {  0x80,  0x220, 0, 0.250000},
  { 0x220,  0x800, 0, 0.062500},
  { 0x800, 0x2220, 0, 0.250000}
};

void test_best_trail_n16()
{
  //  double B[NROUNDS] = {0.0};
  //  uint32_t nrounds = NROUNDS;

  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};

  uint32_t nrounds_full = g_best_trail_n16_len;//simon_xor_ddt_trail_search(key, B, trail, nrounds);

  for(uint32_t i = 0; i < g_best_trail_n16_len; i++) {
	 trail[i].dx = g_best_trail_n16[i].dx;
	 trail[i].dy = g_best_trail_n16[i].dy;
	 trail[i].p = g_best_trail_n16[i].p;
  }

  printf("[%s:%d] \n----- End search -----\n", __FILE__, __LINE__);
  double p_tot = 1.0;
#if 0									  // DEBUG
  printf("[%s:%d] Final trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG
#if 1									  // print round diffs
  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  differential_t round_diffs[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(trail, round_diffs, nrounds_full, lrot_const_s, lrot_const_t, lrot_const_u);

  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds_full + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p, log2(round_diffs[i].p));
	 p_tot *= round_diffs[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif
#if 1
  printf("[%s:%d] key\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("key[%d] = 0x%X;\n", i, key[i]);
  }
  printf("[%s:%s():%d] Print in LaTeX in file log.txt:\n", __FILE__, __FUNCTION__, __LINE__);
  FILE* fp = fopen("log.txt", "a");
  simon_print_round_diffs_latex(fp, (nrounds_full + 1), key, round_diffs);
  fclose(fp);
#endif
}

void test_simon_xor_ddt_trail_search()
{
#if(WORD_SIZE <= 16)
  double B[NROUNDS] = {0.0};
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  uint32_t nrounds = NROUNDS;
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};

  uint32_t nrounds_full = simon_xor_ddt_trail_search(key, B, trail, nrounds);

  printf("[%s:%d] \n----- End search -----\n", __FILE__, __LINE__);
  double p_tot = 1.0;
#if 0									  // DEBUG
  printf("[%s:%d] Final trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG
#if 1									  // DEBUG
  printf("[%s:%d] Final bounds:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds_full; i++) {
	 printf("B[%2d] = 2^%f\n", i, log2(B[i]));
  }
#endif
#if 1									  // print round diffs
  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  differential_t round_diffs[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(trail, round_diffs, nrounds_full, lrot_const_s, lrot_const_t, lrot_const_u);

  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds_full + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p, log2(round_diffs[i].p));
	 p_tot *= round_diffs[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif
#if 1
  printf("[%s:%d] key\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("key[%d] = 0x%X;\n", i, key[i]);
  }
  printf("[%s:%s():%d] Print in LaTeX in file log.txt:\n", __FILE__, __FUNCTION__, __LINE__);
  FILE* fp = fopen("log.txt", "a");
  simon_print_round_diffs_latex(fp, (nrounds_full + 1), key, round_diffs);
  fclose(fp);
#endif
#endif  // #if(WORD_SIZE <= 16)
}

/*
B[ 1] = 2^-4.000000
B[ 2] = 2^-4.000000
B[ 3] = 2^-6.000000
B[ 4] = 2^-8.000000
B[ 5] = 2^-12.000000
B[ 6] = 2^-14.000000
B[ 7] = 2^-18.000000
B[ 8] = 2^-24.000000
B[ 9] = 2^-28.000000
B[10] = 2^-30.000000
B[11] = 2^-36.000000
 0:     8808 ->     2022 0.015625 (2^-6.000000)
 1:        2 ->     8800 0.250000 (2^-2.000000)
 2:     8800 ->     2000 0.062500 (2^-4.000000)
 3:     2000 ->      800 0.250000 (2^-2.000000)
 4:      800 ->        0 0.250000 (2^-2.000000)
 5:        0 ->      800 1.000000 (2^0.000000)
 6:      800 ->     2000 0.250000 (2^-2.000000)
 7:     2000 ->     8800 0.250000 (2^-2.000000)
 8:     8800 ->        2 0.062500 (2^-4.000000)
 9:        2 ->     8808 0.250000 (2^-2.000000)
10:     8808 ->     2020 0.015625 (2^-6.000000)
11:     2020 ->      888 0.062500 (2^-4.000000)
p_tot = 0.000000000014552 = 2^-36.000000, Bn = 0.000000 = 2^-36.000000
*/

void test_simon_xor_trail_search()
{
  double B[NROUNDS] = {0.0};
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  //  uint32_t nrounds = NROUNDS;
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
  uint32_t trail_len = 0;
  //  std::unordered_map<std::string, differential_t**> trails_hash_map;

  //  uint32_t nrounds_full = 
  simon_xor_trail_search(key, B, trail, &trail_len);

  double p_tot = 1.0;

#if 1									  // DEBUG
  printf("[%s:%d] Final best trail:\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
	 p_tot *= trail[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif  // #if 0									  // DEBUG


#if 1									  // DEBUG
  printf("[%s:%d] Final bounds %dR:\n", __FILE__, __LINE__, NROUNDS);
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 printf("B[%2d] = 2^%f\n", i, log2(B[i]));
  }
#endif

#if 0
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map;
  uint32_t dyy_init = 0;
  printf("[%s:%d] \n----- Begin cluster algoritm 2 -----\n", __FILE__, __LINE__);
  //  simon_trail_cluster_search(&trails_hash_map, B, trail, NROUNDS, &dyy_init);
  simon_trail_cluster_search_boost(&trails_hash_map, B, trail, NROUNDS, &dyy_init);
  printf("[%s:%d] \n----- End cluster algorithm 2 -----\n", __FILE__, __LINE__);

  //  simon_print_hash_table(trails_hash_map, nrounds_full);
  simon_boost_print_hash_table(trails_hash_map, nrounds_full);

  p_tot = 1.0;

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
#endif

#if 0									  // verify probabilities of trail
  uint32_t npairs = SIMON_NPAIRS;

  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map.begin();
  uint32_t trail_cnt = 0;
  uint32_t num_rounds = len;
  while(hash_map_iter != trails_hash_map.end()) {
	 double p_tot = 1.0;
	 trail_cnt++;
	 differential_t trail[NROUNDS] = {{0,0,0,0.0}};
	 //	 uint32_t dyy_init = (*(hash_map_iter->second))[0].dy;
	 printf("[%5d] ", trail_cnt);
	 for(uint32_t i = 0; i < len; i++) {
		uint32_t dx = (*(hash_map_iter->second))[i].dx;
		uint32_t dy = (*(hash_map_iter->second))[i].dy;
		double p = (*(hash_map_iter->second))[i].p;
		if(i == 0) {
		  //		  uint32_t dxx = (*(hash_map_iter->second))[i+1].dx;
		  //		  dy = dy ^ dyy_init;
		}
		trail[i] = {dx, dy, 0, p};
		p_tot *= p;
		printf("%4X  %4X ", dx, dy);
	 }
	 printf(" | 2^%f\n", log2(p_tot));

	 //	 uint32_t temp_dyy = ;
	 simon_verify_xor_trail(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
	 simon_verify_xor_differential(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);

	 hash_map_iter++;
  }
#endif

#if 0									  // print round diffs
  differential_t round_diffs[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(trail, round_diffs, NROUNDS, lrot_const_s, lrot_const_t, lrot_const_u);

  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (NROUNDS + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p, log2(round_diffs[i].p));
	 p_tot *= round_diffs[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif
#if 0									  // print in LaTeX
  printf("[%s:%d] key\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < 4; i++) {
	 printf("key[%d] = 0x%X;\n", i, key[i]);
  }
  printf("[%s:%s():%d] LaTeX trail stored in log.txt:\n", __FILE__, __FUNCTION__, __LINE__);
  FILE* fp = fopen("log.txt", "a");
  simon_print_round_diffs_latex(fp, (NROUNDS + 1), key, round_diffs);
  fclose(fp);
#endif
}

void test_simon_cluster_trails()
{
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  double p_thres = XDP_ROT_AND_P_THRES;
  uint32_t npairs = SIMON_NPAIRS;
  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp
  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p;	 // Dp
  uint64_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
  xdp_rot_and_pddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, max_cnt, p_thres);

  uint32_t num_rounds = 4;//NROUNDS;
#if 0									  // Abed at al.
  differential_t trail[4] = {
	 {0x1100, 0x4000, 0, 1.000000},
	 {0x0400, 0x1100, 0, 0.062500}, // -4
	 {0x0100, 0x0400, 0, 0.250000}, // -2
	 {     0, 0x0100, 0, 0.250000}  // -2
  };
  uint32_t dyy_init = 0;//
#endif
#if 0									  // my not OK
  differential_t trail[4] = {
	 {0x8800,    0x2, 0, 1.000000},
	 {0x2000, 0x8800, 0, 0.062500}, // -4
	 {0x0800, 0x2000, 0, 0.250000}, // -2
	 {     0, 0x0800, 0, 0.250000}  // -2
  };
  uint32_t dyy_init = 0x8808;// ^ LROT(trail[0].dx, SIMON_LROT_CONST_U) ^ trail[1].dx;
#endif
#if 1								  // my OK
  differential_t trail[4] = {
	 {   0x2, 0x0008, 0, 0.250000},
	 {0x8800, 0x2000, 0, 0.062500}, // -4
	 {0x2000,  0x800, 0, 0.250000}, // -2
	 { 0x800,      0, 0, 0.250000}  // -2
  };
  uint32_t dyy_init = 0;//0x8088
#endif
  uint32_t trail_len = num_rounds;
  differential_t diff[4] = {{0,0,0,0.0}};

  double B[4] = {1.0,
					  (1.0/(double)(1UL << 4)),
					  (1.0/(double)(1UL << 6)),
					  (1.0/(double)(1UL << 8))};

  //  double B[NROUNDS] = {0.0};
  //  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}}
  uint32_t init_round = 0;
  uint32_t dx_in = trail[0].dx;
  uint32_t dy_in = 0;//dyy_init;
  differential_t input_diff = {dx_in, dy_in};
  uint32_t dx_out = trail[num_rounds - 1].dx;
  uint32_t dy_out = trail[num_rounds - 1].dy;
  differential_t output_diff = {dx_out, dy_out};
  double eps = SIMON_EPS;

  std::unordered_map<std::string, differential_t**> trails_hash_map;
  std::string s_trail = trail_to_string(trail, trail_len);
  differential_t** new_trail;
  new_trail = (differential_t** )calloc(1, sizeof(differential_t*));
  *new_trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
  for(uint32_t i = 0; i < trail_len; i++) {
	 (*new_trail)[i].dx = trail[i].dx;
	 (*new_trail)[i].dy = trail[i].dy;
	 (*new_trail)[i].p = trail[i].p;
  }
  std::pair<std::string, differential_t**> new_pair (s_trail,new_trail);
  trails_hash_map.insert(new_pair);

  //  simon_xor_cluster_trails(init_round, num_rounds, B, diff, trail, &trails_hash_map, dyy_init, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, eps);
  simon_xor_cluster_trails(init_round, num_rounds, B, diff, trail, &trails_hash_map, input_diff, output_diff, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, eps);

  printf("\n");

#if 1
  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map.begin();
  printf("[%s%d] Found %d trails:\n", __FILE__, __LINE__, (uint32_t)trails_hash_map.size());
  uint32_t trail_cnt = 0;
  while(hash_map_iter != trails_hash_map.end()) {
	 double p_tot = 1.0;
	 trail_cnt++;
	 //	 differential_t trail[4] = {{0,0,0,0.0}};
	 printf("[%5d] ", trail_cnt);
	 for(uint32_t i = 0; i < trail_len; i++) {
		printf("%4X  %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
		p_tot *= (*(hash_map_iter->second))[i].p;
	 }
	 printf(" | 2^%f\n", log2(p_tot));
	 hash_map_iter++;
  }
#endif

#if 0
  double p_tot = 1.0;
  differential_t round_diffs[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(trail, round_diffs, num_rounds, lrot_const_s, lrot_const_t, lrot_const_u);
  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (num_rounds); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, round_diffs[i].dx, round_diffs[i].dy, round_diffs[i].p, log2(round_diffs[i].p));
	 p_tot *= round_diffs[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));
#endif

  simon_verify_xor_trail(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);

}

void simon_compute_round_diff_matrix(uint32_t word_size,
												 uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
												 gsl_matrix* A, uint32_t A_nrows, uint32_t A_ncols)
{
  uint32_t all_words = (1ULL << word_size);

  for(uint32_t dx_in = 0; dx_in < all_words; dx_in++) {
	 for(uint32_t dy_in = 0; dy_in < all_words; dy_in++) {
		for(uint32_t dc = 0; dc < all_words; dc++) {

		  double p = xdp_rot_and(dx_in, dc, lrot_const_s, lrot_const_t);
		  uint32_t dx_out = dy_in ^ dc ^ LROT(dx_in, lrot_const_u);
		  uint32_t dy_out = dx_in;

		  uint32_t row = (dy_in << word_size) | dx_in;
		  uint32_t col = (dy_out << word_size) | dx_out;

		  assert(row < A_nrows);
		  assert(col < A_ncols);

		  gsl_matrix_set(A, row, col, p);

		}
	 }
  }

  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void test_simon_compute_round_diff_matrix()
{
  uint32_t lrot_const_s = 1;
  uint32_t lrot_const_t = 3;
  uint32_t lrot_sonst_u = 2;
  uint32_t word_size = 5;
  assert(word_size == WORD_SIZE);
  uint32_t all_blocks = (1ULL << (2 * word_size));
  uint32_t A_nrows = all_blocks;
  uint32_t A_ncols = all_blocks;
  uint32_t nrounds = 3;

  //  all_blocks == all_blocks;		  // avoid warning

#if 1
  printf("[%s:%d] A[%d x %d]\n", __FILE__, __LINE__, A_nrows, A_ncols);
#endif

  gsl_matrix* A = gsl_matrix_calloc(A_nrows, A_ncols);
  gsl_matrix* R = gsl_matrix_calloc(A_nrows, A_ncols);

  simon_compute_round_diff_matrix(word_size, lrot_const_s, lrot_const_t, lrot_sonst_u, A, A_nrows, A_ncols);

  for(uint32_t i = 0; i < nrounds; i++) {
	 gsl_blas_dgemm(CblasNoTrans, CblasNoTrans, 1.0, A, A, 0.0, R); // AA!
	 gsl_matrix_memcpy(A, R);	  // should be AA !!! (add second matrix to accumulate product: AA = A * A * A ...)
  }

#if 1
  printf("A = \n");
  for(uint32_t row = 0; row < A_nrows; row++) {
	 for(uint32_t col = 0; col < A_ncols; col++) {
		double e = gsl_matrix_get(A, row, col);
		if(e != 0.0)
		  printf("%1.0f ", log2(e));
		else
		  printf(" . ");
		if((row != 0) && (col != 0)) {
		  assert(e != 0.0);
		}
	 }
	 printf("\n\n");
  }
  printf("\n");
#endif

  gsl_matrix_free(R);
  gsl_matrix_free(A);
}

// {--- test hash map ---

void hash_map_add(std::unordered_map<std::string, differential_t**>* trails_hash_map)
{
  uint32_t trail_len = 10;
  uint32_t N = (1U << 18);
  for(uint32_t j = 0; j < N; j++) {
	 differential_t** trail;
	 trail = (differential_t** )calloc(1, sizeof(differential_t*));
	 *trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
	 for(uint32_t i = 0; i < trail_len; i++) {
		(*trail)[i].dx = xrandom() & MASK;
		(*trail)[i].dy = xrandom() & MASK;
	 }
	 std::string s = trail_to_string(*trail, trail_len);
	 (*trails_hash_map)[s] = trail;
  }
  std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map->begin();
  while(hash_map_iter != trails_hash_map->end()) {
	 for(uint32_t i = 0; i < trail_len; i++) {
		//		printf("%4X %4X ", hash_map_iter->second[i].dx, hash_map_iter->second[i].dy);
		printf("%4X  %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
	 }
	 printf("\n");
	 printf("%s\n", hash_map_iter->first.c_str());
	 hash_map_iter++;
  }
}

void test_trail_to_string()
{
  uint32_t trail_len = 10;
  differential_t** trail;
  trail = (differential_t** )calloc(1, sizeof(differential_t*));
  *trail = (differential_t*)calloc(trail_len, sizeof(differential_t));
  for(uint32_t i = 0; i < trail_len; i++) {
	 (*trail)[i].dx = xrandom() & MASK;
	 (*trail)[i].dy = xrandom() & MASK;
  }
 for(uint32_t i = 0; i < trail_len; i++) {
	printf("%4X %4X ", (*trail)[i].dx, (*trail)[i].dy);
	//	printf("%d %d ", trail[i].dx, trail[i].dy);
 }
 printf("\n");

 std::string s = trail_to_string(*trail, trail_len);
 printf("%s\n", s.c_str());

 std::unordered_map<std::string, differential_t**> trails_hash_map;

 trails_hash_map[s] = trail;

 std::unordered_map<std::string, differential_t**>::const_iterator hash_map_iter = trails_hash_map.find(s);

 if(hash_map_iter == trails_hash_map.end()) {
	printf("Not found!\n");
 } else {
	std::cout << hash_map_iter->first << " is " << hash_map_iter->second << "\n";

	//	differential_t found_trail[trail_len];
	//	found_trail = hash_map_iter->second;
	for(uint32_t i = 0; i < trail_len; i++) {
	  printf("%4X  %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
	}
	printf("\n");
	printf("%s\n", hash_map_iter->first.c_str());
 }

 // std::unordered_map<std::string, int> map;
 // map["string"] = 10;
 // std::unordered_map<std::string, int>::const_iterator map_iter = map.find("string");
 printf("Before\n");
 hash_map_add(&trails_hash_map);
 printf("After\n");
 hash_map_iter = trails_hash_map.begin();
#if 1
 while(hash_map_iter != trails_hash_map.end()) {
	for(uint32_t i = 0; i < trail_len; i++) {
	  //	  printf("%4X %4X ", hash_map_iter->second[i].dx, hash_map_iter->second[i].dy);
	  printf("%4X  %4X ", (*(hash_map_iter->second))[i].dx, (*(hash_map_iter->second))[i].dy);
	}
	printf("\n");
	printf("%s\n", hash_map_iter->first.c_str());
	hash_map_iter++;
 }
#endif

 free(*trail);
 free(trail);
}

// --- test hash map ---}


/*
[./tests/simon-xor-threshold-search-tests.cc:1283] INPUT DIFF    0    1
R[ 0] MAX: (   0    1) -> (   1    0) 2^0.000000
R[ 1] MAX: (   0    1) -> (   4    1) 2^-2.000000
R[ 2] MAX: (   0    1) -> (  11    4) 2^-4.000000
R[ 3] MAX: (   0    1) -> (  40   11) 2^-7.299560
R[ 4] MAX: (   0    1) -> ( 111   40) 2^-9.299560
R[ 5] MAX: (   0    1) -> ( 544  100) 2^-14.105182
R[ 6] MAX: (   0    1) -> (1101  404) 2^-17.599758
R[ 7] MAX: (   0    1) -> (4000 1101) 2^-21.461885
R[ 8] MAX: (   0    1) -> (1100 4000) 2^-23.402965
R[ 9] MAX: (   0    1) -> ( 104    0) 2^-25.348416
R[10] MAX: (   0    1) -> (   1    0) 2^-26.163226
R[11] MAX: (   0    1) -> (   4    1) 2^-28.115223
R[12] MAX: (   0    1) -> ( 100    0) 2^-28.960967
R[13] MAX: (   0    1) -> ( 400  100) 2^-30.949967
[./tests/simon-xor-threshold-search-tests.cc:simon_diff_search()1400] BEST 12R: (   0    1) -> (   4    1) 2^-28.115223
 */

// verify the DTU differential
void test_simon_verify_differential_gviz()
{
  uint64_t npairs = (1ULL << 32);
  assert(WORD_SIZE == 16);
#if 0									  // DTU, 12R, 2^-36 -> 2^-29
  assert(NROUNDS == 12);
  uint32_t nrounds = 12;
  differential_t input_diff = {0x0001, 0x0000, 0, 0.0};
  differential_t output_diff = {0x0100, 0x0000, 0, 0.0};
  //  differential_t output_diff = {0x2, 0x230, 0, 0.0};
#endif
#if 0								  // mydiff
  assert(NROUNDS == 13);
  uint32_t nrounds = 13;
  differential_t input_diff  = {0, 1, 0, 0.0};
  differential_t output_diff = {0x100, 0, 0, 0.0};
  // MAX:      100        0 2^-28.960967
#endif
#if 0									  // mydiff
  assert(NROUNDS == 8);
  uint32_t nrounds = 8;
  differential_t input_diff  = {0, 1, 0, 0.0};
  differential_t output_diff = {0x4000, 0x1101, 0, 0.0};
#endif
#if 0									  // mydiff-12
  assert(NROUNDS == 12);
  uint32_t nrounds = 12;
  differential_t input_diff  = {0, 0x8000, 0, 0.0};
  differential_t output_diff = {0x80, 0, 0, 0.0};
  //  differential_t output_diff = {0, 0x8200, 0, 0.0};
#endif
#if 0									  // 13R, p 2^-28.96
  assert(NROUNDS == 13);
  uint32_t nrounds = 13;
  differential_t input_diff  = {0, 0x40, 0, 0.0};
  differential_t output_diff = {0x4000, 0, 0, 0.0};
#endif
#if 1									  // 13R, p 2^-28.11
  // 12R: (2000 8000) -> (2000    0) 2^-28.115223
  assert(NROUNDS == 13);
  uint32_t nrounds = 13;
  differential_t input_diff  = {0x2000, 0x8000, 0, 0.0};
  differential_t output_diff = {0x2000, 0, 0, 0.0};
  //  differential_t input_diff  = {0x4000, 0x1, 0, 0.0};
  //  differential_t output_diff = {0x4000, 0, 0, 0.0};
#endif

  std::vector<simon_diff_graph_edge_t> E;
  uint32_t nkeys = (1ULL << 0);
  double edp = 0.0;
  //  assert(nkeys == 1);
  for(uint32_t i = 0; i < nkeys; i++) {

	 // generate random key
	 uint32_t key[SIMON_MAX_NROUNDS] = {0};
#if 0
	 key[0] = xrandom() & MASK;
	 key[1] = xrandom() & MASK;
	 key[2] = xrandom() & MASK;
	 key[3] = xrandom() & MASK;
#else
	 uint32_t mkey[4] = {0x545A, 0xE2AD, 0xEA9F, 0x6B56};
	 uint32_t s = 0;//6;//5;//1;//0;
	 key[0] = LROT(mkey[0], s);
	 key[1] = LROT(mkey[1], s);
	 key[2] = LROT(mkey[2], s);
	 key[3] = LROT(mkey[3], s);

	 s = 0;//6;//5;//1;
	 input_diff.dx  = LROT(input_diff.dx, s);
	 input_diff.dy  = LROT(input_diff.dy, s);
	 output_diff.dx = LROT(output_diff.dx, s);
	 output_diff.dy = LROT(output_diff.dy, s);
#endif

	 printf(" s %d : ", s);
	 printf("--- [%s:%d] Key ", __FILE__, __LINE__);
	 for(uint32_t j = 0; j < 4; j++) {
		printf("%8X ", key[j]);
	 }
	 printf(" --- \n");

	 uint32_t dx_in = input_diff.dx;
	 uint32_t dy_in = input_diff.dy;
	 uint32_t dx_out = output_diff.dx;
	 uint32_t dy_out = output_diff.dy;

	 printf("[%s:%s():%d]:\n Verify %d R differential (%8X %8X) -> (%8X %8X) | 2^%4.2f CP pairs\n", __FILE__, __FUNCTION__, __LINE__, nrounds, dx_in, dy_in, dx_out, dy_out, log2(npairs));

	 //	 npairs = (1ULL << 16);
	 //	 npairs = (1ULL << 16);
#if 1
	 double p_exp = simon_verify_differential(key, input_diff, output_diff, nrounds, npairs, &E);
#else
	 npairs = (1ULL << 27);
	 double p_exp = simon_verify_differential_approx(key, input_diff, output_diff, nrounds, npairs, &E);
#endif
	 printf("[%s:%s():%d]:\n Verified %d R differential (%8X %8X) -> (%8X %8X) | 2^%4.2f CP pairs\n Final probability p = 2^%f\n", __FILE__, __FUNCTION__, __LINE__, nrounds, dx_in, dy_in, dx_out, dy_out, log2(npairs), log2(p_exp));

	 edp += p_exp;

	 double temp_edp = (double)(edp / (double)(i + 1));

	 printf("[%s:%d] edp %f (2^%f)\n", __FILE__, __LINE__, edp, log2(edp));
	 printf("[%s:%d] temp_edp %f (2^%f) nkeys %d\n", __FILE__, __LINE__, temp_edp, log2(temp_edp), i);
	 printf("[%s:%d] OK\n\n", __FILE__, __LINE__);

  }

#if SIMON_DRAW_GRAPH
  char datfile[0xFFFF] = {0};
  sprintf(datfile, SIMON_GVIZ_DATFILE);

  char datfile_con[0xFFFF] = {0};
  sprintf(datfile_con, SIMON_GVIZ_DATFILE_CON);

  simon_graphviz_write_file(datfile, datfile_con, E);
#endif
}

// --- TESTS ---

#define FULL_DDT 1

//uint64_t simon_test_code(
uint64_t simon_test_code(std::unordered_map<uint32_t, std::vector<differential_t>>* T,
								 std::vector<differential_t> DZ,
								 std::unordered_map<uint32_t, differential_t>* H,
								 std::unordered_map<uint32_t, differential_t>* G,
								 const differential_t input_diff,
								 differential_t* max_output_diff,
								 const uint32_t hw_max)
{
  uint64_t cnt_iter = 0;
  std::unordered_map<uint32_t, differential_t>::const_iterator H_iter = H->begin();
  while(H_iter != H->end()) {

	 cnt_iter++;
	 const uint32_t dx_in = (H_iter->second).dx;
	 const uint32_t dy_in = (H_iter->second).dy;
	 const double p_in = (H_iter->second).p;
	 const differential_t diff_in = {dx_in, dy_in, 0, p_in};

#if FULL_DDT
	 std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator ddt_iter = T->find(dx_in);
	 DZ.clear();
	 DZ = (ddt_iter->second); // dz ^ (dx <<< 2)
#endif
	 //	 std::vector<differential_t> DZ = *(ddt_iter->second); // dz ^ (dx <<< 2)

	 std::vector<differential_t>::iterator vec_iter;
	 for(vec_iter = DZ.begin(); vec_iter != DZ.end(); vec_iter++) {

		cnt_iter++;
		differential_t diff = *vec_iter;
		uint32_t dz = diff.dy;	  // = (dx_in <<< 2) ^ dz
		double p = diff.p;

		const uint32_t dx_out = dz ^ dy_in;
		const uint32_t dy_out = dx_in;
		const double p_out = (p_in * p);
		const differential_t diff_out = {dx_out, dy_out, 0, p_out};
		if(hamming_weight(dx_out & MASK) <= hw_max) {

#if 1
		  //		  std::string s_diff_out = differential_to_string(diff_out);
		  uint32_t n_diff_out = differential_to_num(diff_out);
		  std::unordered_map<uint32_t, differential_t>::iterator G_iter = G->find(n_diff_out);
		  if(G_iter != G->end()) {  // diff already in G

			 (G_iter->second).p += diff_out.p;	  // update its probability

			 differential_t new_diff = {(G_iter->second).dx, (G_iter->second).dy, 0,  (G_iter->second).p};

			 simon_diff_update_max(diff_in, new_diff, max_output_diff);

		  } else {

			 //			 differential_t* new_diff = (differential_t *)calloc(1, sizeof(differential_t));
			 differential_t new_diff = {0, 0, 0, 0.0};
			 new_diff.dx = diff_out.dx;
			 new_diff.dy = diff_out.dy;
			 new_diff.npairs = diff_out.npairs;
			 new_diff.p = diff_out.p;

			 std::pair<uint32_t, differential_t> new_pair (n_diff_out, new_diff);
			 G->insert(new_pair);

			 simon_diff_update_max(diff_in, new_diff, max_output_diff);

		  }
#endif
		}
	 }
	 H_iter++;
  }
  return cnt_iter;
}


void test_simon_test_code()
{
  assert(WORD_SIZE <= 16);
#if(WORD_SIZE <= 16)
  std::unordered_map<uint32_t, std::vector<differential_t>> T;
  //  std::unordered_map<std::string, differential_t *> H;
  //  std::unordered_map<std::string, differential_t *> G;
  std::unordered_map<uint32_t, differential_t> H;
  std::unordered_map<uint32_t, differential_t> G;
  std::vector<differential_t> DZ;
  const uint32_t hw_max = 5;
  differential_t max_diff = {0, 0, 0, 0.0};

#if FULL_DDT // compute full DDT online
  printf("[%s:%d] Fill full DDT T\n", __FILE__, __LINE__);
  simon_compute_full_ddt(&T);
#else
  // fill DZ with elements
  uint32_t dz_len = (1ULL << 9);
  printf("[%s:%d] Fill DZ len 2^%4.2f\n", __FILE__, __LINE__, log2(dz_len));
  differential_t diff = {0, 0, 0, 0.0};
  for(uint32_t i = 0; i < dz_len; i++) {
	 diff.dx = xrandom() & MASK;
	 diff.dy = xrandom() & MASK;
	 diff.p = (double)(xrandom() & MASK) / (double)ALL_WORDS;
	 assert((diff.p >= 0.0) && (diff.p <= 1.0));
	 DZ.push_back(diff);
  }
#endif

  // fill H with  elements
  uint32_t h_len = (1ULL << 20);
  printf("[%s:%d] Fill H len 2^%4.2f\n", __FILE__, __LINE__, log2(h_len));
  differential_t input_diff = {0, 0, 0, 0.0}; // DTU
  for(uint32_t i = 0; i < h_len; i++) {
	 input_diff.dx = xrandom() & MASK;
	 input_diff.dy = xrandom() & MASK;
	 input_diff.npairs = 0;
	 input_diff.p = (double)(xrandom() & MASK) / (double)ALL_WORDS;
	 assert((input_diff.p >= 0.0) && (input_diff.p <= 1.0));

	 //	 std::string s_diff = differential_to_string(input_diff);
	 //	 std::pair<std::string, differential_t *> new_pair (s_diff, &input_diff);
	 uint32_t n_diff = differential_to_num(input_diff);
	 std::pair<uint32_t, differential_t> new_pair (n_diff, input_diff);
	 H.insert(new_pair);
  }

  //  uint32_t g_len = (1ULL << 20);
  //  G.reserve(g_len);
  //  G.rehash(g_len);

  timestamp_t start_time = get_timestamp();
  printf("[%s:%d] Start search %lld H_len 2^%4.2f G_len 2^%4.2f\n", __FILE__, __LINE__, (WORD_MAX_T)start_time, log2(H.size()), log2(G.size()));
  uint64_t cnt_iter = simon_test_code(&T, DZ, &H, &G, input_diff, &max_diff, hw_max);
  timestamp_t end_time = get_timestamp();
  printf("[%s:%d] End search %lld H_len 2^%4.2f G_len 2^%4.2f\n", __FILE__, __LINE__, (WORD_MAX_T)end_time, log2(H.size()), log2(G.size()));

  double total_time_sec = (double)(end_time - start_time) / 1000000.0L;
  double total_time_ms = (double)(end_time - start_time) / 1000.0L;
  double total_time_mu = (double)(end_time - start_time);
  double total_time_min = total_time_sec / 60.0;
  double C = total_time_sec / (double)cnt_iter;
  printf("[%s:%d] %f min %f s %f ms %f mu\n", __FILE__, __LINE__, total_time_min, total_time_sec, total_time_ms, total_time_mu);
  //  printf("[%s:%d] cnt_iter %ld (2^%4.2f) C %f (2^%f)\n", __FILE__, __LINE__, cnt_iter, log2(cnt_iter), C, log2(C));
  printf("[%s:%d] cnt_iter %lld (2^%4.2f) C %f (2^%f)\n", __FILE__, __LINE__, (WORD_MAX_T)cnt_iter, log2(cnt_iter), C, log2(C));

#endif  // #if(WORD_SIZE <= 16)
}


void test_simon_compute_full_ddt()
{
  std::unordered_map<uint32_t, std::vector<differential_t>> T;
  simon_compute_full_ddt(&T);
	 //  std::unordered_map<uint32_t, std::vector<differential_t>*>::const_iterator T_iter;
	 //  for(T_iter = T.begin(); T_iter != T.end(); T_iter++) {
	 //	 free(T_iter->second);
	 //  }

#if 0
  // ---

  std::vector<uint32_t>::iterator vec_iter;
  for(vec_iter = DX.begin(); vec_iter != DX.end(); vec_iter++) {
	 uint32_t dx = *vec_iter;
	 simon_ddt_add_row(T, dx, hw_max);
#if 1									  // DEBUG
	 std::unordered_map<uint32_t, std::vector<differential_t>*>::const_iterator T_iter = T->find(dx);
	 printf("%4X: %d\n", dx, (uint32_t)T_iter->second->size());
	 assert(T_iter != T->end());
	 //	 printf("%4X: %d\n", dx, T[dx].size());
#endif
  }
#endif

}

void test_simon32_ddt_file()
{
  std::unordered_map<uint32_t, std::vector<differential_t>> T;

  simon32_ddt_file_write(SIMON_DDT_FILE_NAME, &T);

  simon32_ddt_file_read(SIMON_DDT_FILE_NAME, &T);

#if 1									  // DEBUG
  std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator T_iter;
  for(T_iter = T.begin(); T_iter != T.end(); T_iter++) {
	 std::vector<differential_t> DX = T_iter->second;
	 std::vector<differential_t>::iterator DX_iter;
	 //	 for(DX_iter = T_iter->second->begin(); DX_iter != T_iter->second->end(); DX_iter++) {
	 for(DX_iter = DX.begin(); DX_iter != DX.end(); DX_iter++) {
		uint32_t dx = DX_iter->dx;
		uint32_t dy = DX_iter->dy;
		double p = DX_iter->p;
		assert(dx == T_iter->first);
		printf("T: %X %X %f\n", dx, dy, p);
	 }
  }
#endif
 
}

// full search
void test_simon_diff_search(const uint32_t dx_in,
									 const uint32_t dy_in, 
									 const char* logfile)
{
  uint32_t nrounds = NROUNDS;
  uint32_t hw_max = 5;

  std::unordered_map<uint32_t, std::vector<differential_t>> T;

  // fill the DDT
#if 0 // compute partial DDT to start with
  std::vector<uint32_t> DX;
  uint32_t DX_len = 1;//ALL_WORDS;
  for(uint32_t x = 0; x < DX_len; x++) {
	 DX.push_back(x);
  }
  assert(DX.size() == DX_len);

  uint32_t hw = WORD_SIZE;
  simon_compute_partial_ddt(&T, DX, hw);
#endif
#if 1 // compute full DDT online
  simon_compute_full_ddt(&T);
#endif
#if 0 // read full DDT from file
  simon32_ddt_file_read(SIMON_DDT_FILE_NAME, &T);
#endif
  std::unordered_map<uint32_t, differential_t> D;
  uint32_t D_round = 13;
  simon_diff_search(nrounds, dx_in, dy_in, hw_max, &T, &D, D_round, logfile);
}

void test_simon_compute_partial_ddt()
{

  uint32_t n = WORD_SIZE;
  uint32_t hw = 2;
  std::vector<uint32_t> DX;

  printf("[%s:%d] Check\n", __FILE__, __LINE__);

  gen_word_hw(n, hw, &DX);

  printf("[%s:%d] Check\n", __FILE__, __LINE__);

  std::unordered_map<uint32_t, std::vector<differential_t>> T;
  simon_compute_partial_ddt(&T, DX, hw);

  printf("[%s:%d] Check\n", __FILE__, __LINE__);

  std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator hash_map_iter;
  for(hash_map_iter = T.begin(); hash_map_iter != T.end(); hash_map_iter++) {
	 uint32_t dx = hash_map_iter->first;
	 printf("[%s:%d] %4X: ", __FILE__, __LINE__, dx);
	 std::vector<differential_t> DX = (hash_map_iter->second);
	 std::vector<differential_t>::iterator vec_iter;
	 for(vec_iter = DX.begin(); vec_iter != DX.end(); vec_iter++) {
		differential_t diff = *vec_iter;
		uint32_t dz = diff.dy;
		double p = diff.p;
		printf("%4X %f | ", dz, p);
		assert(p != 0.0);
		assert(dx == diff.dx);
	 }
	 printf("\n");
  }
}

void test_gen_word_hw()
{
  uint32_t hw = 4;
  uint32_t n = WORD_SIZE;

  std::vector<uint32_t> X;

  uint32_t x_cnt_0 = gen_word_hw(n, hw, &X);

  printf("\n[%s:%d] Recursive finished!\n", __FILE__, __LINE__);

  uint32_t x_cnt_1 = gen_word_hw_all(n, hw);

  printf("\n[%s:%d] Sequential finished!\n", __FILE__, __LINE__);

  printf("\n[%s:%d] %d %d %d\n", __FILE__, __LINE__, x_cnt_0, x_cnt_1, (uint32_t)X.size()); 
 assert(x_cnt_0 == x_cnt_1);
 assert(x_cnt_0 == X.size());
}


/*
  256400 = (256400)|  100  190
  256400 = (256400)|   19 1900

256400 = (256400)256 400|  100  190
256400 = (256400)25 6400|   19 1900

167046592 = (1670 46592)|  686 B600
167046592 = (16704 6592)| 4140 19C0

*/
void test_oss_bug()
{
  printf("[%s:%s():%d]\n", __FILE__, __FUNCTION__, __LINE__);

  uint32_t dx1 = 0x686;//0x100;
  uint32_t dy1 = 0xB600;//0x190;

  uint32_t dx2 = 0x4140;//0x19;
  uint32_t dy2 = 0x19C0;//0x1900;

  // std::stringstream stream;
  // stream << std::setfill('0') << std::setw(2) << value;
  //  oss1 << std::setfill('0') << std::setw(WORD_SIZE / 8);
  //  oss2 << std::setfill('0') << std::setw(WORD_SIZE / 8);

  std::stringstream oss1("");
  oss1 << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << dx1;
  oss1 << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << dy1;
  std::string s1 = oss1.str();	
  std::cout << "s1 = " << s1 << std::endl;

  std::stringstream oss2("");
  oss2 << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << dx2;
  oss2 << std::hex << std::setfill('0') << std::setw(WORD_SIZE / 4) << dy2;
  std::string s2 = oss2.str();	
  std::cout << "s2 = " << s2 << std::endl;

  std::cout << std::hex << s1 << " = (" << dx1 << dy1 << ") " << dx1 << " " << dy1;
  printf("| %4X %4X \n", dx1, dy1);
  std::cout << std::hex << s2 << " = (" << dx2 << dy2 << ") " << dx2 << " " << dy2;
  printf("| %4X %4X \n", dx2, dy2);
}

/*

Tests:

2^32
#--- [./tests/simon-xor-threshold-search-tests.cc:1663] Tests, WORD_SIZE  = 16, MASK =     FFFF
[./tests/simon-xor-threshold-search-tests.cc:1655] 1380893203927934 1380893214569622 10.641688 s 10641.688000 millis 10641688.000000 micros
real    0m10.643s
user    0m10.617s
sys     0m0.000s

2^34
#--- [./tests/simon-xor-threshold-search-tests.cc:1663] Tests, WORD_SIZE  = 16, MASK =     FFFF
[./tests/simon-xor-threshold-search-tests.cc:1655] 1380893317476362 1380893360042214 42.565852 s 42565.852000 ms 42565852.000000 mus
real    0m42.567s
user    0m42.447s
sys     0m0.008s

*/
void test_time()
{
  //  struct time_msval time_msout;
  uint64_t cnt = 0;
  timestamp_t start_time = get_timestamp();
  printf("[%s:%s():%d] Start loop\n", __FILE__, __FUNCTION__, __LINE__);
  for(uint64_t i = 0; i < (uint64_t)(1ULL << 32); i++) {
	 cnt++;
	 //	 printf("%lld\n", cnt);
	 //	 fflush(stdout);
  }
  printf("[%s:%s():%d] End loop\n", __FILE__, __FUNCTION__, __LINE__);
  timestamp_t end_time = get_timestamp();
  double total_time_sec = (double)(end_time - start_time) / 1000000.0L;
  double total_time_millisec = (double)(end_time - start_time) / 1000.0L;
  double total_time_microsec = (double)(end_time - start_time);
  printf("[%s:%d] %lld %lld %f s %f ms %f mu\n", __FILE__, __LINE__, (WORD_MAX_T)start_time, (WORD_MAX_T)end_time, total_time_sec, total_time_millisec, total_time_microsec);
}

void test_simon_diff_hash_custom()
{
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map;

  simon_diff_hash diff_hash;  // hash function

  uint32_t N = (1U << 5);

  // fill the hash table with random data
  for(uint32_t h = 0; h < N; h++) {

	 differential_t diff[SIMON_NDIFFS] = {{0, 0, 0, 0.0}};
	 for(uint32_t i = 0; i < SIMON_NDIFFS; i++) {
		diff[i].dx = xrandom() & MASK;
		diff[i].dy = xrandom() & MASK;
	 }

	 std::array<differential_t, SIMON_NDIFFS> diff_array;

	 for(uint32_t i = 0; i < SIMON_NDIFFS; i++) {
		diff_array[i] = diff[i];
	 }

	 uint32_t hash_val = diff_hash(diff_array);
#if 1									  // DEBUG
	 printf("[%s:%d] H[%X] | ", __FILE__, __LINE__, hash_val);
	 simon_print_diff_array(diff_array);
#endif
	 std::pair<std::array<differential_t, SIMON_NDIFFS>, uint32_t> new_pair (diff_array, hash_val);
	 diffs_hash_map.insert(new_pair);

	 boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::const_iterator map_iter 
		= diffs_hash_map.find(diff_array);
#if 0									  // DEBUG
	 printf("[%s:%d] H[%X] | ", __FILE__, __LINE__, map_iter->second);
	 simon_print_diff_array(map_iter->first);
#endif
	 assert(map_iter != diffs_hash_map.end());

  }

  simon_print_diff_hash_map(diffs_hash_map);
}

void test_simon_trail_hash_custom()
{
  //  std::unordered_map<std::string, differential_t**>* diffs_hash_map;
  //  std::unordered_map<std::string, differential_t**>* trails_hash_map;
  //  std::unordered_map<std::array<differential_t, NROUNDS>, std::array<differential_t, NROUNDS>> hash_map;
  //  std::unordered_map<uint64_t, std::array<differential_t, NROUNDS>> trails_hash_map;

  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map;

  simon_trail_hash trail_hash;  // hash function

  uint32_t N = (1U << 5);

  // fill the hash table with random data
  for(uint32_t h = 0; h < N; h++) {

	 differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};
	 for(uint32_t i = 0; i < NROUNDS; i++) {
		trail[i].dx = xrandom() & MASK;
		trail[i].dy = xrandom() & MASK;
	 }

	 std::array<differential_t, NROUNDS> trail_array;

	 for(uint32_t i = 0; i < NROUNDS; i++) {
		trail_array[i] = trail[i];
	 }

	 uint32_t hash_val = trail_hash(trail_array);
#if 0									  // DEBUG
	 printf("[%s:%d] H[%X] | ", __FILE__, __LINE__, hash_val);
	 simon_print_trail_array(trail_array);
#endif
	 std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, hash_val);
	 trails_hash_map.insert(new_pair);

	 boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>::const_iterator map_iter 
		= trails_hash_map.find(trail_array);
#if 0									  // DEBUG
	 printf("[%s:%d] H[%X] | ", __FILE__, __LINE__, map_iter->second);
	 simon_print_trail_array(map_iter->first);
#endif
	 assert(map_iter != trails_hash_map.end());
  }

  simon_print_trail_hash_map(trails_hash_map);
}


// for Simon for a fixed trail found with threshold search
// search for clusters of other trails connecting the same differential
void test_simon_diff_search_fixed()
{
  assert(SIMON_TRAIL_LEN >= NROUNDS);
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map;

#if 0									  // DEBUG
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;
  uint32_t npairs = (1ULL << 22);
  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  simon_verify_xor_trail(NROUNDS, npairs, key, g_trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(NROUNDS, npairs, key, g_trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
#endif

#if 1
  FILE* fp = fopen(SIMON_CLUSTER_TRAILS_DATFILE, "w"); // init file
  fclose(fp);
  uint32_t dyy_init = 0;		  // dummy
  simon_trail_cluster_search_boost(&trails_hash_map, g_B, g_trail, NROUNDS, &dyy_init);
#endif

}

/**
 * Given a target node (level,dx,dy) and a vector of such nodes return
 * the index of the target node within the vector or return the size
 * of the vector + 1 if the node was not found. 
 *
 * Used in the computation of the transition matrix of the trails
 * graph for Simon.
 */
uint32_t simon_trails_graph_transition_matrix_node_to_index(std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp> V,
																				const simon_diff_graph_node_t target) 
{
  uint32_t index = V.size() + 1;
  bool b_found = false;
  uint32_t index_iter = 0;
  std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp>::iterator node_iter = V.begin();
#if 0									  // DEBUG
  printf("[%s:%d] TGT (%2d %8X %8X) => \n", __FILE__, __LINE__,
			target.level, target.node[0], target.node[1]);
#endif
  while((!b_found) && (node_iter != V.end())) {
	 const simon_diff_graph_node_t current = node_iter->second;
#if 0									  // DEBUG
	 printf("[%3d] CUR (%2d %8X %8X)\n", index_iter, current.level, current.node[0], current.node[1]);
#endif
	 b_found = ((current.level == target.level) && (current.node[0] == target.node[0]) && (current.node[1] == target.node[1]));
	 if(b_found) {
		index = index_iter;
	 }
	 index_iter++;
	 node_iter++;
  }
  assert(b_found);				  // normally the elemnt whould always be found
  return index;
}

void simon_trails_graph_transition_vector_print(gsl_vector* V, uint32_t V_dim)
{
  for(uint32_t i = 0; i < V_dim; i++) {
	 double val = gsl_vector_get(V, i);
	 if(val) {
		printf("%4.2f ", log2(val));
	 } else {
		printf(".");
	 }
  }
}

void simon_trails_graph_transition_matrix_print(gsl_matrix* A, uint32_t A_nrows, uint32_t A_ncols)
{
  for(uint32_t row = 0; row < A_nrows; row++){
	 printf("[%2d] ", row);
	 for(uint32_t col = 0; col < A_ncols; col++){
		double e = gsl_matrix_get(A, row, col);
		if(e) {
		  printf("%4.2f ", log2(e));
		} else {
		  printf(".");
		}
	 }
	 printf("\n");
  }
  printf("\n");
}

// set all non-zero entries to 1 (all 0 entries are unchanged)
void simon_trails_graph_transition_matrix_binarize(gsl_matrix* A, uint32_t A_nrows, uint32_t A_ncols)
{
  for(uint32_t row = 0; row < A_nrows; row++){
	 for(uint32_t col = 0; col < A_ncols; col++){
		double e = gsl_matrix_get(A, row, col);
		if(e) {
		  gsl_matrix_set(A, row, col, 1.0);
		}
	 }
  }
}

/**
 * Compute a transition matrix for graph representing the clustering
 * of trails in Simon64 The data for the graph is read from a data
 * file \ref SIMON_CLUSTER_TRAILS_DATFILE written by \ref
 * simon_boost_print_hash_table from a previous call to \ref
 * simon_trail_cluster_search_boost called from \ref
 * test_simon_diff_search_fixed . The data from the file is stored in
 * a vector E of \ref simon_diff_graph_edge_t structures
 */
void simon_trails_graph_transition_matrix_compute()
{
  std::vector<simon_diff_graph_edge_t> E; // edges
  std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp> V; // vertices

#if 1									  // DEBUG
  printf("[%s:%d] Read graph from file '%s'\n", __FILE__, __LINE__, SIMON_CLUSTER_TRAILS_DATFILE);
#endif  // #if 1									  // DEBUG

  simon_cluster_trails_datfile_read(&E); // read garph from file

  // --------------------------------------
#if 1									  // TEMP

#if 1									  // DEBUG
  printf("\n[%s:%d] #edges E.size %d\n", __FILE__, __LINE__, (uint32_t)E.size());
#endif  // #if 1									  // DEBUG


  simon_diff_graph_extract_nodes(E, &V); // extract nodes

#if 0									  // DEBUG
  simon_diff_graph_print_nodes(V);
#endif  // #if 1									  // DEBUG
#if 1									  // DEBUG
  printf("[%s:%d] #vertices V.size %d\n", __FILE__, __LINE__, (uint32_t)V.size());
#endif  // #if 1									  // DEBUG

  uint32_t A_nrows = V.size();
  uint32_t A_ncols = V.size();
  gsl_matrix* A = gsl_matrix_calloc(A_nrows, A_ncols);

  for(uint32_t i = 0; i < E.size(); i++) {

	 simon_diff_graph_node_t node_from = {0, {0, 0}, 0, 0, 0.0};
	 node_from.level = E.at(i).level;
	 node_from.node[0] = E.at(i).node_from[0];
	 node_from.node[1] = E.at(i).node_from[1];
	 uint32_t index_from = simon_trails_graph_transition_matrix_node_to_index(V, node_from);
	 assert(index_from < V.size());

	 simon_diff_graph_node_t node_to = {0, {0, 0}, 0, 0, 0.0};
	 node_to.level = E.at(i).level + 1;
	 node_to.node[0] = E.at(i).node_to[0];
	 node_to.node[1] = E.at(i).node_to[1];
	 uint32_t index_to = simon_trails_graph_transition_matrix_node_to_index(V, node_to);
	 assert(index_to < V.size());

	 assert(node_to.level = (node_from.level + 1));

	 double p_cost = E.at(i).p;// * E.at(i).cnt; // !!!
	 assert(p_cost <= 1.0);

#if 0									  // DEBUG
	 printf("[%s:%d] A[%3d][%3d] = %f | (%2d %8X %8X) -> (%2d %8X %8X)\n", __FILE__, __LINE__,
			  index_from, index_to, p_cost, 
			  node_from.level, node_from.node[0], node_from.node[1],
			  node_to.level, node_to.node[0], node_to.node[1]);
#endif
	 gsl_matrix_set(A, index_from, index_to, p_cost);
  }

#if 0									  // DEBUG
  simon_trails_graph_transition_matrix_print(A, A_nrows, A_ncols);
#endif  // #if 0									  // DEBUG

#define SIMON_TMATRIX_BINARY 1 // set non-zero entries to 1
#if SIMON_TMATRIX_BINARY
  simon_trails_graph_transition_matrix_binarize(A, A_nrows, A_ncols);
#if 1									  // DEBUG
  printf("\n[%s:%d] ---------------- BINARIZED A^{%2d} -------------------\n", __FILE__, __LINE__, 1);
  simon_trails_graph_transition_matrix_print(A, A_nrows, A_ncols); // print product
#endif  // #if 0									  // DEBUG
#endif  // #if SIMON_TMATRIX_BINARY

  uint32_t nrounds = 21;

  gsl_matrix* AA = gsl_matrix_calloc(A_nrows, A_ncols); // accumulayes product: AA = A * A * A ...
  gsl_matrix_memcpy(AA, A);									  // copy initial AA <- A

  gsl_matrix* R = gsl_matrix_calloc(A_nrows, A_ncols); // temporary matrix
  gsl_matrix_set_zero(R);	  // init R

#if 0									  // DEBUG
  printf("\n[%s:%d] ---------------- A^{%2d} -------------------\n", __FILE__, __LINE__, 1);
  simon_trails_graph_transition_matrix_print(AA, A_nrows, A_ncols); // print product
#endif  // #if 0									  // DEBUG
  for(uint32_t i = 1; i < nrounds; i++) { // start from 1
	 gsl_blas_dgemm(CblasNoTrans, CblasNoTrans, 1.0, AA, A, 0.0, R); // AA * A = R
	 gsl_matrix_memcpy(AA, R);	  // AA <- R
	 gsl_matrix_set_zero(R);	  // init R
#if 0									  // DEBUG
	 printf("\n[%s:%d] ---------------- A^{%2d} -------------------\n", __FILE__, __LINE__, i+1);
	 simon_trails_graph_transition_matrix_print(AA, A_nrows, A_ncols); // print product
#endif  // #if 0									  // DEBUG
  }
#if 0									  // DEBUG
  printf("\n[%s:%d] ---------------- A^{%2d} -------------------\n", __FILE__, __LINE__, nrounds);
  simon_trails_graph_transition_matrix_print(AA, A_nrows, A_ncols); // print product
#endif  // #if 0									  // DEBUG


  assert(A_ncols == A_nrows);
  uint32_t start_pos = 0;		  // index   0 = ( 0  4000000 11000000)
  uint32_t end_pos = (A_ncols - 1);   // index 509 = (21 11000000  4000000)
  gsl_vector* S = gsl_vector_calloc(A_nrows); // initial vector
  gsl_vector* SS = gsl_vector_calloc(A_nrows); // product accumulator
  gsl_vector* T = gsl_vector_calloc(A_nrows); // final vector

  double p = 0.0;
  gsl_vector_set(S, start_pos, 1.0);
  gsl_vector_set(T, end_pos, 1.0);
  gsl_blas_dgemv(CblasTrans, 1.0, AA, S, 0.0, SS);
  gsl_blas_ddot(SS, T, &p);

#if 1									  // DEBUG
  printf("\n[%s:%d] ---------------- S -------------------\n", __FILE__, __LINE__);
  simon_trails_graph_transition_vector_print(S, A_ncols);
  printf("\n[%s:%d] ---------------- S A^{%2d} -------------------\n", __FILE__, __LINE__, nrounds);
  simon_trails_graph_transition_vector_print(SS, A_ncols);
  printf("\n[%s:%d] ---------------- T -------------------\n", __FILE__, __LINE__);
  simon_trails_graph_transition_vector_print(T, A_ncols);
  printf("\n[%s:%d] ---------------- S A^{%2d} T -------------------\n", __FILE__, __LINE__, nrounds);
  printf("[%s:%d] p = S A^{21} T = %f = %f\n", __FILE__, __LINE__, p, log2(p));
  printf("\n");
#endif

  // free
  gsl_vector_free(SS);
  gsl_vector_free(S);
  gsl_vector_free(T);
  gsl_matrix_free(R);
  gsl_matrix_free(AA);
  gsl_matrix_free(A);

  // --------------------------------------
#endif // #if 0									  // TEMP
}

void test_simon_trails_graph_transition_matrix()
{
  simon_trails_graph_transition_matrix_compute();
}

void test_simon_cluster_trails_datfile_read()
{
  assert(WORD_SIZE == 32);
  //  const differential_t diff_input = g_trail[0];

  std::vector<simon_diff_graph_edge_t> E;

  simon_cluster_trails_datfile_read(&E);

  printf("\nE.size %d\n", (uint32_t)E.size());

  char datfile[0xFFFF] = {0};
  sprintf(datfile, SIMON_GVIZ_CLUSTER_TRAILS_DATFILE);

  char datfile_con[0xFFFF] = {0};
  sprintf(datfile_con, SIMON_GVIZ_CLUSTER_TRAILS_DATFILE_CON);

  simon_graphviz_write_file(datfile, datfile_con, E);

}

// for Simon for a fixed trail found with threshold search
// search for clusters of other trails connecting the same multiple differentials
void test_simon_multi_diff_search_fixed()
{
  assert(SIMON_TRAIL_LEN >= NROUNDS);

  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map;
  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map;

  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  double p_thres = XDP_ROT_AND_P_THRES;
  //  uint32_t npairs = SIMON_NPAIRS;
  uint32_t dyy_init = 0;		  // dummy

  double B[NROUNDS];
  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS] = {{0, 0, 0, 0.0}};

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  std::multiset<differential_t, struct_comp_diff_p> hways_diff_mset_p; // all highways
  std::set<differential_t, struct_comp_diff_dx_dy> hways_diff_set_dx_dy;

  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p;	 // Dp

  uint64_t max_cnt = XDP_ROT_AND_MAX_DIFF_CNT;
  xdp_rot_and_pddt(&diff_set_dx_dy, &diff_mset_p, lrot_const_s, lrot_const_t, max_cnt, p_thres);
#if 0						 // DEBUG
  xdp_rot_and_print_set_dx_dy(diff_set_dx_dy);
#endif
  hways_diff_mset_p = diff_mset_p;
  hways_diff_set_dx_dy = diff_set_dx_dy;

  uint32_t nrounds = NROUNDS;

  // init bounds and trail
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = g_B[i];
	 trail[i] = diff[i] = g_trail[i];
  }

  double p = 1.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 p *= trail[i].p;
  }

  differential_t** diff_max;//[2] = {{0,0,0,0.0}};
  diff_max = (differential_t** )calloc(1, sizeof(differential_t*));
  *diff_max = (differential_t*)calloc(2, sizeof(differential_t));
  (*diff_max)[0] = {0, 0, 0, 0.0};
  (*diff_max)[1] = {0, 0, 0, 0.0};

#if 1
  std::array<differential_t, NROUNDS> trail_array;
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 trail_array[i].dx = trail[i].dx;
	 trail_array[i].dy = trail[i].dy;
	 trail_array[i].npairs = trail[i].npairs;
	 trail_array[i].p = trail[i].p;
  }

  simon_trail_hash trail_hash;  // trails hash function
  uint32_t trail_hash_val = trail_hash(trail_array);
  std::pair<std::array<differential_t, NROUNDS>, uint32_t> new_pair (trail_array, trail_hash_val);
  trails_hash_map.insert(new_pair);

  printf("[%s:%d] Initial trail\n", __FILE__, __LINE__);
  simon_print_trail_hash_map(trails_hash_map);

  // Add initial differential
  std::array<differential_t, SIMON_NDIFFS> diff_array;
  diff_array[0].p = 1.0;
  diff_array[0].dx = diff[0].dx;
  diff_array[0].dy = diff[0].dy ^ diff[1].dx; // !!
  diff_array[1].p = p;
  diff_array[1].dx = diff[nrounds - 1].dx;
  diff_array[1].dy = diff[nrounds - 1].dy;

  simon_diff_hash diff_hash;  // differential hash function
  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>::iterator diff_iter 
	 = diffs_hash_map.find(diff_array);

  double p_max = (*diff_max)[1].p;

  assert((*diff_max)[1].p == 0.0);
  assert(diff_iter == diffs_hash_map.end());
  if(diff_iter == diffs_hash_map.end()) {
	 uint32_t diff_hash_val = diff_hash(diff_array);
	 std::pair<std::array<differential_t, SIMON_NDIFFS>, uint32_t> new_pair (diff_array, diff_hash_val);
	 diffs_hash_map.insert(new_pair);

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 if(p > p_max) {
		(*diff_max)[0].p = (*diff_max)[1].p = p;
		(*diff_max)[0].dx = trail[0].dx;
		(*diff_max)[0].dy = trail[0].dy ^ trail[1].dx; // !!
		(*diff_max)[1].dx = trail[NROUNDS - 1].dx;
		(*diff_max)[1].dy = trail[NROUNDS - 1].dy;
		printf("[%s:%d] Update MAX differential: %4X %4X -> %4X %4X 2^%f | #trails %d\n", __FILE__, __LINE__, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p), (uint32_t)trails_hash_map.size());
	 }
  }
  printf("[%s:%d] Initial MAX differential: %4X %4X -> %4X %4X 2^%f | #trails %d\n", __FILE__, __LINE__, (*diff_max)[0].dx, (*diff_max)[0].dy, (*diff_max)[1].dx, (*diff_max)[1].dy, log2((*diff_max)[1].p), (uint32_t)trails_hash_map.size());
#endif

  double Bn = B[nrounds - 1] * SIMON_EPS;
  int r = 0;						  // initial round
  bool b_hash_map = true;
  double p_eps = 1.0;
#if 1
  simon_xor_threshold_search(r, nrounds, B, &Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, &diff_mset_p, &diff_set_dx_dy, &hways_diff_mset_p, &hways_diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy, &diffs_hash_map, &trails_hash_map, diff_max, b_hash_map, p_eps, p_thres);
#endif
}


void simon_best_trails_latex(differential_t trail_1[SIMON_TRAIL_LEN_MAX + 1], uint32_t trail_len_1,
									  differential_t trail_2[SIMON_TRAIL_LEN_MAX + 1], uint32_t trail_len_2,
									  differential_t trail_3[SIMON_TRAIL_LEN_MAX + 1], uint32_t trail_len_3,
									  differential_t trail_4[SIMON_TRAIL_LEN_MAX + 1], uint32_t trail_len_4)
{
  assert(trail_len_1 <= trail_len_2);
  assert(trail_len_2 <= trail_len_3);
  assert(trail_len_3 <= trail_len_4);

  uint32_t max_trail_len = trail_len_4;
  double p_1 = 1.0;
  double p_2 = 1.0;
  double p_3 = 1.0;
  double p_4 = 1.0;

  double p_diff_1 = -34;
  uint32_t ntrails_1 = 1;
  uint64_t nhways_1 = 128;
  double p_thres_1 = -4.05;
  uint32_t ntime_1 = 36;		  // minutes
  //  uint32_t max_hw_1 = 32;

  double p_diff_2 = -29.69;
  uint32_t ntrails_2 = 45083;
  uint64_t nhways_2 = 128;
  double p_thres_2 = -4.05;
  uint32_t ntime_2 = 47;		  // minutes
  //  uint32_t max_hw_2 = 32;

  double p_diff_3 = -42.11;
  uint32_t ntrails_3 = 112573;
  uint64_t nhways_3 = 128;
  double p_thres_3 = -4.05;
  uint32_t ntime_3 = 132;		  // minutes
  //  uint32_t max_hw_3 = 32;

  double p_diff_4 = -61.42;
  uint32_t ntrails_4 = 125084;
  uint64_t nhways_4 = 128;
  double p_thres_4 = -4.05;
  uint32_t ntime_4 = 778;		  // minutes
  //  uint32_t max_hw_4 = 32;

  FILE* fp = fopen(SIMON_BEST_TRAILS_LATEX_FILE, "w");

  fprintf(fp, "\\begin{table}[htp!]\n");
  fprintf(fp, "\\caption{Differential trails for \\textsc{Simon32}, \\textsc{Simon48} and \\textsc{Simon64}.}\n");
  fprintf(fp, "\\label{table:simon-trails}\n");
  fprintf(fp, "\\centering\n");
  fprintf(fp, "\\begin{tabular}{c|ccc|ccc|ccc|ccc}\n");
  fprintf(fp, "\n%%------------------------ START TABLE ---------------\n");
  fprintf(fp, "\\toprule\n");
  fprintf(fp, "  & & \\textsc{Simon32} & & ");
  fprintf(fp, "  & \\textsc{Simon32} & & ");
  fprintf(fp, "  & \\textsc{Simon48} & & ");
  fprintf(fp, "  & \\textsc{Simon64} & \\\\\n");
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
#if 1
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

  fprintf(fp, "\\midrule\n");

  fprintf(fp, " $\\mathrm{log}_2 p_{\\mathrm{thres}}$ & & & $%4.2f$ &", p_thres_1);
  fprintf(fp, " & & $%4.2f$ &", p_thres_2);
  fprintf(fp, " & & $%4.2f$ &", p_thres_3);
  fprintf(fp, " & & $%4.2f$ \\\\\n", p_thres_4);

  fprintf(fp, " $\{\\mathrm{pDDT}}$ & & & $%lld$ &", (WORD_MAX_T)nhways_1);
  fprintf(fp, " & & $%lld$ &", (WORD_MAX_T)nhways_2);
  fprintf(fp, " & & $%lld$ &", (WORD_MAX_T)nhways_3);
  fprintf(fp, " & & $%lld$ \\\\\n", (WORD_MAX_T)nhways_4);

  fprintf(fp, " Time: & & & $%d$ min. &", ntime_1);
  fprintf(fp, " & & $%d$ min. &", ntime_2);
  fprintf(fp, " & & $%d$ min. &", ntime_3);
  fprintf(fp, " & & $%d$ min. \\\\\n", ntime_4);
#endif
  fprintf(fp, "\\bottomrule\n");
  fprintf(fp, "%%------------------------ END TABLE ---------------\n");
  fprintf(fp, "\\end{tabular}\n");
  fprintf(fp, "\\end{table}\n");
  fclose(fp);
}

// 
// print the best found trails in LaTeX format
// 
void test_simon_best_trails_latex()
{
  assert(SIMON_TRAIL_LEN_MAX >= NROUNDS);
  uint32_t nrounds = 0;
  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;

#if 0									  // verify trails
  uint32_t dyy_init = 0;		  // dummy
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;
  uint32_t npairs = (1ULL << 22);

#if(WORD_SIZE == 16) 

  nrounds = 12;
  simon_verify_xor_trail(nrounds, npairs, key, g_simon32_trail_12r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(nrounds, npairs, key, g_simon32_trail_12r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  sleep(3);

  nrounds = 13;
  simon_verify_xor_trail(nrounds, npairs, key, g_simon32_trail_13r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(nrounds, npairs, key, g_simon32_trail_13r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  sleep(3);

#elif(WORD_SIZE == 24) 

  nrounds = 15;
  simon_verify_xor_trail(nrounds, npairs, key, g_simon48_trail_15r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(nrounds, npairs, key, g_simon48_trail_15r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  sleep(3);

#elif(WORD_SIZE == 32) 

  nrounds = 21;
  simon_verify_xor_trail(nrounds, npairs, key, g_simon64_trail_21r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(nrounds, npairs, key, g_simon64_trail_21r, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  sleep(3);

#endif  // #if(WORD_SIZE == 16) 
#endif

  nrounds = 12;
  differential_t simon32_round_diffs_12r[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(g_simon32_trail_12r, simon32_round_diffs_12r, nrounds, lrot_const_s, lrot_const_t, lrot_const_u);

  nrounds = 13;
  differential_t simon32_round_diffs_13r[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(g_simon32_trail_13r, simon32_round_diffs_13r, nrounds, lrot_const_s, lrot_const_t, lrot_const_u);

  nrounds = 15;
  differential_t simon48_round_diffs_15r[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(g_simon48_trail_15r, simon48_round_diffs_15r, nrounds, lrot_const_s, lrot_const_t, lrot_const_u);

  nrounds = 21;
  differential_t simon64_round_diffs_21r[SIMON_TRAIL_LEN_MAX + 1] = {{0, 0, 0, 0.0}};
  simon_trail_to_round_diffs(g_simon64_trail_21r, simon64_round_diffs_21r, nrounds, lrot_const_s, lrot_const_t, lrot_const_u);

  nrounds = 12;
  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  double p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, simon32_round_diffs_12r[i].dx, simon32_round_diffs_12r[i].dy, simon32_round_diffs_12r[i].p, log2(simon32_round_diffs_12r[i].p));
	 p_tot *= simon32_round_diffs_12r[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));

  nrounds = 13;
  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, simon32_round_diffs_13r[i].dx, simon32_round_diffs_13r[i].dy, simon32_round_diffs_13r[i].p, log2(simon32_round_diffs_13r[i].p));
	 p_tot *= simon32_round_diffs_13r[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));

  nrounds = 15;
  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, simon48_round_diffs_15r[i].dx, simon48_round_diffs_15r[i].dy, simon48_round_diffs_15r[i].p, log2(simon48_round_diffs_15r[i].p));
	 p_tot *= simon48_round_diffs_15r[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));

  nrounds = 21;
  printf("[%s:%d] Final trail (round differences):\n", __FILE__, __LINE__);
  p_tot = 1.0;
  for(uint32_t i = 0; i < (nrounds + 1); i++) {
	 printf("%2d: %8X -> %8X %f (2^%f)\n", i, simon64_round_diffs_21r[i].dx, simon64_round_diffs_21r[i].dy, simon64_round_diffs_21r[i].p, log2(simon64_round_diffs_21r[i].p));
	 p_tot *= simon64_round_diffs_21r[i].p;
  }
  printf("p_tot = %16.15f = 2^%f\n", p_tot, log2(p_tot));

  uint32_t simon32_12r_len = 12 + 1;
  uint32_t simon32_13r_len = 13 + 1;
  uint32_t simon48_15r_len = 15 + 1;
  uint32_t simon64_21r_len = 21 + 1;

  simon_best_trails_latex(simon32_round_diffs_12r, simon32_12r_len,
								  simon32_round_diffs_13r, simon32_13r_len,
								  simon48_round_diffs_15r, simon48_15r_len,
								  simon64_round_diffs_21r, simon64_21r_len);
}


/**
 * Main function.
 */
//int main()
int main (int argc, char ** argv)
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8lX\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  time_t rawtime;
  time(&rawtime);

#if 0
  if (argc != 3) {
	 printf("[%s:%d] Bad number fo arguments %d (must be 3)\n", __FILE__, __LINE__, argc);
	 return 1;
  }

  const uint32_t dx_in = atoi(argv[1]);
  const uint32_t dy_in = atoi(argv[2]);
  sprintf(logfile, "simon-0x%X-0x%X.log", dx_in, dy_in);

  //#OAR -t bigmem
  printf("dx_in = 0x%X\n", dx_in);
  printf("dy_in = 0x%X\n", dy_in);
  printf("logfile = %s\n", logfile);
  assert(dy_in < ALL_WORDS);
  assert(dx_in < ALL_WORDS);
  assert((dx_in != 0) || (dy_in != 0));

  FILE* fp = fopen(logfile, "w");
  fprintf(fp, "Time: %s", ctime (&rawtime));
  fprintf(fp, " dx_in 0x%X\n dy_in 0x%X\n logfile %s\n", dx_in, dy_in, logfile);
  fclose(fp);
#endif
#if 0
  char argfile[0xFFFF] = {0};
  sprintf(argfile, "simon-parallel-args");
  simon_gen_args_file(argfile);
#endif
#if 0
  char argfile[0xFFFF] = {0};
  sprintf(argfile, "simon-parallel-args-inv.txt");
  simon_gen_args_file_rot_invariant(argfile);
#endif
#if 0
  test_simon_diff_search(dx_in, dy_in, logfile);
#endif

  char logfile[0xFFFF] = {0};
  sprintf(logfile, "simon-params.log");
  FILE* fp = fopen(logfile, "w");
  fprintf(fp, "\nTime: %s", ctime (&rawtime));
  fprintf(fp, "[%s:%d]\n WORD_SIZE %d\n NROUNDS %d\n XDP_ROT_AND_P_THRES %f 2^%f\n XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f\n SIMON_EPS %f 2^%f\n XDP_ROT_AND_MAX_HW %d\n TRAIL_MAX_HW %d\n SIMON_BACK_TO_HWAY %d\n", 
			 __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), (WORD_MAX_T)XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY);
  fclose(fp);

  printf("[%s:%d] WORD_SIZE %d NROUNDS %d XDP_ROT_AND_P_THRES %f 2^%f XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f SIMON_EPS %f 2^%f XDP_ROT_AND_MAX_HW %d TRAIL_MAX_HW %d SIMON_BACK_TO_HWAY %d\n", 
			 __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), (WORD_MAX_T)XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY);

  //  test_simon_trails_graph_transition_matrix();
  test_simon_diff_search_fixed(); // cluster trails around a fixed trail
  //  test_simon_cluster_trails_datfile_read(); // read dat file stored by test_simon_diff_search_fixed()
  //  test_simon_multi_diff_search_fixed();
  //  test_simon_best_trails_latex();
  //  test_simon_xor_trail_search(); // threshold search (+ differential search)
  //  test_simon_diff_hash_custom();
  //  test_simon_trail_hash_custom();
  //  test_simon_test_code();
  //  test_time();
  //  test_simon_compute_full_ddt();
  //  test_simon32_ddt_file();
  //  test_oss_bug();
  //  test_simon_compute_partial_ddt();
  //  test_gen_word_hw();
  //  test_simon_verify_differential_gviz(); // + print data for GraphViz
  //  test_simon_cluster_trails();   // cluster trails around the best one
  //  test_simon_xor_ddt_trail_search(); // full DDT search
  //  test_simon_compute_round_diff_matrix();
  //  test_trail_to_string();
  //  test_best_trail_n16();

  printf("[%s:%d] WORD_SIZE %d NROUNDS %d XDP_ROT_AND_P_THRES %f 2^%f XDP_ROT_AND_MAX_DIFF_CNT %lld 2^%4.2f SIMON_EPS %f 2^%f XDP_ROT_AND_MAX_HW %d TRAIL_MAX_HW %d SIMON_BACK_TO_HWAY %d\n", 
			 __FILE__, __LINE__, WORD_SIZE, NROUNDS, XDP_ROT_AND_P_THRES, log2(XDP_ROT_AND_P_THRES), (WORD_MAX_T)XDP_ROT_AND_MAX_DIFF_CNT, log2(XDP_ROT_AND_MAX_DIFF_CNT), SIMON_EPS, log2(SIMON_EPS), XDP_ROT_AND_MAX_HW, TRAIL_MAX_HW, SIMON_BACK_TO_HWAY);

  return 0;
}
