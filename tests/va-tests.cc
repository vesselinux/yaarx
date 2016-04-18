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
 * \file  va-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Various tests that does not fit anywhere else and/or are under development.
 *
 * \attention This file contains compileable, but mostly obsolete code. 
 *            It is intended for debugging purpouses and is NOT used 
 *            in any of the YAARX programs
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef BSDR_H
#include "bsdr.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif
#ifndef GSL_PERMUTATION_H
#include <gsl/gsl_permutation.h>
#endif

/**
 * Test the condition for a non-zero probability ADP-XOR differential
 * (cf. Theorem 2, Wallen)
 */
void test_adp_xor_nonzero_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  //  uint32_t q = random32() % WORD_SIZE; // initial bit position
  //		uint32_t x = (random32() % 2);
  //		uint32_t y = (random32() % 2);
  for(uint32_t q = 0; q < WORD_SIZE; q++) {

	 for(uint32_t r = 1; r < 4; r++) { // skip x = y = 0

		const uint32_t x = r & 1;
		const uint32_t y = (r >> 1) & 1;
		const uint32_t z = x ^ y;

		printf("\n[%s:%d] --- q = %2d | %d %d %d ---\n", __FILE__, __LINE__, q, x, y, z);
		uint32_t cnt_all = 0;

		uint64_t N = (1ULL << (WORD_SIZE - q - 1)); // bits da[n-1:q+1]
		for(uint32_t i = 0; i < N; i++) {
		  for(uint32_t j = 0; j < N; j++) {
			 uint32_t cnt_o = 0;	  // output diffs
			 for(uint32_t k = 0; k < N; k++) {

				uint32_t da, db, dc;
				da = db = dc = 0;
				da |= (x << q);					  // da[q:0] = da[q] | 0*
				db |= (y << q);					  // db[q:0] = db[q] | 0*
				dc |= (z << q);					  // dc[q:0] = dc[q] | 0*

				da |= (i << (q+1));	  // da[n-1:q+1]
				db |= (j << (q+1));	  // db[n-1:q+1]
				dc |= (k << (q+1));	  // dc[n-1:q+1]

				bsd_t dc_naf = naf(dc);
				uint32_t dc_unaf = dc_naf.val;

#if 1
				printf("%10d ", cnt_all);
				print_binary(da);
				print_binary(db);
				print_binary(dc);
				print_binary(dc_unaf);
				printf("\n");
#endif
				double p = adp_xor(A, da, db, dc);
				assert(p != 0.0);
				cnt_all++;
				cnt_o++;
			 }
			 uint32_t tot_o_th = pow(2, (WORD_SIZE - q - 1));
			 printf("[%s:%d]Total out: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_o, tot_o_th, log2(cnt_o));
			 assert(tot_o_th == cnt_o);
		  }
		}
		uint32_t tot_th = pow(2, (3 * (WORD_SIZE - q - 1)));
		printf("[%s:%d]Total: %d %d (2^%f)\n", __FILE__, __LINE__, cnt_all, tot_th, log2(cnt_all));
		assert(tot_th == cnt_all);
		//		printf("\n[%s:%d] q = %2d | %d %d %d | total: %d (2^%f) | %d\n", __FILE__, __LINE__, q, x, y, z, cnt_all, log2(cnt_all), tot_th);
	 }

  }
  adp_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Test the condition under which  xdp-add is non-zero:
 * 
 * eq(da<<1, db<<1, dc<<1) & (da ^ db ^ dc ^ (da << 1))
 * 
 * See: [Lipmaa, Moriai, 2001]
 */
void test_xdp_add_nonzero_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		printf("[%s:%d] --- %8X %8X ---\n", __FILE__, __LINE__, i, j);
		for(uint32_t k = 0; k < ALL_WORDS; k++) {
		  uint32_t da = i;
		  uint32_t db = j;
		  uint32_t dc = k;

		  double p = xdp_add(A, da, db, dc);
#if 1
		  if(p != 0.0) {
			 print_binary(da);
			 print_binary(db);
			 print_binary(dc);
			 //		  print_binary(dc_unaf);
			 printf("\n");
		  }
#endif
		  if(p != 0.0) {
			 bool b_always_sat = true;
			 for(uint32_t t = 1; t < WORD_SIZE; t++) {
				uint32_t tt = t -1;
				uint32_t x = (da >> t) & 1;
				uint32_t y = (db >> t) & 1;
				uint32_t z = (dc >> t) & 1;
				uint32_t xx = (da >> tt) & 1;
				uint32_t yy = (db >> tt) & 1;
				uint32_t zz = (dc >> tt) & 1;
				bool b_cond = (((xx == 0) && (yy == 0) && (zz == 0)) || 
									((xx == 1) && (yy == 1) && (zz == 1)));
				if(b_cond) {
				  uint32_t q = x ^ y ^ z;
				  uint32_t qq = xx ^ yy ^ zz;
				  //				  printf("| (%d %d)", q, qq);
				  if(q != qq) {
					 b_always_sat = false;
				  }
				  assert(q == qq);
				}
			 }
			 assert(b_always_sat == true);
		  } else {
			 bool b_always_sat = true;
			 for(uint32_t t = 0; t < WORD_SIZE; t++) {
				uint32_t tt = t -1;
				uint32_t x = (da >> t) & 1;
				uint32_t y = (db >> t) & 1;
				uint32_t z = (dc >> t) & 1;
				uint32_t xx = (da >> tt) & 1;
				uint32_t yy = (db >> tt) & 1;
				uint32_t zz = (dc >> tt) & 1;
				bool b_cond = (((xx == 0) && (yy == 0) && (zz == 0)) || 
									((xx == 1) && (yy == 1) && (zz == 1)));
				if(b_cond) {
				  uint32_t q = x ^ y ^ z;
				  uint32_t qq = xx ^ yy ^ zz;
				  //				  printf("| (%d %d)", q, qq);
				  if(q != qq) {
					 b_always_sat = false;
				  }
				}
			 }
			 assert(b_always_sat == false);
		  }
		}
	 }
  }

  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Test the indices for the non-zero condition for xdp-add
 */
void test_xdp_add_nonzero_index_cond()
{
  uint32_t N = (1U << 6);

  for(uint32_t x = 0; x < N; x++) {
	 uint32_t i = (x >> 0) & 1;
	 uint32_t j = (x >> 1) & 1;
	 uint32_t k = (x >> 2) & 1;
	 uint32_t ii = (x >> 3) & 1;
	 uint32_t jj = (x >> 4) & 1;
	 uint32_t kk = (x >> 5) & 1;

	 // condition for: A * A_{111} * X  != 0 if c == 1
	 uint32_t c111 = (ii ^ jj ^ kk) & (i & j & k);

	 // condition for: A * A_{000} * X if c == 1
	 uint32_t c000 = (1 ^ (ii ^ jj ^ kk)) & ((1 ^ i) & (1 ^ j) & (1 ^ k));

	 //uint32_t c = 

	 if((c000 ^ c111) == 1) {
		printf("[%s:%d] %d%d%d|%d%d%d : %d %d\n", __FILE__, __LINE__, kk, jj, ii, k, j, i, c000, c111);
	 }

#if 0
	 if(c111 == 1) {
		printf("[%s:%d] %d%d%d|%d%d%d : %d %d\n", __FILE__, __LINE__, kk, jj, ii, k, j, i, c000, c111);
	 }
#endif
#if 0
	 if(c000 == 1) {
		printf("[%s:%d] %d%d%d|%d%d%d : %d %d\n", __FILE__, __LINE__, kk, jj, ii, k, j, i, c000, c111);
	 }
#endif
  }
}

void test_xdp_add_nonzero_cond()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		//		printf("[%s:%d] --- %8X %8X ---\n", __FILE__, __LINE__, i, j);
		for(uint32_t k = 0; k < ALL_WORDS; k++) {
		  uint32_t da = i;
		  uint32_t db = j;
		  uint32_t dc = k;

		  //		  uint32_t da_unaf = naf(da).val;
		  //		  uint32_t db_unaf = naf(db).val;
		  //		  uint32_t dc_unaf = naf(dc).val;

		  double p =  xdp_add(A, da, db, dc);
		  double p1 = xdp_add(A, da, dc, db);
		  double p2 = xdp_add(A, db, da, dc);
		  double p3 = xdp_add(A, db, dc, da);
		  double p4 = xdp_add(A, dc, db, da);
		  double p5 = xdp_add(A, dc, da, db);

		  assert(p == p1);
		  assert(p == p2);
		  assert(p == p3);
		  assert(p == p4);
		  assert(p == p5);

#if 1
		  if(p != 0.0) {
			 print_binary(da);
			 print_binary(db);
			 print_binary(dc);
			 //			 printf("|");
			 //			 print_binary(da_unaf);
			 //			 print_binary(db_unaf);
			 //			 print_binary(dc_unaf);
			 printf("\n");
		  }
#endif

		}
	 }
  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Combine two output sets \p dc_set_0 and \p dc_set_1 from XDP-ADD,
 * to produce a single set.
 */
void xdp_add_combine_output_diff_sets(diff_set_t* dc_set, 
												  const diff_set_t dc_sets_in[2]) 
{
  // initialize
  dc_set->diff = 0;
  dc_set->fixed = 0;

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t dc_diff_i[2] = {0,0};
	 uint32_t dc_fixed_i[2] = {0,0};

	 for(uint32_t j = 0; j < 2; j++) {
		dc_diff_i[j] = (dc_sets_in[j].diff >> i) & 1; 
		dc_fixed_i[j] = (dc_sets_in[j].fixed >> i) & 1;
	 }

	 if((dc_fixed_i[0] == STAR) && (dc_fixed_i[1] == STAR)) { // (*,*)
		  dc_set->diff |= (dc_diff_i[0] << i);					  // dc[i] = dc0[i] = dc1[i]
		  dc_set->fixed |= (STAR << i);		
	 }
	 if((dc_fixed_i[0] == FIXED) && (dc_fixed_i[1] == FIXED)) { // (-,-)
		if(dc_diff_i[0] == dc_diff_i[1]) { // fixed and equal
			 dc_set->diff |= (dc_diff_i[0] << i);
			 dc_set->fixed |= (FIXED << i);		
		  } else { // fixed and different
			 dc_set->diff |= (dc_diff_i[0] << i);
			 dc_set->fixed |= (STAR << i);		
		  }
	 }
	 if((dc_fixed_i[0] == FIXED) && (dc_fixed_i[1] == STAR)) { // (-,*)
		  dc_set->diff |= (dc_diff_i[0] << i);					  // dc[i] = dc0[i]
		  dc_set->fixed |= (FIXED << i);		
	 }
	 if((dc_fixed_i[0] == STAR) && (dc_fixed_i[1] == FIXED)) { // (*,-)
		  dc_set->diff |= (dc_diff_i[1] << i);					  // dc[i] = dc1[i]
		  dc_set->fixed |= (FIXED << i);		
	 }
  }
}

/**
 * Test for \ref xdp_add_combine_output_diff_sets and \ref xdp_add_input_diff_sets_to_diffs .
 */
void test_xdp_add_combine_output_diff_sets()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};
  diff_set_t dc_set_arr[2] = {{0,0}};
  diff_set_t dc_set = {0,0};

  da_set.diff = random32() & MASK;
  da_set.fixed = random32() & MASK;

  db_set.diff = random32() & MASK;
  db_set.fixed = random32() & MASK;

  xdp_add_input_diff_sets_to_diffs(da_set, db_set, da, db);

  printf("[%s:%d] Input sets: da (%8X,%8X), db (%8X,%8X)\n", 
			__FILE__, __LINE__, da_set.diff, da_set.fixed, db_set.diff, db_set.fixed);
  printf("[%s:%d] Output diffs: 0:(%8X,%8X), 1:(%8X,%8X)\n",
			__FILE__, __LINE__, da[0], db[0], da[1], db[1]);

  for(uint32_t j = 0; j < 2; j++) {
	 xdp_add_output_diff_set(da[j], db[j], &dc_set_arr[j]);
  }

  xdp_add_combine_output_diff_sets(&dc_set, dc_set_arr);

  std::vector<uint32_t> dc_set_all;
  xdp_add_diff_set_gen_all(dc_set, &dc_set_all);

  for(uint32_t j = 0; j < 2; j++) {
	 std::vector<uint32_t>::iterator dc_iter;
	 for(dc_iter = dc_set_all.begin(); dc_iter != dc_set_all.end(); dc_iter++) {
		uint32_t dc = *dc_iter;
		double p_i = xdp_add(A, da[j], db[j], dc);
#if 1									  // DEBUG
		printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da[j], db[j], dc, p_i);
#endif
	 }
  }

  //  printf("[%s:%d] p = %f\n", __FILE__, __LINE__, p);
  xdp_add_free_matrices(A);
}

/**
 * Test for \ref xdp_add_combine_output_diff_sets and \ref xdp_add_input_diff_sets_to_diffs 
 * over all possible inputs.
 */
void test_xdp_add_combine_output_diff_sets_all()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};
  diff_set_t dc_set_arr[2] = {{0,0}};
  diff_set_t dc_set = {0,0};

  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff = d1;
			 da_set.fixed = f1;
			 db_set.diff = d2;
			 db_set.fixed = f2;

			 // Compute (da^0, db^0), (da^1, db^1)
			 xdp_add_input_diff_sets_to_diffs(da_set, db_set, da, db);

			 printf("[%s:%d] Input sets: da (%8X,%8X), db (%8X,%8X)\n", 
					  __FILE__, __LINE__, da_set.diff, da_set.fixed, db_set.diff, db_set.fixed);
			 printf("[%s:%d] Output diffs: 0:(%8X,%8X), 1:(%8X,%8X)\n",
					  __FILE__, __LINE__, da[0], db[0], da[1], db[1]);

			 for(uint32_t j = 0; j < 2; j++) {
				xdp_add_output_diff_set(da[j], db[j], &dc_set_arr[j]);
			 }

			 xdp_add_combine_output_diff_sets(&dc_set, dc_set_arr);

			 std::vector<uint32_t> dc_set_all;
			 xdp_add_diff_set_gen_all(dc_set, &dc_set_all);

			 for(uint32_t j = 0; j < 2; j++) {
				std::vector<uint32_t>::iterator dc_iter;
				for(dc_iter = dc_set_all.begin(); dc_iter != dc_set_all.end(); dc_iter++) {
				  uint32_t dc = *dc_iter;
				  double p_i = xdp_add(A, da[j], db[j], dc);
#if 1									  // DEBUG
				  printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							__FILE__, __LINE__, da[j], db[j], dc, p_i);
#endif
				  //				  assert(p_i != 0.0);
				}
			 }
		  }
		}
	 }
  }
  //  printf("[%s:%d] p = %f\n", __FILE__, __LINE__, p);
  xdp_add_free_matrices(A);
}

/**
 * Test for \ref xdp_add_combine_output_diff_sets and \ref xdp_add_input_diff_sets_to_diffs .
 */
void test_xdp_add_combine_output_diff_sets_2()
{
  diff_set_t dc_set = {0,0};
  diff_set_t dc_set_arr[2] = {{0,0}};

  for(uint32_t j = 0; j < 2; j++) {
	 dc_set_arr[j].diff = random32() & MASK;
	 dc_set_arr[j].fixed = random32() & MASK;
  }

  std::vector<uint32_t> dc_set_0;
  xdp_add_diff_set_gen_all(dc_set_arr[0], &dc_set_0);

  std::vector<uint32_t> dc_set_1;
  xdp_add_diff_set_gen_all(dc_set_arr[1], &dc_set_1);

  xdp_add_combine_output_diff_sets(&dc_set, dc_set_arr);

  std::vector<uint32_t> dc_set_all;
  xdp_add_diff_set_gen_all(dc_set, &dc_set_all);

  std::vector<uint32_t>::iterator dc_iter_0;
  printf("[%s:%d] Set 0: (%8X %8X)\n", __FILE__, __LINE__, dc_set_arr[0].diff, dc_set_arr[0].fixed);
  for(dc_iter_0 = dc_set_0.begin(); dc_iter_0 != dc_set_0.end(); dc_iter_0++) {
	 uint32_t dc = *dc_iter_0;
	 printf("%8X\n", dc);
  }
  std::vector<uint32_t>::iterator dc_iter_1;
  printf("[%s:%d] Set 1: (%8X %8X)\n", __FILE__, __LINE__, dc_set_arr[1].diff, dc_set_arr[1].fixed);
  for(dc_iter_1 = dc_set_1.begin(); dc_iter_1 != dc_set_1.end(); dc_iter_1++) {
	 uint32_t dc = *dc_iter_1;
	 printf("%8X\n", dc);
  }
  std::vector<uint32_t>::iterator dc_iter_all;
  printf("[%s:%d] Set ALL: (%8X %8X)\n", __FILE__, __LINE__, dc_set.diff, dc_set.fixed);
  for(dc_iter_all = dc_set_all.begin(); dc_iter_all != dc_set_all.end(); dc_iter_all++) {
	 uint32_t dc = *dc_iter_all;
	 printf("%8X\n", dc);
  }

}

/**
 * Constructing a set of output differences for xdp-add.
 */
void test_xdp_add_input_diff_to_output_dset()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  uint32_t cnt = 0;

  //  uint32_t da = 0;//0x3F;//random32() & MASK;
  //  uint32_t db = 5;//0x3F;//random32() & MASK;
  for(uint32_t da = 0; da < ALL_WORDS; da++) {
		for(uint32_t db = 0; db < ALL_WORDS; db++) {

		uint32_t chi = (da ^ db);

		// if g[i] = 1, dc[i] can be anything i.e. g[i] == *
		uint32_t g = 0;
		uint32_t star = 1;

		uint32_t dc = 0;

		dc |= (da & 1) ^ (db & 1);	  // dc[0] = da[0] ^ db[0]

		for(uint32_t i = 1; i < WORD_SIZE; i++) {

		  uint32_t dc_prev = (dc >> (i - 1)) & 1;
		  uint32_t g_prev = (g >> (i - 1)) & 1;
		  uint32_t chi_this = (chi >> i) & 1;
		  //		  uint32_t chi_prev = (chi >> (i - 1)) & 1;
		  uint32_t da_this = (da >> i) & 1;
		  uint32_t db_this = (db >> i) & 1;
		  uint32_t da_prev = (da >> (i-1)) & 1;
		  uint32_t db_prev = (db >> (i-1)) & 1;

		  if((g_prev != star) || (i == 1)) { // dc[i] = da[i] ^ db[i] ^ dc[i-1]
			 if(i > 1) {
				dc |= (da_this ^ db_this ^ dc_prev) << i;
				g |= (0 << i);			  // fixed
			 } else {					  // i == 1
				if((da_prev == db_prev) && (da_prev == dc_prev)) {
				  dc |= (da_this ^ db_this ^ dc_prev) << i;
				  g |= (0 << i);			  // fixed
				} else {
				  if(chi_this == 1) {
					 g |= (star << i);		  // *
					 dc |= (0 << i);			  // dc[i] = *
				  } else {
					 g |= (0 << i);			  // fixed
					 dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
				  }
				}
			 }
		  } else {
			 //			 assert(1 == 0);
			 if((chi_this == 1) || (i == (WORD_SIZE - 1))) {
				g |= (star << i);		  // *
				dc |= (0 << i);			  // dc[i] = *
			 } else {
				g |= (0 << i);			  // fixed
				dc |= (da_this << i);			  // dc[i] = da[i] = db[i]
			 }
		  }
		}

		double p = xdp_add(A, da, db, dc);
		printf("[%s:%d] %8X %8X (%8X %8X) %f\n", __FILE__, __LINE__, da, db, dc, g, p);
		assert(p != 0.0);

#if 0
		print_binary(da);
		printf("\n");
		print_binary(db);
		printf("\n");
		print_binary(dc);
		printf("\n");
		print_binary(g);
		printf("\n");
#endif

		for(uint32_t i = 0; i < WORD_SIZE; i++) {

		  uint32_t t = (g >> i) & 1;
		  if(t == 0)
			 continue;

		  uint32_t dc_new = dc ^ (1 << i);
		  double pp = xdp_add(A, da, db, dc_new);
		  printf("[%s:%d] %8X %8X (%8X %8X) %f\n", __FILE__, __LINE__, da, db, dc_new, g, pp);
#if 0
		  print_binary(da);
		  printf("\n");
		  print_binary(db);
		  printf("\n");
		  print_binary(dc_new);
		  printf("\n");
		  print_binary(g);
		  printf("\n");
#endif
		  assert(pp != 0.0);

		  p += pp;
		}
		double p_max = max_xdp_add(A, da, db, &dc);
		if(p >= p_max) {
		  printf("[%s:%d] %d: %f %f\n", __FILE__, __LINE__, cnt++, p, p_max);
		}
		//		printf("Total: %f, max (%f %8X)\n", p, p_max, dc);
#if 0
		print_binary(da);
		printf("\n");
		print_binary(db);
		printf("\n");
		print_binary(dc);
		printf("\n");
#endif
	 }
  }

  xdp_add_free_matrices(A);
}

/**
 * Test if the output set dc generated from \f$(da^0, db^0)\f$ or \f$(da^1, db^1)\f$
 * is maximum with respect to all \f$da \in A\f$, \f$db \in B\f$.
 */
void test_xdp_add_dc_set_is_max()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};

  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff  = d1;
			 da_set.fixed = f1;//0xffffffff & MASK;//f1;
			 db_set.diff  = d2;
			 db_set.fixed = f2;//0xffffffff & MASK;//f2;

			 xdp_add_input_dsets_to_input_diffs(da_set, db_set, da, db);

#if 1									  // DEBUG
			 printf("[%s:%d]\n", __FILE__, __LINE__);
			 printf("\n da = ");
			 xdp_add_dset_print_set(da_set);
			 print_binary(da[0]);
			 print_binary(da[1]);
			 printf("\n db = ");
			 xdp_add_dset_print_set(db_set);
			 print_binary(db[0]);
			 print_binary(db[1]);
			 printf("\n");
#endif
#if 0									  // DEBUG
			 printf("[%s:%d] Input sets: da (%8X,%8X), db (%8X,%8X)\n", 
					  __FILE__, __LINE__, da_set.diff, da_set.fixed, db_set.diff, db_set.fixed);
			 printf("[%s:%d] Input diffs: 0:(%8X,%8X), 1:(%8X,%8X)\n",
					  __FILE__, __LINE__, da[0], db[0], da[1], db[1]);
#endif
			 diff_set_t dc_set[2] = {{0,0}};
			 uint32_t dc_set_len[2] = {0};

			 double p[2] = {0.0, 0.0};
			 for(uint32_t j = 0; j < 2; j++) {
				xdp_add_input_diff_to_output_dset(da[j], db[j], &dc_set[j]);
#if 1									  // DEBUG
				printf("\ndc%d = ", j);
				xdp_add_dset_print_set(dc_set[j]);
				printf("\n");
#endif
				std::vector<uint32_t> dc_set_all;
				xdp_add_dset_gen_diff_all(dc_set[j], &dc_set_all);

				dc_set_len[j] = dc_set_all.size();

				std::vector<uint32_t>::iterator vec_iter;
				for(vec_iter = dc_set_all.begin(); vec_iter != dc_set_all.end(); vec_iter++) {
				  uint32_t dc_i = *vec_iter;
				  double p_i = xdp_add(A, da[j], db[j], dc_i);
#if 0								  // DEBUG
				  printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							__FILE__, __LINE__, da[j], db[j], dc_i, p_i);
#endif
				  assert(p_i != 0.0);
				  p[j] += p_i;
				}
#if 1								  // DEBUG
				printf("[%s:%d] p[%d] = %f\n", __FILE__, __LINE__, j, p[j]);
#endif
#if 1	  // DEBUG ----------
				diff_set_t da_set_temp = {da[j],0};
				diff_set_t db_set_temp = {db[j],0};
				double pp = xdp_add_dset(AA, WORD_SIZE, da_set_temp, db_set_temp, dc_set[j]);
				assert(p[j] == pp);
				//				double pp = xdp_add_dset(AA, da_set, db_set, dc_set[j]);
				//				printf("[%s:%d]pp[%d] = %f\n", __FILE__, __LINE__, j, pp);
				//				assert(p[j] <= pp); // NO
#endif  // DEBUG ----------
			 }

			 double p_max = 0.0;
			 p_max = std::max(p[0],p[1]);

			 diff_set_t dc_set_out = {0,0};
			 uint32_t hw0 = hw32(da[0] ^ db[0]);
			 uint32_t hw1 = hw32(da[1] ^ db[1]);
			 if(hw0 > hw1) {
				dc_set_out = {dc_set[1].diff, dc_set[1].fixed};
				assert(p[0] < p[1]);
			 }
			 if(hw0 < hw1) {
				dc_set_out = {dc_set[0].diff, dc_set[0].fixed};
				assert(p[0] > p[1]);
			 }
			 if(hw0 == hw1) {
				if(dc_set_len[0] >= dc_set_len[1]) {
				  dc_set_out = {dc_set[0].diff, dc_set[0].fixed};
				} else {
				  dc_set_out = {dc_set[1].diff, dc_set[1].fixed};
				}
			 }

			 //			 assert(p[0] >= p[1]);

			 std::vector<uint32_t> da_set_all;
			 xdp_add_dset_gen_diff_all(da_set, &da_set_all);
			 std::vector<uint32_t>::iterator da_iter = da_set_all.begin();

			 std::vector<uint32_t> db_set_all;
			 xdp_add_dset_gen_diff_all(db_set, &db_set_all);
			 std::vector<uint32_t>::iterator db_iter = db_set_all.begin();

			 for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
				for(db_iter = db_set_all.begin(); db_iter != db_set_all.end(); db_iter++) {
				  uint32_t da_i = *da_iter;
				  uint32_t db_i = *db_iter;

				  diff_set_t dc_set_i = {0,0};
				  xdp_add_input_diff_to_output_dset(da_i, db_i, &dc_set_i);
				  std::vector<uint32_t> dc_set_all_i;
				  xdp_add_dset_gen_diff_all(dc_set_i, &dc_set_all_i);

				  double p_max_i = 0.0;
				  uint32_t dc_max_i = 0;
				  std::vector<uint32_t>::iterator vec_iter;
				  for(vec_iter = dc_set_all_i.begin(); vec_iter != dc_set_all_i.end(); vec_iter++) {
					 uint32_t dc_i = *vec_iter;
					 double p_i = xdp_add(A, da_i, db_i, dc_i);
#if 1									  // DEBUG
					 printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							  __FILE__, __LINE__, da_i, db_i, dc_i, p_i);
#endif
					 assert(p_i != 0.0);
					 if(p_i > p_max_i) {
						p_max_i = p_i;		  // !
						dc_max_i = da_i;
					 }
				  }
#if 0									  // DEBUG
				  printf("[%s:%d] MAX_XDP_ADD_i[(%8X,%8X)->%8X] = %f | %f\n", 
							__FILE__, __LINE__, da_i, db_i, 
							dc_max_i, p_max_i, p_max);
#endif
				  //				  uint32_t dc_temp = 0;
				  p_max_i = max_xdp_add(A, da_i, db_i, &dc_max_i);
				  if(p_max_i > p_max) {
					 printf("[%s:%d] p_max_i %f, p_max %f ", __FILE__, __LINE__, p_max_i, p_max);
					 printf("%8X %8X -> {%8X,%8X} vs. {%8X,%8X}\n", da_i, db_i, dc_set_i.diff, dc_set_i.fixed, dc_set_out.diff, dc_set_out.fixed);
				  }
				  //				  printf("[%s:%d]p_max_i = %f\n", __FILE__, __LINE__, p_max_i);
				  assert(p_max_i <= p_max);
				}
			 }

		  }
		}
	 }
  }

  xdp_add_dset_free_matrices(AA);
  xdp_add_free_matrices(A);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void speck_xdp_add_pddt_gen_random(uint32_t hw_thres, double p_thres, const uint64_t max_size,
											  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
											  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p)
{
  //  uint32_t n = WORD_SIZE;
  //  double p_thres = P_THRES;
  double p = 0.0;

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  // init C
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);


  uint64_t cnt = 0;

  uint32_t hway_old_size = diff_set_dx_dy_dz->size();
  while(cnt < max_size) {

	 uint32_t da = gen_sparse(hw_thres, WORD_SIZE);
	 uint32_t db = gen_sparse(hw_thres, WORD_SIZE);
	 uint32_t dc = 0;//gen_sparse(hw_thres, WORD_SIZE);
	 //	 double p = xdp_add(A, da, db, dc);

	 p = max_xdp_add_lm(da, db, &dc);

	 if((p >= p_thres) && (hw32(dc) <= hw_thres)) {

		differential_3d_t new_diff;
		new_diff.dx = da;
		new_diff.dy = db;
		new_diff.dz = dc;
		new_diff.p = p;
		uint32_t old_size = diff_set_dx_dy_dz->size();
		diff_set_dx_dy_dz->insert(new_diff);
		if(old_size != diff_set_dx_dy_dz->size()) {
		  diff_mset_p->insert(new_diff);
#if 1									  // DEBUG
		  uint32_t hway_size = diff_set_dx_dy_dz->size();
		  //		  printf("\r[%s:%d] [%10lld / %10lld] | Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f  HW size %d 2^%f", __FILE__, __LINE__, cnt, max_size, da, db, dc, p, log2(p), log2(p_thres), hway_size, log2(hway_size));
		  printf("\r[%s:%d] Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f  HW size %d 2^%f", __FILE__, __LINE__, da, db, dc, p, log2(p), log2(p_thres), hway_size, log2(hway_size));
		  fflush(stdout);
#endif
		  cnt++;
		}
	 }
  }
  uint32_t hway_new_size = diff_set_dx_dy_dz->size();

  assert((hway_new_size - hway_old_size) == max_size);

  printf("[%s:%d] HW size %d 2^%f\n", __FILE__, __LINE__, hway_new_size, log2(hway_new_size));

  //  speck_xdp_add_pddt_i(k, n, p_thres, A, C, &da, &db, &dc, &p, diff_set_dx_dy_dz, diff_mset_p, max_size);
#if 0									  // DEBUG
  printf("[%s:%d] p_thres = %f (2^%f), n = %d, #diffs = %d\n", __FILE__, __LINE__, 
			p_thres, log2(p_thres), WORD_SIZE, diff_mset_p->size());
#endif
  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());

  gsl_vector_free(C);
  xdp_add_free_matrices(A);
}

/**
 * For fixed da, db, generate max_size set of dc such that p(da, db -> dc) >= p_thres 
 * and (optinally) HW(dc) >= hw_thres.
 */
uint32_t speck_xdp_add_dx_dy_pddt_gen_dset( const uint32_t da, const uint32_t db, const double p_thres,
														  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
														  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p)
{
  uint64_t cnt = 0;

  diff_set_t dc_set;
  xdp_add_input_diff_to_output_dset(da, db, &dc_set);
  
  //  uint64_t dc_set_size = xdp_add_dset_size(dc_set);

  //  std::vector<uint32_t> dc_set_all;
  //  xdp_add_dset_gen_diff_all(dc_set, &dc_set_all);
  uint32_t nfree = hw32(dc_set.fixed & MASK);	  // number of free (non-fixed) positions
  uint32_t N = (1U << (nfree));
  double logN = log2(N);

  uint32_t max_vals = N;//32;//16;

  uint32_t nrand_vals = std::min((const uint64_t)N, (const uint64_t)max_vals);

  //  for(uint32_t i = 0; i < N; i++) { // all values of the free positions
  for(uint32_t val = 0; val < nrand_vals; val++) { // nvals random values

	 uint32_t i = random32() % N;
	 if(nrand_vals == N) {
		i = val;
	 }

	 uint32_t dc_new = dc_set.diff;
	 uint32_t i_pos = 0;				  // counting the bit position within the log2(N)-bit value i

	 for(uint32_t j = 0; j < WORD_SIZE; j++) {
		uint32_t is_fixed = (dc_set.fixed >> j) & 1;

		if(is_fixed == STAR) {		  // the position is free
		  uint32_t val = (i >> i_pos) & 1;
		  dc_new ^= (val << j);	  // flip the bit at the free position
		  assert((double)i_pos < logN);
		  i_pos++;
		}
	 }

	 uint32_t db_next = LROT(db, SPECK_LEFT_ROT_CONST) ^ dc_new;
	 bool b_is_low_hw_next = (hw32(dc_new) <= SPECK_MAX_HW) && (hw32(db_next) <= SPECK_MAX_HW);

	 if((b_is_low_hw_next) && (da != 0) && (db != 0)) {

		double p = xdp_add_lm(da, db, dc_new);

		if(p >= p_thres) {

		  differential_3d_t new_diff;
		  new_diff.dx = da;
		  new_diff.dy = db;
		  new_diff.dz = dc_new;
		  new_diff.p = p;
		  uint32_t old_size = diff_set_dx_dy_dz->size();
		  diff_set_dx_dy_dz->insert(new_diff);
		  if(old_size != diff_set_dx_dy_dz->size()) {
			 diff_mset_p->insert(new_diff);
#if 1									  // DEBUG
			 uint32_t hway_size = diff_set_dx_dy_dz->size();
			 printf("\r[%s:%d] Add %8X %8X -> %8X : %f 2^%4.2f | 2^%4.2f  HW size %d 2^%f", __FILE__, __LINE__, da, db, dc_new, p, log2(p), log2(p_thres), hway_size, log2(hway_size));
			 fflush(stdout);
#endif
			 cnt++;
		  }
		}
	 }
	 assert(i_pos == log2(N));
  }
  assert(diff_set_dx_dy_dz->size() == diff_mset_p->size());
  return cnt;
}

/*
 * Original thershold search. Has option for back-to-highway + can be used also for clustering of trails.
 * TODO: Obsolete! Should be removed. For trail search we use \p speck_xor_threshold_search_simple
 * and for clustering \p speck_xor_cluster_trails_boost
 */
void speck_xor_threshold_search(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
										  const differential_t diff_in[NROUNDS], uint32_t dx_init_in, uint32_t dy_init_in, 
										  differential_t trail[NROUNDS], uint32_t* dx_init, uint32_t* dy_init,
										  uint32_t right_rot_const, uint32_t left_rot_const,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p, // country roads
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
										  double p_thres, bool b_speck_cluster_trails)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 bool b_end = false;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		uint32_t dz = mset_iter->dz;
		pn = mset_iter->p;
		uint32_t dxx = dz;		                     // x_{i+1}
		uint32_t dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((pn >= *Bn) && (pn != 0.0)) {
		  dx_init_in = LROT(dx, right_rot_const);
		  dy_init_in = dy;
		  trail[n].dx = dxx;		  // dx_{i+1}
		  trail[n].dy = dyy;		  // dy_{i+1} 
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
		cnt++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx; // alpha
		uint32_t dy = mset_iter->dy; // gamma
		uint32_t dz = mset_iter->dz;
		pn = mset_iter->p;
		uint32_t dxx = dz;		                     // x_{i+1}
		uint32_t dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
		std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator begin_iter = diff_mset_p->begin();
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) {
#if 0									  // DEBUG
		  if((dx == 0x8000) && (dy == 0)) {
			 printf("\n[%s:%d] CHECKPOINT! (%X %X -> %X %f) (%X %X)\n", __FILE__, __LINE__, dx, dy, dz, pn, dx_init_in, dy_init_in);
			 sleep(3);
		  }
#endif
		  dx_init_in = LROT(dx, right_rot_const);
		  dy_init_in = dy;
		  diff[n].dx = dxx;		  // dx_{i+1}
		  diff[n].dy = dyy;		  // dy_{i+1} 
		  diff[n].p = pn;
		  speck_xor_threshold_search(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  cnt = 0;
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }
  }

  // Greedy !!!
#if SPECK_GREEDY_SEARCH
  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round
  //  if(0) {

	 uint32_t dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 uint32_t dy = diff[n - 1].dy; // the y input to ADD
	 uint32_t dz = 0;


	 pn = max_xdp_add_lm(dx, dy, &dz);
	 uint32_t dxx = dz;		                     // x_{i+1}
	 uint32_t dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p = p * pn * B[nrounds - 1 - (n + 1)];

	 if((p >= *Bn) && (p != 0.0)) {
		diff[n].dx = dxx;		  // dx_{i+1}
		diff[n].dy = dyy;		  // dy_{i+1} 
		diff[n].p = pn;
		speck_xor_threshold_search(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);
	 } 
  }
#else	 // Threshold search
  //  if(0) {							  // !!!
  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 uint32_t dy = diff[n - 1].dy; // the y input to ADD

	 differential_3d_t diff_dz;
	 diff_dz.dx = dx;  			  // alpha
	 diff_dz.dy = dy;
	 diff_dz.dz = 0;
	 diff_dz.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);

#if 0									  // DEBUG
	 printf("[%s:%d] Found in HWays: %8X %8X %8X 2^%f\n", __FILE__, __LINE__, hway_iter->dx, hway_iter->dy, hway_iter->dz, log2(hway_iter->p));
#endif

#define CLEAR_CROADS 1
#if CLEAR_CROADS								  // !!!
	 croads_diff_set_dx_dy_dz->clear();
	 croads_diff_mset_p->clear();
#endif

	 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
	 bool b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);

#if CLEAR_CROADS
	 assert(b_found_in_croads == false);
#endif

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 assert(diff_set_dx_dy_dz->size() != 0);

	 const uint32_t max_cnt = (1ULL << (WORD_SIZE - 1));//SPECK_MAX_DIFF_CNT; 

#if 0								  // DEBUG
	 printf("\n ----------------------------------------------------------------------------------------\n");
	 printf("[%s:%d] Find in CR or HW (dx_rrot dy) = (%8X %8X)\n", __FILE__, __LINE__, dx, dy);
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 uint32_t cnt_new = speck_xdp_add_dx_dy_pddt(dx, dy, diff_set_dx_dy_dz, diff_mset_p, croads_diff_set_dx_dy_dz, croads_diff_mset_p, right_rot_const, left_rot_const, p_min, max_cnt, b_speck_cluster_trails);

	 if(cnt_new != 0) {
#if 0									  // DEBUG
		printf("[%s:%d] [%2d / %2d]: Added %d new CR dx dy %8X %8X: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d.\n", __FILE__, __LINE__, n, NROUNDS, cnt_new, dx, dy, p_min, log2(p_min), croads_diff_set_dx_dy_dz->size(), croads_diff_mset_p->size());
#endif
		croad_iter = croads_diff_set_dx_dy_dz->lower_bound(diff_dz);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy_dz->end()) && (croad_iter->dx == dx) && (croad_iter->dy == dy);
	 } else {
#if 0									  // DEBUG
		//		printf("\r[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
		//		fflush(stdout);
		printf("[%s:%d] [%2d / %2d]: No new country roads found: p_min = %f (2^%f).\n", __FILE__, __LINE__, n, NROUNDS, p_min, log2(p_min));
#endif
	 }

	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy_dz;
	 std::multiset<differential_3d_t, struct_comp_diff_3d_p> found_mset_p;

	 if(b_found_in_hways) {
		//		while((hway_iter->dx == dx) && (hway_iter->p >= p_min)) {
		while((hway_iter->dx == dx)  && (hway_iter->dy == dy)) {
#if 1									  // DEBUG
		  bool b_low_hw = (hw32(hway_iter->dx) <= SPECK_MAX_HW) &&  (hw32(hway_iter->dy) <= SPECK_MAX_HW) && (hw32(hway_iter->dz) <= SPECK_MAX_HW);
		  bool b_is_hway = (hway_iter->p >= SPECK_P_THRES) && b_low_hw;
		  if(!b_is_hway) {
			 printf("[%s:%d] CHECKPOINT! %8X %8X 2^%f\n", __FILE__, __LINE__, dx, dy, log2(hway_iter->p));
		  }
		  assert(b_is_hway);
#endif
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 if(b_found_in_croads) {
		//		printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
#if CLEAR_CROADS
		assert(croad_iter->p >= p_min);
#endif
		//		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min)) {
		while((croad_iter->dx == dx) && (croad_iter->dy == dy) && (croad_iter->p >= p_min) && (croad_iter != croads_diff_set_dx_dy_dz->end())) {

#if CLEAR_CROADS

		  dx = croad_iter->dx;
		  dy = croad_iter->dy;
		  uint32_t dz = croad_iter->dz;

		  uint32_t dx_next = dz;
		  uint32_t dy_next = LROT(dy, left_rot_const) ^ dx_next;
		  uint32_t dx_next_rrot = RROT(dx_next, right_rot_const); // ! the left input to the next round will be rotated before entering the ADD op

#if SPECK_BACK_TO_HWAY

		  bool b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dx_next_rrot, dy_next, *diff_set_dx_dy_dz);

#else	 // #if SPECK_BACK_TO_HWAY


		  uint32_t dz_max_next = 0;
		  double p_max_next = 0.0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
		  p_max_next = max_xdp_add_lm(dx_next_rrot, dy_next, &dz_max_next);
#else	 // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
		  //		  p_max_next = max_xdp_add(A, dx_next_rrot, dy_next, &dz_max_next);
		  p_max_next = max_xdp_add_lm(dx_next_rrot, dy_next, &dz_max_next);
#endif  // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
		  bool b_low_hw = (hw32(dx) <= SPECK_MAX_HW) &&  (hw32(dy) <= SPECK_MAX_HW) && (hw32(dz) <= SPECK_MAX_HW);
		  bool b_low_hw_next = (hw32(dx_next_rrot) <= SPECK_MAX_HW) &&  (hw32(dy_next) <= SPECK_MAX_HW) && (hw32(dz_max_next) <= SPECK_MAX_HW);
		  bool b_is_hway_next = (p_max_next >= SPECK_P_THRES) && b_low_hw && b_low_hw_next;
		  //			 assert(b_low_hw_next);

#endif  // #if SPECK_BACK_TO_HWAY

#if 0	  // DEBUG
		  printf("[%s:%d] List of CR: dx dy dz %8X %8X %8X 2^%f\n\n", __FILE__, __LINE__, dx, dy, dz, log2(croad_iter->p));
		  printf("[%s:%d] CHECK is HW: dx_next_rrot dy_next %8X %8X\n\n", __FILE__, __LINE__, dx_next_rrot, dy_next);
#endif

		  assert(b_is_hway_next);
		  if(b_is_hway_next) {
			 found_mset_p.insert(*croad_iter);
		  }
#else	 // #if CLEAR_CROADS
		  found_mset_p.insert(*croad_iter);
#endif  // #if CLEAR_CROADS
		  croad_iter++;
		}
	 }

#if 1									  // add the max
	 double p_max = 0.0;
	 uint32_t dz_max = 0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#else
	 //	 p_max = max_xdp_add(A, dx, dy, &dz_max);
	 p_max = max_xdp_add_lm(dx, dy, &dz_max);
#endif
	 //	 assert((hw32(diff_dz.dx) <= SPECK_MAX_HW) && (hw32(diff_dz.dy) <= SPECK_MAX_HW));
	 bool b_low_hw = (hw32(dx) <= SPECK_MAX_HW) && (hw32(dy) <= SPECK_MAX_HW) && (hw32(dz_max) <= SPECK_MAX_HW);
	 if((p_max >= SPECK_P_THRES) && (b_low_hw)) {
#if 0									  // DEBUG
		printf("[%s:%d] Add (%X %X %X) 2^%f\n", __FILE__, __LINE__, dx, dy, dz_max, log2(p_max));
#endif  // #if 0									  // DEBUG
		differential_3d_t new_diff = {dx, dy, dz_max, p_max};
		found_mset_p.insert(new_diff);
		b_found_in_hways = true;
	 }
#endif

	 std::multiset<differential_3d_t, struct_comp_diff_3d_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("[%s:%d] %2d: Temp set size %d\n", __FILE__, __LINE__, n, found_mset_p.size());
#endif

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);

	 //		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy_dz->end())) {
	 if((find_iter->dx == dx) && (find_iter->dy == dy)) {
		while((find_iter->dx == dx) && (find_iter->dy == dy) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  assert((find_iter->dy == dy));
		  diff_dz = *find_iter;

		  dx = diff_dz.dx;
		  dy = diff_dz.dy;
		  uint32_t dz = diff_dz.dz;
		  pn = diff_dz.p;
#if 0									  // DEBUG
		  printf("[%s:%d] List: (%X %X %X) 2^%f | b_found_in_hways %d\n", __FILE__, __LINE__, dx, dy, dz, log2(pn), b_found_in_hways);
#endif  // #if 0									  // DEBUG
		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  uint32_t dxx = dz;
		  uint32_t dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}
#if 1																	// DEBUG
		  // ! the left input to the next round will be rotated before entering the ADD op
		  bool b_low_hw = (hw32(diff_dz.dx) <= SPECK_MAX_HW) &&  (hw32(diff_dz.dy) <= SPECK_MAX_HW) && (hw32(diff_dz.dz) <= SPECK_MAX_HW);
		  uint32_t dxx_rrot = RROT(dz, right_rot_const); 		                     // x_{i+1}
		  //		  bool b_is_hway = false;
#if SPECK_BACK_TO_HWAY
		  //		  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>::iterator hway_iter = diff_set_dx_dy_dz->lower_bound(diff_dz);
		  //		  b_is_hway = (hway_iter != diff_set_dx_dy_dz->end()) && (hway_iter->dx == dx) && (hway_iter->dy == dy);
		  //		  assert(b_found_in_hways == b_is_hway);
#else	 // #if SPECK_BACK_TO_HWAY
		  //		  b_is_hway = (diff_dz.p >= SPECK_P_THRES) && b_low_hw;
#if 0									  // DEBUG
		  printf("[%s:%d] b_found_in_hways = %d b_is_hway %d |  (%X %X %X) 2^%f\n", __FILE__, __LINE__, b_found_in_hways, b_is_hway, diff_dz.dx, diff_dz.dy, diff_dz.dz, log2(diff_dz.p));
#endif  // #if 0									  // DEBUG
#endif  // #if SPECK_BACK_TO_HWAY
		  assert(b_low_hw);

		  bool b_is_hway_next = false;
		  if(!b_found_in_hways) {
#if SPECK_BACK_TO_HWAY
			 b_is_hway_next = speck_xdp_add_is_dz_in_set_dx_dy_dz(dxx_rrot, dyy, *diff_set_dx_dy_dz);
#else	 // #if SPECK_BACK_TO_HWAY
			 uint32_t dz_max_next = 0;
			 double p_max_next = 0.0;
#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 p_max_next = max_xdp_add_lm(dxx_rrot, dyy, &dz_max_next);
#else	 // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 //			 p_max_next = max_xdp_add(A, dxx_rrot, dyy, &dz_max_next);
			 p_max_next = max_xdp_add_lm(dxx_rrot, dyy, &dz_max_next);
#endif  // #if((WORD_SIZE == 16) || (WORD_SIZE == 32))
			 bool b_low_hw_next = (hw32(dxx_rrot) <= SPECK_MAX_HW) &&  (hw32(dyy) <= SPECK_MAX_HW) && (hw32(dz_max_next) <= SPECK_MAX_HW);
			 b_is_hway_next = (p_max_next >= SPECK_P_THRES) && b_low_hw_next;
			 assert(b_low_hw_next);
#endif  // #if SPECK_BACK_TO_HWAY
			 //			 printf("[%s:%d] CHECK is HW: dxx_rrot dyy %8X %8X\n\n", __FILE__, __LINE__, dxx_rrot, dyy);
			 assert(b_is_hway_next);
		  }
		  assert(b_found_in_hways || b_is_hway_next);
#endif  // DEBUG
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dxx;		  // dx_{i+1}
			 diff[n].dy = dyy;		  // dy_{i+1} 
			 diff[n].p = pn;
			 speck_xor_threshold_search(n+1, nrounds, A, B, Bn, diff, dx_init_in, dy_init_in, trail, dx_init, dy_init, right_rot_const, left_rot_const, diff_mset_p, diff_set_dx_dy_dz, croads_diff_mset_p, croads_diff_set_dx_dy_dz, p_thres, b_speck_cluster_trails);

		  }
		  find_iter++;
		}	// while
	 }		// if
  }
#endif  // #if SPECK_GREEDY_SEARCH

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = RROT(diff[n - 1].dx, right_rot_const); // the x input to ADD
	 uint32_t dy = diff[n - 1].dy; // the y input to ADD
	 uint32_t dz = 0;

#if((WORD_SIZE == 16) || (WORD_SIZE == 32))
	 pn = max_xdp_add_lm(dx, dy, &dz);
#else
	 //	 pn = max_xdp_add(A, dx, dy, &dz);
	 pn = max_xdp_add_lm(dx, dy, &dz);
#endif
	 uint32_t dxx = dz;		                     // x_{i+1}
	 uint32_t dyy = LROT(dy, left_rot_const) ^ dz; // y_{i+1}

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 bool b_low_hw = true;//(hw32(dxx) <= SPECK_MAX_HW) && (hw32(dyy) <= SPECK_MAX_HW);
	 if((b_low_hw) && (p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("\n[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dxx;
		diff[n].dy = dyy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  *dx_init = dx_init_in;
		  *dy_init = dy_init_in;
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

void marx_wtrail_print_gsl_matrix_int(const gsl_matrix A, const uint32_t nrows, const uint32_t ncols)
{
  for(uint32_t row = 0; row < nrows; row++){
	 for(uint32_t col = 0; col < ncols; col++){
		double e = gsl_matrix_get(&A, row, col);
		printf("%d, ", (uint32_t)e);
	 }
	 printf("\n");
  }
}

void marx_wtrail_build_permutation_matrices(uint32_t order)
{
  gsl_permutation * perm = gsl_permutation_alloc(4);
  gsl_permutation_init(perm);
  int n = 0;
  do {
	 gsl_matrix* P = gsl_matrix_calloc(MBOXES, MBOXES);
	 gsl_matrix_set_zero(P);
	 for(uint32_t i = 0; i < order; i++) {
		uint32_t j = gsl_permutation_get(perm, i);
		gsl_matrix_set(P, i, j, 1);
	 }
#if 1 // DEBUG
	 printf("Permutation #%2d\n", n);
	 gsl_permutation_fprintf(stdout, perm, " %u");
	 printf("\n");
	 marx_wtrail_print_gsl_matrix_int(*P, MBOXES, MBOXES);
#endif // #if 0 // DEBUG
	 gsl_matrix_free(P);
	 n++;
  }
  while (gsl_permutation_next(perm) == GSL_SUCCESS);

  gsl_permutation_free(perm);
}

/*

Invert a matrix in GSL

http://www.macapp.net/pmwiki/pmwiki.php?n=Main.InvertMatrix

#include <gsl/gsl_matrix.h>
#include <gsl/gsl_linalg.h>
#include <gsl/gsl_cblas.h>

int main (void)
{
// Define the dimension n of the matrix
// and the signum s (for LU decomposition)
int n = 2;
int s;

// Define all the used matrices
gsl_matrix * m = gsl_matrix_alloc (n, n);
gsl_matrix * inverse = gsl_matrix_alloc (n, n);
gsl_permutation * perm = gsl_permutation_alloc (n);

// Fill the matrix m
//
//
//
//

// Make LU decomposition of matrix m
gsl_linalg_LU_decomp (m, perm, &s);

// Invert the matrix m
gsl_linalg_LU_invert (m, perm, inverse);
}
*/


/**
 * Main function of VA tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  //  assert(WORD_SIZE <= 10);
  srandom(time(NULL));
  //  test_xdp_add_dc_set_is_max();
  //  test_xdp_add_combine_output_diff_sets();
  //  test_xdp_add_combine_output_diff_sets_2();
  //  test_xdp_add_nonzero_cond();
  //  test_adp_xor_nonzero_all();
  //  test_xdp_add_nonzero_all();
  return 0;
}
