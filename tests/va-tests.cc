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
