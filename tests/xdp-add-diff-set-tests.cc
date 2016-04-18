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
 * \file  xdp-add-diff-set-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for xdp-add-diff-set.cc .
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
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif

void test_xdp_add_dset_print_matrices()
{
  gsl_matrix* A[2][2][2];
  xdp_add_dset_alloc_matrices(A);
  xdp_add_dset_gen_matrices(A);
  xdp_add_dset_print_matrices(A);
  xdp_add_dset_free_matrices(A);
}

void test_xdp_add_dset_init_states()
{
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_DSET_MSIZE);

  uint32_t N = (1U << 6);
  for(uint32_t w = 0; w < N; w++) {
	 gsl_vector_set_all(C, 0.0);
	 diff_set_t da_set = {0,0};
	 diff_set_t db_set = {0,0};
	 diff_set_t dc_set = {0,0};

	 da_set.diff  = (w >> 0) & 1;
	 da_set.fixed = (w >> 1) & 1;
	 db_set.diff  = (w >> 2) & 1;
	 db_set.fixed = (w >> 3) & 1;
	 dc_set.diff  = (w >> 4) & 1;
	 dc_set.fixed = (w >> 5) & 1;
#if 0									  // DEBUG
	 printf("%d%d%d%d%d%d\n", 
			  dc_set.fixed, dc_set.diff,
			  db_set.fixed, db_set.diff,
			  da_set.fixed, da_set.diff);
#endif
	 uint32_t pos = 0;
	 xdp_add_dset_init_states(pos, C, da_set, db_set, dc_set);

	 if(da_set.fixed == FIXED) {
		printf("%d", (uint32_t)da_set.diff);
	 } else {
		printf("*");
	 }
	 if(db_set.fixed == FIXED) {
		printf("%d", (uint32_t)db_set.diff);
	 } else {
		printf("*");
	 }
	 if(dc_set.fixed == FIXED) {
		printf("%d", (uint32_t)dc_set.diff);
	 } else {
		printf("*");
	 }
	 printf(" | ");
	 for(uint32_t i = 0; i < XDP_ADD_DSET_MSIZE; i++) {
		uint32_t val = gsl_vector_get(C, i);
		printf("%d", val);
	 }
	 printf("\n");
  }

  gsl_vector_free(C);

}

void test_xdp_add_dset()
{
  gsl_matrix* A[2][2][2];
  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  diff_set_t dc_set = {0,0};

  xdp_add_dset_alloc_matrices(A);
  xdp_add_dset_gen_matrices(A);
  //  xdp_add_dset_print_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add
  xdp_add_alloc_matrices(AA);
  xdp_add_sf(AA);
  xdp_add_normalize_matrices(AA);

#if 1
  da_set.diff  = xrandom() & MASK;
  da_set.fixed = xrandom() & MASK;//0xFFFFFFFF & MASK;
  db_set.diff  = xrandom() & MASK;
  db_set.fixed = xrandom() & MASK;//0xFFFFFFFF & MASK; 
  dc_set.diff  = xrandom() & MASK;
  dc_set.fixed = xrandom() & MASK;//0xFFFFFFFF & MASK; 
#else
  da_set.diff  = 0;//xrandom() & MASK;
  da_set.fixed = 0;//xrandom() & MASK;
  db_set.diff  = 0;//xrandom() & MASK;
  db_set.fixed = 1;//xrandom() & MASK;
  dc_set.diff  = 4;//xrandom() & MASK;
  dc_set.fixed = 3;//xrandom() & MASK;
#endif
  printf("[%s:%d] da db dc = (%llX,%llX), (%llX,%llX), (%llX,%llX)\n",
			__FILE__, __LINE__, 
			(WORD_MAX_T)da_set.diff, (WORD_MAX_T)da_set.fixed, 
			(WORD_MAX_T)db_set.diff, (WORD_MAX_T)db_set.fixed, 
			(WORD_MAX_T)dc_set.diff, (WORD_MAX_T)dc_set.fixed);

  printf("[%s:%d] XDP_ADD_DIFF_SET ", __FILE__, __LINE__);
  printf("\n da = ");
  xdp_add_dset_print_set(da_set);
  printf("\n db = ");
  xdp_add_dset_print_set(db_set);
  printf("\n dc = ");
  xdp_add_dset_print_set(dc_set);
  printf("\n");

  double p = xdp_add_dset(A, WORD_SIZE, da_set, db_set, dc_set);
  double pp = xdp_add_dset_exper(AA, da_set, db_set, dc_set);

  printf("\n p = %f, pp = %f\n", p, pp);

  xdp_add_dset_free_matrices(A);
  xdp_add_free_matrices(AA);
}

void test_xdp_add_dset_vs_exper_all()
{
#if(WORD_SIZE <= 4)
  gsl_matrix* A[2][2][2];		  // xdp-add
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* AAA[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(AAA);
  xdp_add_dset_gen_matrices_all(AAA, AA);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  diff_set_t dc_set = {0,0};


  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {
			 for(uint32_t d3 = 0; d3 < ALL_WORDS; d3++) {
				for(uint32_t f3 = 0; f3 < ALL_WORDS; f3++) {

				  da_set.diff = d1;
				  da_set.fixed = f1;
				  db_set.diff = d2;
				  db_set.fixed = f2;
				  dc_set.diff = d3;
				  dc_set.fixed = f3;

#if 1									  // test max
				  diff_set_t max_dc_set_exp = {0, 0};
				  double max_p_exp = max_xdp_add_dset_exper(A, da_set, db_set, &max_dc_set_exp);
				  diff_set_t max_dc_set = {0, 0};
				  double max_p = max_xdp_add_dset(da_set, db_set, &max_dc_set);
				  printf("\nmax1= ");
				  xdp_add_dset_print_set(max_dc_set_exp);
				  printf("\nmax2= ");
				  xdp_add_dset_print_set(max_dc_set);
				  assert(max_p == max_p_exp);
#endif
#if 0
				  printf("[%s:%d] da db dc = (%8X,%8X), (%8X,%8X), (%8X,%8X)\n",
							__FILE__, __LINE__,
							da_set.diff, da_set.fixed, 
							db_set.diff, db_set.fixed, 
							dc_set.diff, dc_set.fixed);
#endif
				  printf("[%s:%d] XDP_ADD_DIFF_SET ", __FILE__, __LINE__);
				  printf("\n da = ");
				  xdp_add_dset_print_set(da_set);
				  printf("\n db = ");
				  xdp_add_dset_print_set(db_set);
				  printf("\n dc = ");
				  xdp_add_dset_print_set(dc_set);
				  printf("\n");

				  double p = xdp_add_dset_exper(A, da_set, db_set, dc_set);
				  double pp = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set);
				  double ppp = xdp_add_dset_all(AAA, WORD_SIZE, da_set, db_set, dc_set);

				  printf("[%s:%d] EXP %f, THE %f, THE2 %f\n", __FILE__, __LINE__, p, pp, ppp);
				  assert(p == pp);
				  assert(p == ppp);
				}
			 }
		  }
		}
	 }
  }
  xdp_add_dset_free_matrices_all(AAA);
  xdp_add_dset_free_matrices(AA);
  xdp_add_free_matrices(A);
#endif // #if(WORD_SIZE <= 4)
}

void test_xdp_add_dset_vs_exper_rand()
{
  uint32_t N = (1U << 10);

  gsl_matrix* A[2][2][2];		  // xdp-add
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  diff_set_t dc_set = {0,0};


  for(uint32_t i = 0; i < N; i++) {

	 da_set.diff  = xrandom() & MASK;
	 da_set.fixed = xrandom() & MASK;
	 db_set.diff  = xrandom() & MASK;
	 db_set.fixed = xrandom() & MASK;
	 dc_set.diff  = xrandom() & MASK;
	 dc_set.fixed = xrandom() & MASK;

#if 0									  // DEBUG
	 printf("[%s:%d] da db dc = (%8X,%8X), (%8X,%8X), (%8X,%8X)\n",
			  __FILE__, __LINE__,
			  da_set.diff, da_set.fixed, 
			  db_set.diff, db_set.fixed, 
			  dc_set.diff, dc_set.fixed);
#endif

	 printf("[%s:%d] XDP_ADD_DIFF_SET ", __FILE__, __LINE__);
	 printf("\n da = ");
	 xdp_add_dset_print_set(da_set);
	 printf("\n db = ");
	 xdp_add_dset_print_set(db_set);
	 printf("\n dc = ");
	 xdp_add_dset_print_set(dc_set);
	 printf("\n");

	 if(WORD_SIZE < 12) {
		double p = xdp_add_dset_exper(A, da_set, db_set, dc_set);
		double pp = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set);
		printf("[%s:%d] EXP %f, THE %f\n", __FILE__, __LINE__, p, pp);
		assert(p == pp);
	 } else {
		//		double p = xdp_add(A, da_set.diff, db_set.diff, dc_set.diff); // just a random differential
		//		printf("[%s:%d] RND %f (2^%f), THE %f (2^%f)\n", __FILE__, __LINE__, p, log2(p), pp, log2(pp));
		double pp = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set);
		printf("[%s:%d] THE %f (2^%f)\n", __FILE__, __LINE__, pp, log2(pp));
	 }
  }
  xdp_add_dset_free_matrices(AA);
  xdp_add_free_matrices(A);
  printf("[%s:%d] OK", __FILE__, __LINE__);
}

void test_xdp_add_input_diff_to_output_dset_all()
{
#if(WORD_SIZE <= 12)
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {

		diff_set_t dc_set = {0,0};

		xdp_add_input_diff_to_output_dset(da, db, &dc_set);
#if 0									  // DEBUG
		printf("[%s:%d] (%8X, %8X) -> {%8X, %8X}\n", __FILE__, __LINE__, da, db, dc_set.diff, dc_set.fixed);
#endif
		std::vector<uint32_t> dc_set_all;
		xdp_add_dset_gen_diff_all(dc_set, &dc_set_all);

		double p = 0.0;
		std::vector<uint32_t>::iterator vec_iter;
		for(vec_iter = dc_set_all.begin(); vec_iter != dc_set_all.end(); vec_iter++) {
		  uint32_t dc_i = *vec_iter;
		  double p_i = xdp_add(A, da, db, dc_i);
#if 1									  // DEBUG
		  printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc_i, p_i);
#endif
		  assert(p_i != 0.0);
		  p += p_i;
		}

		uint32_t dc = 0;
#if 0
		double p_max = max_xdp_add(A, da, db, &dc);
#else
		double p_max = max_xdp_add_lm(da, db, &dc);
#endif
#if 1									  // DEBUG
		printf("[%s:%d] p_set %f p_max %f | %f %d\n", __FILE__, __LINE__, p, p_max, (p - p_max), (uint32_t)dc_set_all.size());
#endif
		assert(p >= p_max);
		//  printf("Total: %f, max (%f %8X)\n", p, p_max, dc);

	 }
  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
#endif // #if(WORD_SIZE <= 12)
}

/**
 * Test for \ref xdp_add_input_dsets_to_input_diffs .
 */
void test_xdp_add_input_dsets_to_input_diffs()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  WORD_T da[2] = {0,0};
  WORD_T db[2] = {0,0};

  da_set.diff = xrandom() & MASK;
  da_set.fixed = xrandom() & MASK;

  db_set.diff = xrandom() & MASK;
  db_set.fixed = xrandom() & MASK;

  xdp_add_input_dsets_to_input_diffs(da_set, db_set, da, db);

  printf("[%s:%d] Input sets: da (%llX,%llX), db (%llX,%llX)\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da_set.diff, (WORD_MAX_T)da_set.fixed, (WORD_MAX_T)db_set.diff, (WORD_MAX_T)db_set.fixed);
  printf("[%s:%d] Output diffs: 0:(%llX,%llX), 1:(%llX,%llX)\n",
			__FILE__, __LINE__, (WORD_MAX_T)da[0], (WORD_MAX_T)db[0], (WORD_MAX_T)da[1], (WORD_MAX_T)db[1]);

  diff_set_t dc_set[2] = {{0,0}};

  for(uint32_t j = 0; j < 2; j++) {
	 xdp_add_input_diff_to_output_dset(da[j], db[j], &dc_set[j]);

	 std::vector<WORD_T> dc_set_all;
	 xdp_add_dset_gen_diff_all(dc_set[j], &dc_set_all);

	 double p = 0.0;
	 std::vector<WORD_T>::iterator vec_iter;
	 for(vec_iter = dc_set_all.begin(); vec_iter != dc_set_all.end(); vec_iter++) {
		WORD_T dc_i = *vec_iter;
		double p_i = xdp_add(A, da[j], db[j], dc_i);
#if 1									  // DEBUG
		printf("[%s:%d] XDP_ADD[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
				 __FILE__, __LINE__, (WORD_MAX_T)da[j], (WORD_MAX_T)db[j], (WORD_MAX_T)dc_i, p_i, log2(p_i));
#endif
		assert(p_i != 0.0);
		p += p_i;
	 }
	 printf("[%s:%d] p[%d] = %f\n", __FILE__, __LINE__, j, p);
  }

  xdp_add_free_matrices(A);
}

/**
 * Test for \ref xdp_add_input_dsets_to_input_diffs for all inputs.
 */
void test_xdp_add_input_dsets_to_input_diffs_all()
{
#if(WORD_SIZE <= 6)
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};

  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff = d1;
			 da_set.fixed = f1;
			 db_set.diff = d2;
			 db_set.fixed = f2;

			 xdp_add_input_dsets_to_input_diffs(da_set, db_set, da, db);
#if 1
			 printf("[%s:%d] Input sets: da (%llX,%llX), db (%llX,%llX)\n", 
					  __FILE__, __LINE__, (WORD_MAX_T)da_set.diff, (WORD_MAX_T)da_set.fixed, (WORD_MAX_T)db_set.diff, (WORD_MAX_T)db_set.fixed);
			 printf("[%s:%d] Input diffs: 0:(%llX,%llX), 1:(%llX,%llX)\n",
					  __FILE__, __LINE__, (WORD_MAX_T)da[0], (WORD_MAX_T)db[0], (WORD_MAX_T)da[1], (WORD_MAX_T)db[1]);
#endif
			 diff_set_t dc_set[2] = {{0,0}};

			 double p[2] = {0.0, 0.0};
			 for(uint32_t j = 0; j < 2; j++) {
				xdp_add_input_diff_to_output_dset(da[j], db[j], &dc_set[j]);

				std::vector<uint32_t> dc_set_all;
				xdp_add_dset_gen_diff_all(dc_set[j], &dc_set_all);

				std::vector<uint32_t>::iterator vec_iter;
				for(vec_iter = dc_set_all.begin(); vec_iter != dc_set_all.end(); vec_iter++) {
				  uint32_t dc_i = *vec_iter;
				  double p_i = xdp_add(A, da[j], db[j], dc_i);
#if 1								  // DEBUG
				  printf("[%s:%d] XDP_ADD[(%8X,%8X)->%8X] = %6.5f\n", 
							__FILE__, __LINE__, da[j], db[j], dc_i, p_i);
#endif
				  assert(p_i != 0.0);
				  p[j] += p_i;
				}
				printf("[%s:%d] p[%d] = %f\n", __FILE__, __LINE__, j, p[j]);
			 }

			 uint32_t hw0 = hamming_weight(da[0] ^ db[0]);
			 uint32_t hw1 = hamming_weight(da[1] ^ db[1]);
			 if(hw0 > hw1) {
				assert(p[0] < p[1]);
			 }
			 if(hw0 < hw1) {
				assert(p[0] > p[1]);
			 }
			 if(hw0 == hw1) {
#if 0																		 // can be both
				uint32_t lsb_0 = ((da[0] & 1) & (db[0] & 1)); // lsb = 0,0 => dc = 0
				uint32_t lsb_1 = ((da[1] & 1) & (db[1] & 1)); // lsb = 1,1 => dc = 1
				if(lsb_0 < lsb_1) {
				  assert(p[0] > p[1]);
				}
				if(lsb_0 > lsb_1) {
				  assert(p[0] < p[1]);
				}
				if(lsb_0 == lsb_1) {
				  assert(p[0] == p[1]);
				}
#endif
			 }
		  }
		}
	 }
  }

  xdp_add_free_matrices(A);
#endif // #if(WORD_SIZE <= 6)
}

/**
 * Test for \ref xdp_add_input_dsets_to_input_diffs for all inputs:
 * verify that the generated differences da^j, db^j belong resp. to da_set, db_set 
 */
void test_xdp_add_input_dsets_to_input_diffs_belong_all()
{
#if(WORD_SIZE <= 6)
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};
  uint32_t da[2] = {0,0};
  uint32_t db[2] = {0,0};


  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff = d1;
			 da_set.fixed = f1;
			 db_set.diff = d2;
			 db_set.fixed = f2;

			 xdp_add_input_dsets_to_input_diffs(da_set, db_set, da, db);
#if 1
			 printf("[%s:%d] Input sets: da (%llX,%llX), db (%llX,%llX)\n", 
					  __FILE__, __LINE__, (WORD_MAX_T)da_set.diff, (WORD_MAX_T)da_set.fixed, (WORD_MAX_T)db_set.diff, (WORD_MAX_T)db_set.fixed);
			 printf("[%s:%d] Input diffs: 0:(%llX,%llX), 1:(%llX,%llX)\n",
					  __FILE__, __LINE__, (WORD_MAX_T)da[0], (WORD_MAX_T)db[0], (WORD_MAX_T)da[1], (WORD_MAX_T)db[1]);
#endif
			 bool b_da_found[2] = {false, false};
			 std::vector<uint32_t> da_set_all;
			 xdp_add_dset_gen_diff_all(da_set, &da_set_all);
			 std::vector<uint32_t>::iterator da_iter = da_set_all.begin();
			 //			 for(da_iter = da_set_all.begin(); da_iter != da_set_all.end(); da_iter++) {
			 while((da_iter != da_set_all.end()) && ((b_da_found[0] == false) || (b_da_found[1] == false))) {
				uint32_t da_i = *da_iter;
				if(da_i == da[0]) {
				  b_da_found[0] = true;
				  printf("[%s:%d] Found da[0] = %8X\n", __FILE__, __LINE__, da_i);
				}
				if(da_i == da[1]) {
				  b_da_found[1] = true;
				  printf("[%s:%d] Found da[1] = %8X\n", __FILE__, __LINE__, da_i);
				}
				da_iter++;
			 }
			 assert(b_da_found[0] == true);
			 assert(b_da_found[1] == true);

			 bool b_db_found[2] = {false, false};
			 std::vector<uint32_t> db_set_all;
			 xdp_add_dset_gen_diff_all(db_set, &db_set_all);
			 std::vector<uint32_t>::iterator db_iter = db_set_all.begin();
			 //			 for(db_iter = db_set_all.begin(); db_iter != db_set_all.end(); db_iter++) {
			 while((db_iter != db_set_all.end()) && ((b_db_found[0] == false) || (b_db_found[1] == false))) {
				uint32_t db_i = *db_iter;
				if(db_i == db[0]) {
				  b_db_found[0] = true;
				  printf("[%s:%d] Found db[0] = %8X\n", __FILE__, __LINE__, db_i);
				}
				if(db_i == db[1]) {
				  b_db_found[1] = true;
				  printf("[%s:%d] Found db[1] = %8X\n", __FILE__, __LINE__, db_i);
				}
				db_iter++;
			 }
			 assert(b_db_found[0] == true);
			 assert(b_db_found[1] == true);
		  }
		}
	 }
  }

  xdp_add_free_matrices(A);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
#endif // #if(WORD_SIZE <= 6)
}

void test_xdp_add_count_nz()
{
#if(WORD_SIZE < 12)
  double p_tot = 0.0;
  uint32_t cnt_nz = 0;
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		for(uint32_t k = 0; k < ALL_WORDS; k++) {
		  uint32_t da = i;
		  uint32_t db = j;
		  uint32_t dc = k;

		  double p = xdp_add(A, da, db, dc);
		  p_tot += p;
		  if(p != 0.0) {
			 cnt_nz++;
		  }
		}
	 }
  }
  xdp_add_free_matrices(A);
  uint32_t ndiffs_all = ALL_WORDS * ALL_WORDS * ALL_WORDS;
  uint32_t ninput_diffs = ALL_WORDS * ALL_WORDS;
  double p_norm = (double)p_tot / (double)ninput_diffs;
  printf("[%s:%d] ADP_XOR #nz %d / %d, %f, %f\n", __FILE__, __LINE__, cnt_nz, ndiffs_all, p_tot, p_norm);
#endif  // #if(WORD_SIZE < 14)
}

void test_lrot_dset()
{
  diff_set_t da_set = {0x80, 0};
  diff_set_t db_set = {0, 0};
  uint32_t rot_const = 2;

  db_set = lrot_dset(da_set, rot_const);

  printf("[%s:%d] %llX %llX %d\n", __FILE__, __LINE__, 
			(WORD_MAX_T)da_set.diff, (WORD_MAX_T)db_set.diff, rot_const);
}

void test_xor_dset()
{
  diff_set_t da_set = {0x2, 0};
  diff_set_t db_set = {0x80, 0};
  diff_set_t dc_set = {0, 0};

  //  bool b_single_diff = false;
  //  double p = 0.0;
  //  dc_set = xor_dset(da_set, db_set, &p, b_single_diff);
  dc_set = xor_dset(da_set, db_set);

  printf("[%s:%d] %llX %llX -> %llX\n", __FILE__, __LINE__, 
			(WORD_MAX_T)da_set.diff, (WORD_MAX_T)db_set.diff, (WORD_MAX_T)dc_set.diff);
}

void test_rmax_xdp_add_dset_is_max_all()
{
#if(WORD_SIZE <= 8)
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* AAA[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(AAA);
  xdp_add_dset_gen_matrices_all(AAA, AA);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};

  for(uint32_t d1 = 0; d1 < ALL_WORDS; d1++) {
	 for(uint32_t f1 = 0; f1 < ALL_WORDS; f1++) {
		for(uint32_t d2 = 0; d2 < ALL_WORDS; d2++) {
		  for(uint32_t f2 = 0; f2 < ALL_WORDS; f2++) {

			 da_set.diff  = d1;
			 da_set.fixed = f1;
			 db_set.diff  = d2;
			 db_set.fixed = f2;

			 // max computed using recursive variant
			 diff_set_t dc_set_out = {0,0};
			 xdp_add_input_dset_to_output_dset_rec(AA, da_set, db_set, &dc_set_out);
			 double p_max = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set_out);
			 uint32_t s_max = xdp_add_dset_size(dc_set_out);
			 double r_max = p_max / (double)s_max; 

#if 1									  // DEBUG
			 printf("[%s:%d]\n", __FILE__, __LINE__);
			 printf("\n da = ");
			 xdp_add_dset_print_set(da_set);
			 printf("\n db = ");
			 xdp_add_dset_print_set(db_set);
			 printf("\n dc = ");
			 xdp_add_dset_print_set(dc_set_out);
			 printf("\n");
#endif

			 // max computed using bounds variant
			 bool b_single_diff = false;
			 diff_set_t dc_set_rmax = {0,0};
			 double p_rmax = rmax_xdp_add_dset(AAA, da_set, db_set, &dc_set_rmax, b_single_diff);
			 double p_max_2 = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set_rmax);
			 uint32_t s_rmax = xdp_add_dset_size(dc_set_rmax);
			 double r_rmax = p_rmax / (double)s_rmax; 
			 printf("[%s:%d] %f %f %8X %f = %f\n", __FILE__, __LINE__, p_rmax, p_max_2, s_rmax, r_rmax, r_max);
			 assert(p_rmax == p_max_2);
			 assert(r_rmax == r_max);

			 // check if for inputs that are not sets the max is equl to the fixed diff max
			 if((da_set.fixed == 0) && (db_set.fixed == 0)) {
				uint32_t da = da_set.diff;
				uint32_t db = db_set.diff;
				uint32_t dc_max = 0;
				double p_max_tmp = max_xdp_add_lm(da, db, &dc_max);
				p_max_tmp *= xdp_add_dset_size(dc_set_rmax);
				printf("%f %f (%8X %8X) %8X\n", p_max_tmp, p_rmax, dc_set_rmax.diff, dc_set_rmax.fixed, dc_max);
				assert(p_max_tmp == p_rmax);
			 }

			 // compute the max exhaustively over all output diffs and compare to the above
			 diff_set_t dc_set_i = {0,0};
			 diff_set_t max_dc_set_i = {0,0};
			 double max_r_i = 0.0;
			 double max_p_i = 0.0;
			 uint32_t max_s_i = 0;
			 for(uint32_t d3 = 0; d3 < ALL_WORDS; d3++) {
				for(uint32_t f3 = 0; f3 < ALL_WORDS; f3++) {
				  dc_set_i.diff = d3;
				  dc_set_i.fixed = f3;
				  double p_i = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set_i);
				  uint32_t s_i = xdp_add_dset_size(dc_set_i);
				  double r_i = p_i / (double)s_i; 
				  if(r_i > max_r_i) {
					 max_s_i = s_i;
					 max_p_i = p_i;
					 max_r_i = r_i;
					 max_dc_set_i = {dc_set_i.diff, dc_set_i.fixed};
				  }
				}
			 }
#if 1								  // DEBUG
			 if((max_r_i > r_max)) {
				printf("[%s:%d] p_i = (%f, %f), %2d | %f, %f, ", __FILE__, __LINE__, max_p_i, p_max, max_s_i, max_r_i, r_max);
				xdp_add_dset_print_set(max_dc_set_i);
				printf(" | ");
				xdp_add_dset_print_set(dc_set_out);
				printf("\n");
				assert(max_dc_set_i.fixed == FIXED);
			 }
			 assert(max_r_i == r_max);
			 assert(max_r_i == r_rmax);
#endif
		  }
		}
	 }
  }

  xdp_add_dset_free_matrices_all(AAA);
  xdp_add_dset_free_matrices(AA);
  xdp_add_free_matrices(A);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
#endif // #if(WORD_SIZE <= 8)
}

void test_rmax_xdp_add_dset_is_max_rand()
{
  uint32_t N = (1U << 0);

  gsl_matrix* A[2][2][2];		  // xdp-add
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* AAA[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(AAA);
  xdp_add_dset_gen_matrices_all(AAA, AA);

  diff_set_t da_set = {0,0};
  diff_set_t db_set = {0,0};

  for(uint32_t i = 0; i < N; i++) {

	 // da db = (    2011,    BC28), (    D295,    FFC8)
	 // (85D36265,57E715B7), (5D9EE342,F25CA869)
#if 0
	 da_set.diff  = 0x85D36265;
	 da_set.fixed = 0x57E715B7;
	 db_set.diff  = 0x5D9EE342;
	 db_set.fixed = 0xF25CA869;
#else

	 // 80000000 20000010 | 0.250000 0.500000 ( 1000000        0) A0000010
	 //	 80020001
	 da_set.diff  = xrandom() & MASK;
	 da_set.fixed = xrandom() & MASK;
	 db_set.diff  = xrandom() & MASK;
	 db_set.fixed = xrandom() & MASK;
#endif

#if 1									  // DEBUG
	 printf("[%s:%d] da db dc = (%llX,%llX), (%llX,%llX)\n",
			  __FILE__, __LINE__,
			  (WORD_MAX_T)da_set.diff, (WORD_MAX_T)da_set.fixed, 
			  (WORD_MAX_T)db_set.diff, (WORD_MAX_T)db_set.fixed);
	 printf("\n da = ");
	 xdp_add_dset_print_set(da_set);
	 printf("\n db = ");
	 xdp_add_dset_print_set(db_set);
	 printf("\n");
#endif

#if 1
	 bool b_single_diff = false;
	 diff_set_t dc_set_2 = {0,0};
	 double p_max_2 = rmax_xdp_add_dset(AAA, da_set, db_set, &dc_set_2, b_single_diff);
	 uint32_t s_max_2 = xdp_add_dset_size(dc_set_2);
	 double r_max_2 = p_max_2 / (double)s_max_2; 
	 printf("[%s:%d] After max 1\n", __FILE__, __LINE__);
#endif

#if 1									  // TEST
	 if((da_set.fixed == 0) && (db_set.fixed == 0)) {
		WORD_T da = da_set.diff;
		WORD_T db = db_set.diff;
		WORD_T dc_max = 0;
		double p_max_tmp = max_xdp_add_lm(da, db, &dc_max);
		//				p_max_tmp /= xdp_add_dset_size(dc_set_2);
		printf("%f %f (%llX %llX) %llX\n", p_max_tmp, p_max_2, (WORD_MAX_T)dc_set_2.diff, (WORD_MAX_T)dc_set_2.fixed, (WORD_MAX_T)dc_max);
		assert(p_max_tmp == p_max_2);
	 }
#endif

#define LIM 14

#if(WORD_SIZE < LIM)
	 diff_set_t dc_set = {0,0};
	 xdp_add_input_dset_to_output_dset_rec(AA, da_set, db_set, &dc_set);
	 double p_max = xdp_add_dset(AA, WORD_SIZE, da_set, db_set, dc_set);
	 uint32_t s_max = xdp_add_dset_size(dc_set);
	 double r_max = p_max / (double)s_max; 
	 printf("[%s:%d] After max 2\n", __FILE__, __LINE__);
#endif  // #if(WORD_SIZE < 14)

	 printf("[%s:%d] XDP_ADD_DIFF_SET ", __FILE__, __LINE__);
	 printf("\n da = ");
	 xdp_add_dset_print_set(da_set);
	 printf("\n db = ");
	 xdp_add_dset_print_set(db_set);
#if(WORD_SIZE < LIM)
	 printf("\n dc = ");
	 xdp_add_dset_print_set(dc_set);
#endif  // #if(WORD_SIZE < 14)
	 printf("\ndc2 = ");
	 xdp_add_dset_print_set(dc_set_2);
	 printf("\n");
#if(WORD_SIZE < LIM)
	 printf("[%s:%d] THE   %f, %d, %f \n", __FILE__, __LINE__, r_max, s_max, p_max);
#endif  // #if(WORD_SIZE < 14)
	 printf("[%s:%d] THE_2 %f (2^%f), %d, %f (2^%f)\n", __FILE__, __LINE__, r_max_2, log2(r_max_2), s_max_2, p_max_2, log2(p_max_2));

#if(WORD_SIZE < LIM)
	 assert(r_max == r_max_2);
#endif  // #if(WORD_SIZE < 14)

  }

  xdp_add_dset_free_matrices_all(AAA);
  xdp_add_dset_free_matrices(AA);
  xdp_add_free_matrices(A);
}

/**
 * Main function of the tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  //  assert(WORD_SIZE <= 10);
  srandom(time(NULL));

  //  test_xdp_add_count_nz();
  //  test_rmax_xdp_add_dset_is_max_rand();
  //  test_rmax_xdp_add_dset_is_max_all();			  // <-
  //  test_xdp_add_input_dsets_to_input_diffs_belong_all();
  //  test_xor_dset();
  //  test_lrot_dset();
  //  test_xdp_add_input_dsets_to_input_diffs_all();
  test_xdp_add_input_dsets_to_input_diffs();
  //  test_xdp_add_input_diff_to_output_dset_all();
  //  test_xdp_add_dset_vs_exper_all();
  //  test_xdp_add_dset();
  //  test_xdp_add_dset_init_states();
  //  test_xdp_add_dset_print_matrices();
  return 0;
}
