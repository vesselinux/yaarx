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
 * \file  max-adp-xor3-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for max-adp-xor3.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef MAX_ADP3_XOR_H
#include "max-adp-xor3.hh"
#endif

void test_max_adp_xor3_rec()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);
  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  uint32_t da = xrandom() & MASK;
  uint32_t db = xrandom() & MASK;
  uint32_t dc = xrandom() & MASK;
  uint32_t dd_max = 0;

  max_adp_xor3_rec(A, C, da, db, dc, &dd_max);

#if DEBUG_MAX_ADP_XOR3_TESTS
  double p_max = max_adp_xor3_rec(A, C, da, db, dc, &dd_max);
  printf("[%s:%d] MAX_ADP_XOR3[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, dd_max, p_max);
#endif  // #if DEBUG_MAX_ADP_XOR3_TESTS

  gsl_vector_free(C);
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_xor3_vs_rec_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE < 7);
  // init A
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);
  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {
		for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {

		  uint32_t dd_maxt = 0;
		  double p_maxt = max_adp_xor3(A, da, db, dc, &dd_maxt);
		  uint32_t dd_maxt_rec = 0;
		  double p_maxt_rec = max_adp_xor3_rec(A, C, da, db, dc, &dd_maxt_rec);
#if DEBUG_MAX_ADP_XOR3_TESTS
		  printf("[%s:%d]     MAX_ADP_XOR3[(%8X,%8X,%8X)->%8X] = %6.5f = 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, dd_maxt, p_maxt, log2(p_maxt));
		  printf("[%s:%d] MAX_ADP_XOR3_REC[(%8X,%8X,%8X)->%8X] = %6.5f = 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, dd_maxt, p_maxt_rec, log2(p_maxt_rec));
#endif  // #if DEBUG_MAX_ADP_XOR3_TESTS
		  assert(p_maxt == p_maxt_rec);

		}
	 }
  }
  gsl_vector_free(C);
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_xor3_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t da = 0; da < N; da++) {
	 for(uint32_t db = 0; db < N; db++) {
		for(uint32_t dc = 0; dc < N; dc++) {
		  uint32_t dd1 = 0;
		  uint32_t dd2 = 0;
		  double p1 = max_adp_xor3(A, da, db, dc, &dd1);
		  assert((p1 >= 0.0) && (p1 <= 1.0));
		  double p2 = max_adp_xor3_exper(A, da, db, dc, &dd2);
#if DEBUG_MAX_ADP_XOR3_TESTS
		  printf("[%s:%d] MAX_ADP_XOR3_TH[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, dd1, p1);
		  printf("[%s:%d] MAX_ADP_XOR3_EX[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, dd2, p2);
#endif  // #if DEBUG_MAX_ADP_XOR3_TESTS
		  assert(p1 == p2);
		}
	 }
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  if(WORD_SIZE <= 5) {
	 test_max_adp_xor3_is_max();
	 test_max_adp_xor3_rec();
	 test_max_adp_xor3_vs_rec_all();
  } else {
	 printf("[%s:%d] Please set WORD_SIZE to a value <= 5 to run this test.\n", __FILE__, __LINE__);
  }
  return 0;
}
