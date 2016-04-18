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
 * \file  max-xdp-add-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for max-xdp-add.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif

void test_max_xdp_add()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  WORD_T da = xrandom();//0x700000000;//xrandom() & MASK;
  WORD_T db = xrandom();//0x700000000;//xrandom() & MASK;
  WORD_T dc = 0;
  double p0 = max_xdp_add(A, da, db, &dc);
  assert((p0 >= 0.0) && (p0 <= 1.0));
  double p1 = xdp_add(A, da, db, dc);
  assert((p1 >= 0.0) && (p1 <= 1.0));
  assert(p0 == p1);
#if DEBUG_MAX_XDP_ADD_TESTS
  printf("[%s:%d] XDP_ADD_0[(%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			__FILE__, __LINE__, da, db, dc, p0, log2(p0));
  printf("[%s:%d] XDP_ADD_1[(%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			__FILE__, __LINE__, da, db, dc, p1, log2(p1));
#endif  // #if DEBUG_MAX_XDP_ADD_TESTS
#if(WORD_SIZE <= 10)
  double p2 = xdp_add_exper(da, db, dc);
  printf("[%s:%d] XDP_ADD_2[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p2);
  assert(p1 == p2);
#endif // #if(WORD_SIZE <= 10)
  xdp_add_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

void test_max_xdp_add_is_max()
{
#if(WORD_SIZE <= 10)
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t i = 0; i < N; i++) {
	 for(uint32_t j = 0; j < N; j++) {
		WORD_T da = i;
		WORD_T db = j;
		WORD_T dc1 = 0;
		WORD_T dc2 = 0;
		double p1 = max_xdp_add(A, da, db, &dc1);
		assert((p1 >= 0.0) && (p1 <= 1.0));
		double p2 = max_xdp_add_exper(A, da, db, &dc2);
#if DEBUG_MAX_XDP_ADD_TESTS
		printf("[%s:%d] MAX_XDP_ADD_TH[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc1, p1);
		printf("[%s:%d] MAX_XDP_ADD_EX[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc2, p2);
#else
		printf("\r[%s:%d] MAX_XDP_ADD[(%8X,%8X)->%8X %8X] = %f %f", __FILE__, __LINE__, da, db, dc1, dc2, p1, p2);
		fflush(stdout);
#endif  // #if DEBUG_MAX_XDP_ADD_TESTS
		assert(p1 == p2);
	 }
  }
  printf("\n[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
  xdp_add_free_matrices(A);
#endif // #if(WORD_SIZE <= 10)
}

/**
 * Compare MAX-XDP-ADD vs MAX-XDP-ADD-LM (the version by Lipmaa-Moriai)
 */
void test_max_xdp_add_vs_lm_all()
{
#if(WORD_SIZE <= 10)
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		uint32_t da = i;
		uint32_t db = j;
		uint32_t dc1 = 0;
		uint32_t dc2 = 0;

		double p1 = max_xdp_add(A, da, db, &dc1);
		assert((p1 >= 0.0) && (p1 <= 1.0));
		double p2 = max_xdp_add_lm(da, db, &dc2);

#if 0
		uint32_t C = cap(da, db);
		printf("\n  C = ");
		print_binary(C);
		printf("\n da = ");
		print_binary(da);
		printf("\n db = ");
		print_binary(db);
		printf("\ndc2 = ");
		print_binary(dc2);
		printf("\ndc1 = ");
		print_binary(dc1);
		printf("\n");
#endif

#if 0
		printf("[%s:%d] MAX_XDP_ADD_MY[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc1, p1);
		printf("[%s:%d] MAX_XDP_ADD_LM[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc2, p2);
#else 
		printf("\r[%s:%d] MAX_XDP_ADD_LM[(%8X,%8X)->%8X %8X] = %f %f", __FILE__, __LINE__, da, db, dc1, dc2, p1, p2);
		fflush(stdout);
#endif  // #if 1
		assert(p1 == p2);
	 }
  }
  xdp_add_free_matrices(A);
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
#endif // #if(WORD_SIZE <= 10)
}

/**
 * Main function of MAX-XDP-ADD tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));
  //  test_max_xdp_add();
  test_max_xdp_add_is_max();
  // must be power of 2 for AOP to work
  //  if((WORD_SIZE == 4) || (WORD_SIZE == 8)) {
  //  test_max_xdp_add_vs_lm_all();
  //  } else {
  return 0;
}
