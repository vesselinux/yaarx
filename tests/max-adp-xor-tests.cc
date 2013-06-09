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
 * \file  max-adp-xor-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for max-adp-xor.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef MAX_ADP_XOR_H
#include "max-adp-xor.hh"
#endif

void test_max_adp_xor()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);
  uint32_t da = random32() & MASK;
  uint32_t db = random32() & MASK;
  uint32_t dc = 0;
  double p0 = max_adp_xor(A, da, db, &dc);
  assert((p0 >= 0.0) && (p0 <= 1.0));
  double p1 = adp_xor(A, da, db, dc);
  assert((p1 >= 0.0) && (p1 <= 1.0));
  assert(p0 == p1);
  double p2 = adp_xor_exper(da, db, dc);
  assert(p1 == p2);
#if DEBUG_MAX_ADP_XOR_TESTS
  printf("[%s:%d] ADP_XOR_0[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p0);
  printf("[%s:%d] ADP_XOR_1[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p1);
  printf("[%s:%d] ADP_XOR_2[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p2);
#endif  // #if DEBUG_MAX_ADP_XOR_TESTS
  adp_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_xor_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t da = 0; da < N; da++) {
	 for(uint32_t db = 0; db < N; db++) {
		uint32_t dc1 = 0;
		uint32_t dc2 = 0;
		double p1 = max_adp_xor(A, da, db, &dc1);
		assert((p1 >= 0.0) && (p1 <= 1.0));
		double p2 = max_adp_xor_exper(A, da, db, &dc2);
#if DEBUG_MAX_ADP_XOR_TESTS
		printf("[%s:%d] MAX_ADP_XOR_TH[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc1, p1);
		printf("[%s:%d] MAX_ADP_XOR_EX[(%8X,%8X)->%8X] = %6.5f\n", 
				 __FILE__, __LINE__, da, db, dc2, p2);
#endif  // #if DEBUG_MAX_ADP_XOR_TESTS
		assert(p1 == p2);
	 }
  }
  adp_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  assert(WORD_SIZE <= 10);
  test_max_adp_xor();
  test_max_adp_xor_is_max();
  return 0;
}
