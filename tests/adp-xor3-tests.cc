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
 * \file  adp-xor3-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xor3.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif

void test_adp_xor3_sf()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);
#if DEBUG_MAX_ADP_XOR_TESTS
  adp_xor3_print_matrices(A);
  adp_xor3_print_matrices_sage(A);
#endif  // #if DEBUG_MAX_ADP_XOR_TESTS
  adp_xor3_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

void test_adp_xor3_alloc_matrices()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

void test_adp_xor3()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);
  uint32_t da = random() & MASK;
  uint32_t db = random() & MASK;
  uint32_t dc = random() & MASK;
  uint32_t dd = random() & MASK;
  double p1 = adp_xor3(A, da, db, dc, dd);
  assert((p1 >= 0.0) && (p1 <= 1.0));
  double p2 = adp_xor3_exper(da, db, dc, dd);
#if DEBUG_MAX_ADP_XOR_TESTS
  printf("[%s:%d] ADP_XOR3_1[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, dd, p1);
  printf("[%s:%d] ADP_XOR3_2[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, dd, p2);
#endif  // #if DEBUG_MAX_ADP_XOR_TESTS
  assert(p1 == p2);
  adp_xor3_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

void test_adp_xor3_all()
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
		  for(uint32_t dd = 0; dd < N; dd++) {
			 double p1 = adp_xor3(A, da, db, dc, dd);
			 assert((p1 >= 0.0) && (p1 <= 1.0));
			 double p2 = adp_xor3_exper(da, db, dc, dd);
#if DEBUG_MAX_ADP_XOR_TESTS
			 printf("[%s:%d] ADP_XOR3_TH[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, da, db, dc, dd, p1);
			 printf("[%s:%d] ADP_XOR3_EX[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, da, db, dc, dd, p2);
#endif  // #if DEBUG_MAX_ADP_XOR_TESTS
			 assert(p1 == p2);

		  }
		}
	 }
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

/**
 * Main function of ADP-XOR3 tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  assert(WORD_SIZE <= 10);
  srandom(time(NULL));

  test_adp_xor3_sf();
  test_adp_xor3_alloc_matrices();
  test_adp_xor3();
#if(WORD_SIZE <= 5)
  test_adp_xor3_all();
#endif  // #if(WORD_SIZE <= 5)
  return 0;
}
