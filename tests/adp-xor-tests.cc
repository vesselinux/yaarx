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
 * \file  adp-xor-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xor.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif

/**
 * Test allocation and free of ADP-XOR matrices.
 */
void test_adp_xor_matrices()
{
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);
#if DEBUG_ADP_XOR_TESTS
  adp_xor_print_matrices(A);
#endif  // #if DEBUG_ADP_XOR_TESTS
  adp_xor_free_matrices(A);
}

/**
 * Compare ADP-XOR to the experimental value.
 */
void test_adp_xor_all()
{
#if(WORD_SIZE <= 8)
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  uint64_t N = (1ULL << WORD_SIZE);
  for(WORD_T da = 0; da < N; da++) {
	 for(WORD_T db = 0; db < N; db++) {
		for(WORD_T dc = 0; dc < N; dc++) {
		  double p1 = adp_xor(A, da, db, dc);
		  assert((p1 >= 0.0) && (p1 <= 1.0));
		  double p2 = adp_xor_exper(da, db, dc);
#if DEBUG_ADP_XOR_TESTS
		  printf("[%s:%d] ADP_XOR_TH[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
					__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p1, log2(p1));
		  printf("[%s:%d] ADP_XOR_EX[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
					__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p2, log2(p2));
#endif  // #if DEBUG_ADP_XOR_TESTS
		  double p3 = adp_xor(A, dc, db, da);
		  double p4 = adp_xor(A, da, dc, db);
		  assert(p1 == p2);
		  assert(p1 == p3);
		  assert(p1 == p4);

		}
	 }
  }
  adp_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
#endif // #if(WORD_SIZE <= 8)
}

/**
 * Test ADP-XOR for random input and output ADD differences.
 */
void test_adp_xor()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);
  WORD_T da = xrandom() & MASK;
  WORD_T db = xrandom() & MASK;
  WORD_T dc = xrandom() & MASK;
  double p1 = adp_xor(A, da, db, dc);
  assert((p1 >= 0.0) && (p1 <= 1.0));
#if DEBUG_ADP_XOR_TESTS
  printf("[%s:%d] ADP_XOR_TH[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p1, log2(p1));
#endif  // #if DEBUG_ADP_XOR_TESTS
#if(WORD_SIZE <= 10)
  double p2 = adp_xor_exper(da, db, dc);
  assert(p1 == p2);
#if DEBUG_ADP_XOR_TESTS
  printf("[%s:%d] ADP_XOR_EX[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p2, log2(p2));
#endif  // #if DEBUG_ADP_XOR_TESTS
#endif // #if(WORD_SIZE <= 10)
  adp_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xor_print_matrices_sage()
{
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  //  adp_xor_normalize_matrices(A);
  adp_xor_print_matrices_sage(A);
  adp_xor_free_matrices(A);
}

/**
 * Main function of ADP-XOR tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));

#if 1
  //  assert(WORD_SIZE <= 10);
  //  test_adp_xor();
  //  test_adp_xor_print_matrices_sage();
  //  test_adp_xor_matrices();
  test_adp_xor_all();
#endif
  return 0;
}
