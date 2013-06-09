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
 * \file  xdp-add-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for \f$\mathrm{xdp}^{+}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif

/**
 * Test allocation and free of XDP-ADD matrices.
 */
void test_xdp_add_matrices()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
#if DEBUG_ADP_XOR_TESTS
  xdp_add_print_matrices(A);
#endif  // #if DEBUG_ADP_XOR_TESTS
  xdp_add_free_matrices(A);
  printf("[%s:%d] Test %s() OK.\n", __FILE__, __LINE__, __FUNCTION__);
}

/**
 * Test XDP-ADD for random input and output XOR differences.
 */
void test_xdp_add()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  uint32_t da = random32() & MASK;
  uint32_t db = random32() & MASK;
  uint32_t dc = random32() & MASK;
  double p1 = xdp_add(A, da, db, dc);
  assert((p1 >= 0.0) && (p1 <= 1.0));
  double p2 = xdp_add_exper(da, db, dc);
#if DEBUG_ADP_XOR_TESTS
  printf("[%s:%d] XDP_ADD_TH[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p1);
  printf("[%s:%d] XDP_ADD_EX[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p2);
#endif  // #if DEBUG_ADP_XOR_TESTS
  assert(p1 == p2);
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Compare XDP-ADD to the experimental value.
 */
void test_xdp_add_all()
{
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

		  double p1 = xdp_add(A, da, db, dc);
		  assert((p1 >= 0.0) && (p1 <= 1.0));
		  double p2 = xdp_add_exper(da, db, dc);

#if DEBUG_XDP_ADD_TESTS
		  printf("[%s:%d] XDP_ADD_TH[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p1);
		  printf("[%s:%d] XDP_ADD_EX[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p2);
#endif  // #if DEBUG_XDP_ADD_TESTS
		  assert(p1 == p2);
		}
	 }
  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_add_print_matrices_sage()
{
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  //  xdp_add_normalize_matrices(A);
  xdp_add_print_matrices_sage(A);
  xdp_add_free_matrices(A);
}

/**
 * Tests for the AOP function.
 * \see aop .
 */
void test_aop()
{
  uint32_t n = WORD_SIZE;
#if 0 // Example from Lipmaa paper, Fig.1
  uint32_t  x = 0x8330554;  // = 1000001100110000010101010100
  uint32_t yy = 0x8220554;	 // = 1000001000100000010101010100
  assert(n == 32);
  uint32_t y = aop(x, n);
  printf("yy= %8X, y = %8X\n", yy, y);
  assert(yy == y);
#else	 // random input
  uint32_t x = random32() & MASK;
  uint32_t y = aop(x, n);
  printf("x = %8X = ", x);
  print_binary(x);
  printf("\n");
  printf("y = %8X = ", y);
  print_binary(y);
  printf("\n");
#endif
}


/**
 * Tests for the CAP function.
 * \see cap .
 */
void test_cap()
{
#if 0 // Example from Lipmaa paper, Fig.1
  assert(WORD_SIZE == 32);
  uint32_t  x = 0x8330554;  // = 1000001100110000010101010100
  uint32_t  y = 0x40016C74; // = 0100'0000'0000'0001'0110'1100'0111'0100
  uint32_t cc = 0x824A;		 // = 1000'0010'0100'1010
  uint32_t c = cap(x, y);
  printf("cc = %8X, c = %8X\n", cc, c);
  assert(cc == c);
#else
  uint32_t x = random32() & MASK;
  uint32_t y = random32() & MASK;
  uint32_t c = cap(x, y);
  printf("c = %8X\n", c);
#endif

}

/**
 * Compare \ref xdp_add vs. \ref xdp_add_lm (the version by Lipmaa-Moriai).
 */
void test_xdp_add_vs_lm_all()
{
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

		  double p1 = xdp_add(A, da, db, dc);
		  assert((p1 >= 0.0) && (p1 <= 1.0));
		  double p2 = xdp_add_lm(da, db, dc);
#if 0
		  printf("[%s:%d] XDP_ADD_MY[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p1);
		  printf("[%s:%d] XDP_ADD_LM[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p2);
#else
		  printf("\r[%s:%d] XDP_ADD_LM[(%8X,%8X)->%8X] = %f %f", __FILE__, __LINE__, da, db, dc, p1, p2);
		  fflush(stdout);
#endif  // #if 1
		  assert(p1 == p2);
		}
	 }
  }
  xdp_add_free_matrices(A);
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Main function of XDP-ADD tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  assert(WORD_SIZE <= 10);
  srandom(time(NULL));
#if 0
  test_xdp_add_print_matrices_sage();
  test_cap();
  test_aop();
#endif
#if 1
  test_xdp_add_matrices();
  test_xdp_add();
  if(WORD_SIZE < 7) {
	 test_xdp_add_all();
  }
#endif
  // must be power of 2 for AOP to work
  if((WORD_SIZE == 4) || (WORD_SIZE == 8)) {
	 test_xdp_add_vs_lm_all();
  }
  return 0;
}
