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
  //  uint32_t h = 16;
  // (80810301,AC000098)->12C810399
  WORD_T da = 0xffffffff;//xrandom() & MASK;//gen_sparse(h, WORD_SIZE);//0x8081a0301;
  WORD_T db = 0xffffffff;//xrandom() & MASK;//gen_sparse(h, WORD_SIZE);//xrandom() & MASK;//0xAC000098;
  WORD_T dc = 0;//ADD(da, db);//xrandom() & MASK;//0x12C810399;
  double p0 = xdp_add_lm(da, db, dc);
  double p1 = xdp_add(A, da, db, dc);
  assert((p1 >= 0.0) && (p1 <= 1.0));
#if DEBUG_ADP_XOR_TESTS
  printf("[%s:%d] XDP_ADD_LM[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p0, log2(p0));
  printf("[%s:%d] XDP_ADD_TH[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p1, log2(p1));
#endif  // #if DEBUG_ADP_XOR_TESTS
#if(WORD_SIZE <= 16)
  double p2 = xdp_add_exper(da, db, dc);
  printf("[%s:%d] XDP_ADD_EX[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			__FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p2, log2(p2));
  assert(p1 == p2);
#endif // #if(WORD_SIZE <= 16)
  if(p0 != p1) {
	 printf("[%s:%d] XDP_ADD_LM[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			  __FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p0, log2(p0));
	 printf("[%s:%d] XDP_ADD_TH[(%llX,%llX)->%llX] = %6.5f 2^%4.2f\n", 
			  __FILE__, __LINE__, (WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc, p1, log2(p1));
  }
  assert(p0 == p1);
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Compare XDP-ADD to the experimental value.
 */
void test_xdp_add_all()
{
#if(WORD_SIZE <= 7)
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

		  double p3 = xdp_add_lm(da, db, dc, WORD_SIZE);
		  double p0 = xdp_add_lm(da, db, dc);
		  double p1 = xdp_add(A, da, db, dc);
		  double p2 = xdp_add_exper(da, db, dc);
		  assert((p1 >= 0.0) && (p1 <= 1.0));

#if DEBUG_XDP_ADD_TESTS
		  printf("[%s:%d] XDP_ADD_LM_PART[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p3);
		  printf("[%s:%d] XDP_ADD_LM[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p0);
		  printf("[%s:%d] XDP_ADD_TH[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p1);
		  printf("[%s:%d] XDP_ADD_EX[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p2);
#endif  // #if DEBUG_XDP_ADD_TESTS

		  assert(p0 == p2);
		  assert(p1 == p2);
		  assert(p3 == p2);
		}
	 }
  }
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
#endif // #if(WORD_SIZE <= 7)
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
  uint64_t  x = 0x8330554;  // = 1000001100110000010101010100
  uint64_t yy = 0x8220554;	 // = 1000001000100000010101010100
  //  assert(n == 32);
  uint64_t y = aop(x, n);
  printf("yy= %llX, y = %llX\n", (WORD_MAX_T)yy, (WORD_MAX_T)y);
  assert(yy == y);
#else	 // random input
  uint32_t x = xrandom() & MASK;
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
#if 1 // Example from Lipmaa paper, Fig.1
  //  assert(WORD_SIZE == 32);
  uint64_t x = 0x8330554;  // = 1000001100110000010101010100
  uint64_t  y = 0x40016C74; // = 0100'0000'0000'0001'0110'1100'0111'0100
  uint64_t cc = 0x824A;		 // = 1000'0010'0100'1010
  uint64_t c = cap(x, y);
  printf("cc = %llX, c = %llX\n", (WORD_MAX_T)cc, (WORD_MAX_T)c);
  assert(cc == c);
#else
  uint32_t x = xrandom() & MASK;
  uint32_t y = xrandom() & MASK;
  uint32_t c = cap(x, y);
  printf("c = %8X\n", c);
#endif

}

/**
 * Compare \ref xdp_add vs. \ref xdp_add_lm (the version by Lipmaa-Moriai).
 */
void test_xdp_add_vs_lm_all()
{
#if(WORD_SIZE <= 7)
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
#endif // #if(WORD_SIZE <= 7)
}

/**
 * Tests related to partitioning the input (cf. Massey paper)
 */
void test_xdp_add_partition()
{
  WORD_T i = 2;
  WORD_T da = (1UL << (i+1)) | (1UL << i);
  WORD_T db = (1UL << i);
  WORD_T cnt = 0;
  for(uint32_t a = 0; a < ALL_WORDS; a++) {
	 WORD_T a_i = (a >> i) & 3; // (a_{i+1} | a_i)
	 if(a_i != 1)
		continue;
	 print_binary(a);
	 printf("\n");
	 for(uint32_t b = 0; b < ALL_WORDS; b++) {
		cnt++;
		WORD_T aa = (a ^ da);
		WORD_T bb = (b ^ db);
		WORD_T x = ADD(a, b);
		WORD_T xx = ADD(aa, bb);
		WORD_T dx = (x ^ xx);
		//		WORD_T xx_tmp = ADD(ADD(x, (1UL << i)), (1UL << (i + 1))); // 00
		//		WORD_T xx_tmp = SUB(x, (1UL << i)); // 10
		WORD_T xx_tmp = ADD(x, (1UL << i)); // 01
		printf("%2d: dx %8X | x xx xt %8X %8X %8X ", cnt, dx, x, xx, xx_tmp);
		printf("| a b aa bb %8X %8X %8X %8X", a, b, aa, bb);
		printf("| da db %8X %8X\n", da, db);
	 }
  }
}

void test_xdp_add_lm()
{
  const WORD_T a = 2;//0x8000000000;
  const WORD_T b = 3;//0x800000000000;
  const WORD_T c = 7;//0x878000000000;
  uint32_t n = 3;//WORD_SIZE;
  double p_part = xdp_add_lm(a, b, c, n); // partial prob.
  double p = xdp_add_lm(a, b, c); // partial prob.
  printf("[%s:%d] n %d %llX %llX %llX %f %f\n", __FILE__, __LINE__, n, (WORD_MAX_T)a, (WORD_MAX_T)b, (WORD_MAX_T)c, p, p_part);
  assert(p == p_part);
}

/**
 * Main function of XDP-ADD tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));

  //  test_xdp_add_partition();
  //  test_xdp_add();
  //  assert(WORD_SIZE <= 10);
  //  test_xdp_add_print_matrices_sage();
  //  test_cap();
  //  test_aop();
  //  test_xdp_add_matrices();
  test_xdp_add_all();
  //  test_xdp_add_vs_lm_all();
  //  test_xdp_add_lm();
  return 0;
}
