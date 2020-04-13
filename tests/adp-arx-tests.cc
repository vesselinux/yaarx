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
 * \file  adp-arx-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-arx.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_ARX_H
#include "adp-arx.hh"
#endif
#ifndef MAX_ADP_ARX_H
#include "max-adp-arx.hh"
#endif

/**
 * Test allocation and free of ADP-ARX matrices.
 */
void test_adp_arx_matrices()
{
  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
#if DEBUG_ADP_ARX_TESTS
  adp_arx_print_matrices(A);
#endif  // #if DEBUG_ADP_ARX_TESTS
  adp_arx_normalize_matrices(A);
  adp_arx_free_matrices(A);
}

/**
 * Compare ADP-ARX to the experimental value for a single input.
 */
void test_adp_arx()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint32_t r = xrandom() % WORD_SIZE;
  uint32_t da = xrandom() & MASK;
  uint32_t db = xrandom() & MASK;
  uint32_t dd = xrandom() & MASK;
  uint32_t de = xrandom() & MASK;

  double p1 = adp_arx(A, r, da, db, dd, de);
  assert((p1 >= 0.0) && (p1 <= 1.0));
  double p2 = adp_arx_exper(r, da, db, dd, de);

#if 1//DEBUG_ADP_ARX_TESTS
  printf("[%s:%d] ADP_ARX_TH[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, r, da, db, dd, de, p1);
  printf("[%s:%d] ADP_ARX_EX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, r, da, db, dd, de, p2);
#endif  // #if DEBUG_ADP_ARX_TESTS
  assert(p1 == p2);

  adp_arx_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Test ADP-ARX to the experimental value for \p N random differences.
 */
void test_adp_arx_rand(uint32_t N)
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  for(uint32_t i = 0; i < N; i++) {
	 uint32_t r = xrandom() % WORD_SIZE;
	 uint32_t da = xrandom() & MASK;
	 uint32_t db = xrandom() & MASK;
	 uint32_t dd = xrandom() & MASK;
	 uint32_t de = xrandom() & MASK;

	 double p1 = adp_arx(A, r, da, db, dd, de);
	 double p2 = adp_arx_exper(r, da, db, dd, de);
	 assert((p2 >= 0.0) && (p2 <= 1.0));

#if 0
	 printf("[%s:%d] ADP_ARX_TH[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de, p1, log2(p1));
	 printf("[%s:%d] ADP_ARX_EX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de, p2, log2(p2));
#else
	 printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
	 fflush(stdout);
#endif
	 assert(p1 == p2);

  }

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Compare ADP-ARX to the experimental value for all input differences.
 */
void test_adp_arx_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE <= 10);
  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t r = 0; r < WORD_SIZE; r++) {
	 for(uint32_t da = 0; da < N; da++) {
		for(uint32_t db = 0; db < N; db++) {
		  for(uint32_t dd = 0; dd < N; dd++) {
			 for(uint32_t de = 0; de < N; de++) {
				double p1 = adp_arx(A, r, da, db, dd, de);
				assert((p1 >= 0.0) && (p1 <= 1.0));
				double p2 = adp_arx_exper(r, da, db, dd, de);
#if 0//DEBUG_ADP_ARX_TESTS
				printf("[%s:%d] ADP_ARX_TH[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
						 __FILE__, __LINE__, r, da, db, dd, de, p1);
				printf("[%s:%d] ADP_ARX_EX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
						 __FILE__, __LINE__, r, da, db, dd, de, p2);
#endif  // #if DEBUG_ADP_ARX_TESTS
#if 1	  // DEBUG_ADP_ARX_TESTS
				printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
				fflush(stdout);
#endif
				assert(p1 == p2);
			 }
		  }
		}
	 }
  }
  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Test MAX-ADP-ARX to the experimental value for \p N random differences.
 */
void test_max_adp_arx_rand(uint32_t N)
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  for(uint32_t i = 0; i < N; i++) {
	 uint32_t r = xrandom() % WORD_SIZE;
	 uint32_t da = xrandom() & MASK;
	 uint32_t db = xrandom() & MASK;
	 uint32_t dd = xrandom() & MASK;
	 uint32_t de_max = 0;

	 double p1 = max_adp_arx(A, r, da, db, dd, &de_max);
	 double p2 = adp_arx(A, r, da, db, dd, de_max);
	 assert((p2 >= 0.0) && (p2 <= 1.0));

#if 0
	 printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de_max, p1, log2(p1));
	 printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			  __FILE__, __LINE__, r, da, db, dd, de_max, p2, log2(p2));
#else
	 printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
	 fflush(stdout);
#endif
	 assert(p1 == p2);

  }

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_arx()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint32_t r = xrandom() % WORD_SIZE;
  uint32_t da = xrandom() & MASK;
  uint32_t db = xrandom() & MASK;
  uint32_t dd = xrandom() & MASK;
  uint32_t de_max = 0;

  double p1 = max_adp_arx(A, r, da, db, dd, &de_max);
  double p2 = adp_arx(A, r, da, db, dd, de_max);
  assert((p2 >= 0.0) && (p2 <= 1.0));

#if 0
  printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			__FILE__, __LINE__, r, da, db, dd, de_max, p1, log2(p1));
  printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f (2^%f)\n", 
			__FILE__, __LINE__, r, da, db, dd, de_max, p2, log2(p2));
#else
  printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
  fflush(stdout);
#endif
  assert(p1 == p2);

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_arx_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint64_t N = ALL_WORDS;

  for(uint32_t r = 0; r < WORD_SIZE; r++) {
	 for(uint32_t da = 0; da < N; da++) {
		for(uint32_t db = 0; db < N; db++) {
		  for(uint32_t dd = 0; dd < N; dd++) {

			 uint32_t de_max = 0;
			 double p1 = max_adp_arx(A, r, da, db, dd, &de_max);

			 double p2 = adp_arx(A, r, da, db, dd, de_max);
			 assert((p2 >= 0.0) && (p2 <= 1.0));

#if 0
			 printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, r, da, db, dd, de_max, p1);
			 printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, r, da, db, dd, de_max, p2);
#else
			 printf("\r[%s:%d] %2d / %2d | %2d %f %f", __FILE__, __LINE__, r, WORD_SIZE, r, p1, p2);
			 fflush(stdout);
#endif
			 assert(p1 == p2);
		  }
		}
	 }
  }

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_arx_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint32_t r = 1;//xrandom() % WORD_SIZE;
  uint32_t da = 0;//xrandom() & MASK;
  uint32_t db = 0;//xrandom() & MASK;
  uint32_t dd = 0;//xrandom() & MASK;
  uint32_t de_max_th = 0;
  uint32_t de_max_ex = 0;

  double p_th = max_adp_arx(A, r, da, db, dd, &de_max_th);
  double p_ex = max_adp_arx_exper(A, r, da, db, dd, &de_max_ex);

#if 1
  printf("[%s:%d] ADP_ARX_MAX_TH[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, r, da, db, dd, de_max_th, p_th);
  printf("[%s:%d] ADP_ARX_MAX_EX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, r, da, db, dd, de_max_ex, p_ex);
#endif
  assert(p_th == p_ex);

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_arx_is_max_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  gsl_matrix* A[2][2][2][2];
  adp_arx_alloc_matrices(A);
  adp_arx_sf(A);
  adp_arx_normalize_matrices(A);

  uint64_t N = ALL_WORDS;

  for(uint32_t r = 0; r < WORD_SIZE; r++) {
	 for(uint32_t da = 0; da < N; da++) {
		for(uint32_t db = 0; db < N; db++) {
		  for(uint32_t dd = 0; dd < N; dd++) {

			 uint32_t de_max_th = 0;
			 uint32_t de_max_ex = 0;

			 double p_th = max_adp_arx(A, r, da, db, dd, &de_max_th);
			 double p_ex = max_adp_arx_exper(A, r, da, db, dd, &de_max_ex);

#if 0
			 printf("[%s:%d] ADP_ARX_MAX_TH[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, r, da, db, dd, de_max_th, p_th);
			 printf("[%s:%d] ADP_ARX_MAX_EX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
					  __FILE__, __LINE__, r, da, db, dd, de_max_ex, p_ex);
#else
			 printf("\r[%s:%d] %2d / %2d | (%2d|%8X,%8X,%8X)->%8X %8X %f %f", __FILE__, __LINE__, r, WORD_SIZE-1, r, da, db, dd, de_max_th, de_max_ex, p_th, p_ex);
			 fflush(stdout);
#endif
			 assert(p_th == p_ex);
		  }
		}
	 }
  }

  adp_arx_free_matrices(A);
  printf("\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Main function of ADP-ARX tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));

#if 1									  // MAX-ADP-ARX
  if(WORD_SIZE <= 5) {
	 test_max_adp_arx_is_max();
	 test_max_adp_arx_is_max_all();
	 test_max_adp_arx();
	 test_max_adp_arx_all();
  } else {
	 uint32_t N = (1UL << 10);
	 test_max_adp_arx_rand(N);
	 test_max_adp_arx();
  }
#endif

#if 1									  // ADP-ARX
  test_adp_arx_matrices();
  test_adp_arx();
  if(WORD_SIZE < 5) {
	 test_adp_arx_all();
  } else {
	 uint32_t N = (1UL << 15);
	 test_adp_arx_rand(N);
  }
#endif
  return 0;
}
