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
 * \file  adp-xor-count-odiff-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xor-count-odiff.cc .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef ADP_XOR_COUNT_ODIFF_H
#include "adp-xor-count-odiff.hh"
#endif

// see test_dp_xor_fi_count_odiff_matrices
void test_adp_xor_count_odiff_matrices()
{
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_count_odiff_alloc_matrices_3d(P);
  adp_xor_count_odiff_sf(P, A);

  uint32_t ndiffs = (1U << 3);

  assert(ADP_XOR_MSIZE == log2(ADP_XOR_COUNT_MSIZE));

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
	 uint32_t dc = (i >> 2) & 1;
#if 1									  // DEBUG
	 printf("P%d%d%d =\n", dc, db, da);
#endif
	 for(uint32_t row = 0; row < ADP_XOR_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_COUNT_MSIZE; col++) {
		  uint32_t e = gsl_matrix_get(P[da][db][dc], row, col);
#if 1									  // DEBUG
		  if(e != 0) {
			 printf("%d", e);
		  } else {
			 printf(".");
		  }
#endif
		}
#if 1									  // DEBUG
		printf("\n");
#endif
	 }
  }

  adp_xor_count_odiff_free_matrices_3d(P);
  adp_xor_free_matrices(A);
}

void test_adp_xor_count_odiff()
{
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_count_odiff_alloc_matrices_3d(P);
  adp_xor_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_count_odiff_alloc_matrices_2d(PP);
  adp_xor_count_odiff_matrices_3d_to_2d(P, PP);

  uint32_t cnt_min = ALL_WORDS;
  uint32_t da_min = 0;
  uint32_t da = random32() & MASK;
  for(uint32_t i = 1; i < ALL_WORDS; i++) {
	 da = i;
	 uint32_t db = 0x4000;//random32() & MASK;

	 double cnt_1 = adp_xor_count_odiff_3d(P, da, db);
	 double cnt_2 = adp_xor_count_odiff_2d(PP, da, db);
#if (WORD_SIZE <= 10)
	 double cnt_3 = adp_xor_count_odiff_exper(da, db);
	 printf("%8X %8X %4.0f %4.0f %4.0f\n", da, db, cnt_1, cnt_2, cnt_3);
#else
	 //	 printf("%8X %8X %4.0f %4.0f\n", da, db, cnt_1, cnt_2);
#endif
	 if(cnt_1 <= cnt_min) {
		cnt_min = cnt_1;
		da_min = da;
		printf("%8X %d\n", da_min, cnt_min);
	 }
  }
  adp_xor_count_odiff_free_matrices_2d(PP);
  adp_xor_count_odiff_free_matrices_3d(P);
  adp_xor_free_matrices(A);
}

void test_adp_xor_count_odiff_all()
{
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_count_odiff_alloc_matrices_3d(P);
  adp_xor_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_count_odiff_alloc_matrices_2d(PP);
  adp_xor_count_odiff_matrices_3d_to_2d(P, PP);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t da = 0; da < N; da++) {
	 for(uint32_t db = 0; db < N; db++) {

		double cnt_1 = adp_xor_count_odiff_3d(P, da, db);
		double cnt_2 = adp_xor_count_odiff_2d(PP, da, db);
		double cnt_3 = adp_xor_count_odiff_exper(da, db);
#if 0				  // DEBUG
		printf("%8X %8X %4.0f %4.0f %4.0f\n", da, db, cnt_1, cnt_2, cnt_3);
#else
		printf("\r%8X %8X %4.0f %4.0f %4.0f", da, db, cnt_1, cnt_2, cnt_3);
		fflush(stdout);
#endif
#if 0
		if(cnt_1 < 4) {
		  printf("\n%8X %8X %4.0f %4.0f %4.0f\n", da, db, cnt_1, cnt_2, cnt_3);
		}
#endif
		assert(cnt_1 == cnt_2);
		assert(cnt_1 == cnt_3);
	 }
  }

  adp_xor_count_odiff_free_matrices_2d(PP);
  adp_xor_count_odiff_free_matrices_3d(P);
  adp_xor_free_matrices(A);
  printf("\n[%s:%d] OK\n", __FILE__, __LINE__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  test_adp_xor_count_odiff();
#if 0
  test_adp_xor_count_odiff_all();
  test_adp_xor_count_odiff_matrices();
#endif
  return 0;
}
