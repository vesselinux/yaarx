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
 * \file  adp-xor-fi-count-odiff-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xor-fi-count-odiff.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif
#ifndef DP_MATRIX_MINIMIZE_H
#include "dp-matrix-minimize.hh"
#endif
#ifndef ADP_XOR_FI_COUNT_ODIFF_H
#include "adp-xor-fi-count-odiff.hh"
#endif

// --- TESTS ---

void test_adp_xor_fi_count_odiff_min_set_size_i()
{
  uint32_t k = 0; 
  uint32_t n = WORD_SIZE;
  uint32_t max_cnt = 1;
  uint32_t S[WORD_SIZE] = {0};

  gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  gsl_vector_set(C, ADP_XOR_FI_COUNT_ISTATE, 1.0);

  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  adp_xor_fi_count_odiff_min_set_size_i(k, n, max_cnt, PP, C, S);

  gsl_vector_free(C);
  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

void test_adp_xor_fi_count_odiff_min_set_size()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  adp_xor_fi_count_odiff_min_set_size_spos(PP);

  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

void test_adp_xor_fi_minimize_matrix_2d()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  uint32_t C[2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE];

  adp_xor_fi_minimize_matrix_2d(PP, C);

  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

void test_dp_xor_fi_count_odiff_matrices()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  uint32_t ndiffs = (1U << 3);

  assert(ADP_XOR_FI_MSIZE == log2(ADP_XOR_FI_COUNT_MSIZE));

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t  a = (i >> 0) & 1;
	 uint32_t da = (i >> 1) & 1;
	 uint32_t db = (i >> 2) & 1;
#if 1									  // DEBUG
	 printf("P%d%d%d =\n", db, da, a);
#endif
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = gsl_matrix_get(P[a][da][db], row, col);
#if 1									  // DEBUG
		  printf("%d ", e);
#endif
		}
#if 1									  // DEBUG
		printf("\n");
#endif
	 }
  }

  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

void test_dp_xor_fi_count_odiff()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  uint32_t a = 0xC000;//random32() & MASK;
  uint32_t da = 0x377B;//random32() & MASK;

  double cnt_1 = adp_xor_fi_count_odiff_3d(P, a, da);
  double cnt_2 = adp_xor_fi_count_odiff_2d(PP, a, da);
  double cnt_3 = adp_xor_fi_count_odiff_exper(a, da);

  printf("%8X %8X %4.0f %4.0f %4.0f\n", a, da, cnt_1, cnt_2, cnt_3);

  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

void test_dp_xor_fi_count_odiff_all()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t a = 0; a < N; a++) {
	 for(uint32_t da = 0; da < N; da++) {

		double cnt_1 = adp_xor_fi_count_odiff_3d(P, a, da);
		double cnt_2 = adp_xor_fi_count_odiff_2d(PP, a, da);
		double cnt_3 = adp_xor_fi_count_odiff_exper(a, da);
#if 0				  // DEBUG
		printf("%8X %8X %4.0f %4.0f %4.0f\n", a, da, cnt_1, cnt_2, cnt_3);
#else
		printf("\r%8X %8X %4.0f %4.0f %4.0f", a, da, cnt_1, cnt_2, cnt_3);
		fflush(stdout);
#endif
		assert(cnt_1 == cnt_2);
		assert(cnt_1 == cnt_3);
	 }
  }

  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
}

void test_adp_xor_fi_count_odiff_print_matrices_sage_2d()
{
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  gsl_matrix* P[2][2][2];
  adp_xor_fi_count_odiff_alloc_matrices_3d(P);
  adp_xor_fi_count_odiff_sf(P, A);

  gsl_matrix* PP[2][2];
  adp_xor_fi_count_odiff_alloc_matrices_2d(PP);
  adp_xor_fi_count_odiff_matrices_3d_to_2d(P, PP);

  adp_xor_fi_count_odiff_print_matrices_sage_2d(PP);

  adp_xor_fi_count_odiff_free_matrices_2d(PP);
  adp_xor_fi_count_odiff_free_matrices_3d(P);
  adp_xor_fixed_input_free_matrices(A);
}

int main()
{
  printf("# [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  test_dp_xor_fi_count_odiff();
#if 0
  test_adp_xor_fi_count_odiff_min_set_size_i();
  test_adp_xor_fi_count_odiff_min_set_size();
  test_adp_xor_fi_count_odiff_print_matrices_sage_2d();
  test_adp_xor_fi_minimize_matrix_2d();
  test_dp_xor_fi_count_odiff_all();
  test_dp_xor_fi_count_odiff_matrices();
#endif
  return 0;
}
