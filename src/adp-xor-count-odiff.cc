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
 * \file  adp-xor-count-odiff.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Count the number of possible output ADD differences after XOR
 * \see adp-xor.cc , adp-xor-fi-count.cc
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

// see adp_xor_fi_count_odiff_alloc_matrices_3d
void adp_xor_count_odiff_alloc_matrices_3d(gsl_matrix* P[2][2][2])
{
  for(int i = 0; i < ADP_XOR_COUNT_NMATRIX_3D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 P[a][b][c] = gsl_matrix_calloc(ADP_XOR_COUNT_MSIZE, ADP_XOR_COUNT_MSIZE);
  }
}

// adp_xor_fi_count_odiff_free_matrices_3d
void adp_xor_count_odiff_free_matrices_3d(gsl_matrix* P[2][2][2])
{
  for(int i = 0; i < ADP_XOR_COUNT_NMATRIX_3D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 gsl_matrix_free(P[a][b][c]);
  }
}

// see adp_xor_fi_count_odiff_alloc_matrices_2d
void adp_xor_count_odiff_alloc_matrices_2d(gsl_matrix* P[2][2])
{
  for(int i = 0; i < ADP_XOR_COUNT_NMATRIX_2D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 P[a][b] = gsl_matrix_calloc(ADP_XOR_COUNT_MSIZE, ADP_XOR_COUNT_MSIZE);
  }
}

// see adp_xor_fi_count_odiff_free_matrices_2d
void adp_xor_count_odiff_free_matrices_2d(gsl_matrix* P[2][2])
{
  for(int i = 0; i < ADP_XOR_COUNT_NMATRIX_2D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 gsl_matrix_free(P[a][b]);
  }
}

//see  adp_xor_fi_count_odiff_matrices_3d_to_2d
void adp_xor_count_odiff_matrices_3d_to_2d(gsl_matrix* P[2][2][2], gsl_matrix* PP[2][2])
{
  for(uint32_t i = 0; i < 2; i++) {
	 for(uint32_t j = 0; j < 2; j++) {
		gsl_matrix_memcpy(PP[i][j], P[i][j][0]);
		gsl_matrix_add(PP[i][j], P[i][j][1]);
	 }
  }
}

// see also: adp_xor_fi_count_odiff_sf()
void adp_xor_count_odiff_sf(gsl_matrix* P[2][2][2], gsl_matrix* A[2][2][2])
{
  uint32_t ndiffs = (1U << 3);

  assert(ADP_XOR_MSIZE == log2(ADP_XOR_COUNT_MSIZE));

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
	 uint32_t dc = (i >> 2) & 1;

#if 0									  // DEBUG
	 printf("[%s:%d] %d%d%d\n", __FILE__, __LINE__, dc, db, da);
#endif

	 for(uint32_t s = 0; s < ADP_XOR_COUNT_MSIZE; s++) {

		gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
		for(int j = 0; j < ADP_XOR_MSIZE; j++) {
		  if((s >> j) & 1) {
			 gsl_vector_set(C, j, 1.0);
		  }
		}
		gsl_vector* L = gsl_vector_calloc(ADP_XOR_MSIZE);
#if 0									  // DEBUG
		printf("s = %3d: ", s);
		for(int j = 0; j < ADP_XOR_MSIZE; j++) {
		  double e = gsl_vector_get(C, j);
		  printf("%1.0f ", e);
		}
		printf("\n");
#endif

		gsl_blas_dgemv(CblasNoTrans, 1.0, A[da][db][dc], C, 0.0, L);

		uint32_t t = 0;
		for(int j = 0; j < ADP_XOR_MSIZE; j++) {
		  double e = gsl_vector_get(L, j);
		  if(e != 0.0) {
			 t |= (1 << j);
		  }
		}

#if 0									  // DEBUG
		printf("[%s:%d] L = %2d: ", __FILE__, __LINE__, t);
		for(int j = 0; j < ADP_XOR_MSIZE; j++) {
		  double e = gsl_vector_get(L, j);
		  if(e != 0) {
			 e = 1.0;
		  } else {
			 e = 0.0;
		  }
		  printf("%1.0f ", e);
		}
		printf("\n");
#endif

		uint32_t col = s;
		uint32_t row = t;
		uint32_t e = gsl_matrix_get(P[da][db][dc], row, col);
		e = e + 1;
		gsl_matrix_set(P[da][db][dc], row, col, e);

		gsl_vector_free(L);
		gsl_vector_free(C);

	 }

#if 0									  // DEBUG
	 printf("\n");
#endif
  }
}

// adp_xor_fi_count_odiff_3d
double adp_xor_count_odiff_3d(gsl_matrix* A[2][2][2], uint32_t da, uint32_t db)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_COUNT_ISTATE, 1.0);

  // init L
  gsl_vector_set_all(L, 1.0);
  gsl_vector_set(L, 0, 0.0);

  R = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (da >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;

	 //	 uint32_t k = (dc >> pos) & 1;
	 //  for(uint32_t k = 0; k < 2; k++) {
	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));

	 gsl_matrix* AA = gsl_matrix_calloc(ADP_XOR_COUNT_MSIZE, ADP_XOR_COUNT_MSIZE);
	 gsl_matrix_memcpy(AA, A[i][j][0]);
	 gsl_matrix_add(AA, A[i][j][1]);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, AA, C, 0.0, R);
	 //	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j][k], C, 0.0, R);
	 gsl_vector_memcpy(C, R);
	 gsl_matrix_free(AA);
  }

#if 0									  // DEBUG
  printf("R  ");
  for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(L, i);
	 printf("%f ", e);
  }
  printf("\n");
#endif
  gsl_blas_ddot(L, C, &p);

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);

#if 0									  // DEBUG
  printf("%8X %8X : %f", a, db, p);
#endif

  return p;
}

// adp_xor_fi_count_odiff_2d
double adp_xor_count_odiff_2d(gsl_matrix* A[2][2], uint32_t da, uint32_t db)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_COUNT_ISTATE, 1.0);
#if 0									  // DEBUG
  printf("[%s:%d] C^t[-1]  ", __FILE__, __LINE__);
  for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%5.0f ", e);
  }
  printf("\n");
#endif

  // init L
  gsl_vector_set_all(L, 1.0);
  gsl_vector_set(L, 0, 0.0);

  R = gsl_vector_calloc(ADP_XOR_COUNT_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (da >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;

	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));

	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j], C, 0.0, R);
	 gsl_vector_memcpy(C, R);
#if 0									  // DEBUG
	 printf("[%s:%d] A%d%d\n", __FILE__, __LINE__, j, i);
	 printf("[%s:%d] C^t[%2d]  ", __FILE__, __LINE__, pos);
	 for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
		double e = gsl_vector_get(C, i);
		printf("%5.0f ", e);
	 }
	 printf("\n");
#endif
  }

#if 0									  // DEBUG
  printf("R  ");
  for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%5.0f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(L, i);
	 printf("%5.0f ", e);
  }
  printf("\n");
#endif
  gsl_blas_ddot(L, C, &p);

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);

#if 0									  // DEBUG
  printf("%8X %8X : %f", a, db, p);
#endif

  return p;
}

// see also: adp_xor_fi_count_odiff_exper()
double adp_xor_count_odiff_exper(const uint32_t da, const uint32_t db)
{
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;
  bool b_W[ALL_WORDS] = {false};

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t a2 = (a1 + da) % MOD;
		uint32_t b2 = (b1 + db) % MOD;
		uint32_t c1 = a1 ^ b1;
		uint32_t c2 = a2 ^ b2;
		uint32_t dx = (c2 - c1 + MOD) % MOD;
		assert((dx >= 0) && (dx < MOD));
		if(b_W[dx] == false) {
#if 0									  // DEBUG
		  printf("%8X\n", dx);
#endif
		  b_W[dx] = true;
		  cnt++;
		}
	 }
  }
  double p = (double)cnt;
  return p;
}
