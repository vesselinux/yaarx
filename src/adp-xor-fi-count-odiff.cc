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
 * \file  adp-xor-fi-count-odiff.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Count the number of possible output differences after the operation
 *        XOR with a fixed input (FI).
 * \see adp-xor-fi.cc
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

/*
S = (s2, s1) = (1 + s2) * 2 + s1

s2, s1 | S
-----------
-1, 0  | 0
-1, 1  | 1
 0, 0  | 2   <- initial state
 0, 1  | 3

Sets of states outline: 

 s =  0: 0 0 0 0  =   0   S = empty set (impossible)
 s =  1: 1 0 0 0  =   1   S \in {0}
 s =  2: 0 1 0 0  =   2   S \in {1}
 s =  3: 1 1 0 0  =   3   S \in {0,1}
 s =  4: 0 0 1 0  =   4   S \in {2}      <- initial set of states
 s =  5: 1 0 1 0  =   5   S \in {0,2}
 s =  6: 0 1 1 0  =   6   S \in {2,3}
 s =  7: 1 1 1 0  =   7   S \in {0,1,2}
 s =  8: 0 0 0 1  =   8   S \in {3}
 s =  9: 1 0 0 1  =   9   S \in {0,3}
 s = 10: 0 1 0 1  =  10   S \in {1,3}
 s = 11: 1 1 0 1  =  11   S \in {0,1,3}
 s = 12: 0 0 1 1  =  12   S \in {2,3}
 s = 13: 1 0 1 1  =  13   S \in {0,2,3}
 s = 14: 0 1 1 1  =  14   S \in {1,2,3}
 s = 15: 1 1 1 1  =  15   S \in {0,1,2,3}
*/

void adp_xor_fi_count_odiff_alloc_matrices_3d(gsl_matrix* P[2][2][2])
{
  for(int i = 0; i < ADP_XOR_FI_COUNT_NMATRIX_3D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 P[a][b][c] = gsl_matrix_calloc(ADP_XOR_FI_COUNT_MSIZE, ADP_XOR_FI_COUNT_MSIZE);
  }
}

void adp_xor_fi_count_odiff_free_matrices_3d(gsl_matrix* P[2][2][2])
{
  for(int i = 0; i < ADP_XOR_FI_COUNT_NMATRIX_3D; i++){
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

void adp_xor_fi_count_odiff_alloc_matrices_2d(gsl_matrix* P[2][2])
{
  for(int i = 0; i < ADP_XOR_FI_COUNT_NMATRIX_2D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 P[a][b] = gsl_matrix_calloc(ADP_XOR_FI_COUNT_MSIZE, ADP_XOR_FI_COUNT_MSIZE);
  }
}

void adp_xor_fi_count_odiff_free_matrices_2d(gsl_matrix* P[2][2])
{
  for(int i = 0; i < ADP_XOR_FI_COUNT_NMATRIX_2D; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 gsl_matrix_free(P[a][b]);
  }
}

// Add matrices for the output diff bit equal 0 and 1: PP[a][da] = P[a][da][0] + P[a][da][1]
void adp_xor_fi_count_odiff_matrices_3d_to_2d(gsl_matrix* P[2][2][2], gsl_matrix* PP[2][2])
{
  for(uint32_t i = 0; i < 2; i++) {
	 for(uint32_t j = 0; j < 2; j++) {
		gsl_matrix_memcpy(PP[i][j], P[i][j][0]);
		gsl_matrix_add(PP[i][j], P[i][j][1]);
	 }
  }
}

void adp_xor_fi_count_odiff_sf(gsl_matrix* P[2][2][2], gsl_matrix* A[2][2][2])
{
  uint32_t ndiffs = (1U << 3);

  assert(ADP_XOR_FI_MSIZE == log2(ADP_XOR_FI_COUNT_MSIZE));

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t  a = (i >> 0) & 1;
	 uint32_t da = (i >> 1) & 1;
	 uint32_t db = (i >> 2) & 1;

#if 0									  // DEBUG
	 printf("[%s:%d] %d%d%d\n", __FILE__, __LINE__, db, da, a);
#endif

	 for(uint32_t s = 0; s < ADP_XOR_FI_COUNT_MSIZE; s++) {

		gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_MSIZE);
		for(int j = 0; j < ADP_XOR_FI_MSIZE; j++) {
		  if((s >> j) & 1) {
			 gsl_vector_set(C, j, 1.0);
		  }
		}
		gsl_vector* L = gsl_vector_calloc(ADP_XOR_FI_MSIZE);
#if 0									  // DEBUG
		printf("[%s:%d] s = %2d: ", __FILE__, __LINE__, s);
		for(int j = 0; j < ADP_XOR_FI_MSIZE; j++) {
		  double e = gsl_vector_get(C, j);
		  printf("%1.0f ", e);
		}
		printf("\n");
#endif

		gsl_blas_dgemv(CblasNoTrans, 1.0, A[a][da][db], C, 0.0, L);

		uint32_t t = 0;
		for(int j = 0; j < ADP_XOR_FI_MSIZE; j++) {
		  double e = gsl_vector_get(L, j);
		  if(e != 0.0) {
			 t |= (1 << j);
		  }
		}

#if 0									  // DEBUG
		printf("[%s:%d] L = %2d: ", __FILE__, __LINE__, t);
		for(int j = 0; j < ADP_XOR_FI_MSIZE; j++) {
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
		uint32_t e = gsl_matrix_get(P[a][da][db], row, col);
		e = e + 1;
		gsl_matrix_set(P[a][da][db], row, col, e);

		gsl_vector_free(L);
		gsl_vector_free(C);

	 }

#if 0									  // DEBUG
	 printf("\n");
#endif
  }
}

double adp_xor_fi_count_odiff_3d(gsl_matrix* A[2][2][2], uint32_t a, uint32_t db)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_FI_COUNT_ISTATE, 1.0);

  // init L
  gsl_vector_set_all(L, 1.0);
  gsl_vector_set(L, 0, 0.0);

  R = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (a >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;

	 //	 uint32_t k = (dc >> pos) & 1;
	 //  for(uint32_t k = 0; k < 2; k++) {
	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));

	 gsl_matrix* AA = gsl_matrix_calloc(ADP_XOR_FI_COUNT_MSIZE, ADP_XOR_FI_COUNT_MSIZE);
	 gsl_matrix_memcpy(AA, A[i][j][0]);
	 gsl_matrix_add(AA, A[i][j][1]);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, AA, C, 0.0, R);
	 //	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j][k], C, 0.0, R);
	 gsl_vector_memcpy(C, R);
	 gsl_matrix_free(AA);
  }

#if 0									  // DEBUG
  printf("R  ");
  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
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

double adp_xor_fi_count_odiff_2d(gsl_matrix* A[2][2], uint32_t a, uint32_t db)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_FI_COUNT_ISTATE, 1.0);
#if 0									  // DEBUG
  printf("[%s:%d] C^t[-1]  ", __FILE__, __LINE__);
  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%5.0f ", e);
  }
  printf("\n");
#endif

  // init L
  gsl_vector_set_all(L, 1.0);
  gsl_vector_set(L, 0, 0.0);

  R = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (a >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;

	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));

	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j], C, 0.0, R);
	 gsl_vector_memcpy(C, R);
#if 0									  // DEBUG
	 printf("[%s:%d] A%d%d\n", __FILE__, __LINE__, j, i);
	 printf("[%s:%d] C^t[%2d]  ", __FILE__, __LINE__, pos);
	 for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
		double e = gsl_vector_get(C, i);
		printf("%5.0f ", e);
	 }
	 printf("\n");
#endif
  }

#if 0									  // DEBUG
  printf("R  ");
  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%5.0f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
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

double adp_xor_fi_count_odiff_exper(const uint32_t a, const uint32_t db)
{
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;
  bool b_W[ALL_WORDS] = {false};

  for(uint32_t b1 = 0; b1 < N; b1++) {
	 uint32_t b2 = (b1 + db) % MOD;
	 uint32_t c1 = a ^ b1;
	 uint32_t c2 = a ^ b2;
	 uint32_t dx = (c2 - c1 + MOD) % MOD;
	 assert((dx >= 0) && (dx < MOD));
	 //	 printf("[%s:%d] %8X\n", __FILE__, __LINE__, dx);
	 if(b_W[dx] == false) {
#if 0									  // DEBUG
		printf("[%s:%d] %8X\n", __FILE__, __LINE__, dx);
#endif
		b_W[dx] = true;
		cnt++;
	 }
  }
  double p = (double)cnt;
  return p;
}


void adp_xor_fi_matrix_to_arrey_2d(gsl_matrix* A[2][2], 
											  uint32_t M[2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE])
{
  for(uint32_t d = 0; d < 4; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
#if 0									  // DEBUG
	 printf("[%s:%d] M%d%d\n", __FILE__, __LINE__, j, i);
#endif
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = gsl_matrix_get(A[i][j], row, col);
		  M[i][j][row][col] = e;
#if 0									  // DEBUG
		  printf("%2d", e);
#endif
		}
#if 0									  // DEBUG
		printf("\n");
#endif
	 }
#if 0									  // DEBUG
	 printf("\n");
#endif
  }
}

void adp_xor_fi_matrix_to_arrey_3d(gsl_matrix* A[2][2][2], 
											  uint32_t M[2][2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE])
{
  for(uint32_t d = 0; d < 8; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 uint32_t k = (d >> 2) & 1;
#if 0									  // DEBUG
	 printf("[%s:%d] M%d%d%d\n", __FILE__, __LINE__, k, j, i);
#endif
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = gsl_matrix_get(A[i][j][k], row, col);
		  //		  M[i][j][k][row][col] = e;
		  M[i][j][k][row][col] = e;
#if 0									  // DEBUG
		  printf("%2d", e);
#endif
		}
#if 0									  // DEBUG
		printf("\n");
#endif
	 }
#if 0									  // DEBUG
	 printf("\n");
#endif
  }
}

uint32_t adp_xor_fi_minimize_matrix_2d(gsl_matrix* A[2][2], 
													uint32_t C[2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE])
{
  uint32_t M[2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE];

  // init matrices
  for(uint32_t d = 0; d < 4; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;

	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  M[i][j][row][col] = 0;
		  C[i][j][row][col] = 0;
		}
	 }
  }

  adp_xor_fi_matrix_to_arrey_2d(A, M);

#if 1									  // DEBUG
  for(uint32_t d = 0; d < 4; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 printf("[%s:%d] M%d%d\n", __FILE__, __LINE__, j, i); // !!
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = M[i][j][row][col];
		  printf("%2d", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
#endif

  uint32_t n = combine_equiv<4>(&M[0][0], &C[0][0]);

#if 1									  // DEBUG
  printf("\n");
  for(uint32_t d = 0; d < 4; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 printf("[%s:%d] C%d%d\n", __FILE__, __LINE__, j, i);
	 for(uint32_t row = 0; row < n; row++) {
		for(uint32_t col = 0; col < n; col++) {
		  uint32_t e = C[i][j][row][col];
		  printf("%2d", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
#endif

  printf("[%s:%d] Size: original %d, new %d\n", __FILE__, __LINE__, ADP_XOR_FI_COUNT_MSIZE, n);
  return n;
}

uint32_t adp_xor_fi_minimize_matrix_3d(gsl_matrix* A[2][2][2], 
													uint32_t C[2][2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE])
{
  uint32_t M[2][2][2][ADP_XOR_FI_COUNT_MSIZE][ADP_XOR_FI_COUNT_MSIZE];

  // init matrices
  for(uint32_t d = 0; d < 8; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 uint32_t k = (d >> 2) & 1;

	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  M[i][j][k][row][col] = 0;
		  C[i][j][k][row][col] = 0;
		}
	 }
  }

  adp_xor_fi_matrix_to_arrey_3d(A, M);

#if 1									  // DEBUG
  for(uint32_t d = 0; d < 8; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 uint32_t k = (d >> 2) & 1;
	 printf("[%s:%d] M%d%d%d\n", __FILE__, __LINE__, k, j, i);
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = M[i][j][k][row][col];
		  printf("%2d", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
#endif

  uint32_t n = combine_equiv<8>(&M[0][0][0], &C[0][0][0]);

#if 1									  // DEBUG
  for(uint32_t d = 0; d < 8; d++) {
	 uint32_t i = (d >> 0) & 1;
	 uint32_t j = (d >> 1) & 1;
	 uint32_t k = (d >> 2) & 1;
	 printf("[%s:%d] C%d%d%d\n", __FILE__, __LINE__, k, j, i);
	 for(uint32_t row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++) {
		for(uint32_t col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++) {
		  uint32_t e = C[i][j][k][row][col];
		  printf("%2d", e);
		}
		printf("\n");
	 }
	 printf("\n");
  }
#endif

  printf("[%s:%d] Size: original %d, new %d\n", __FILE__, __LINE__, ADP_XOR_FI_COUNT_MSIZE, n);
  return n;
}

void adp_xor_fi_count_odiff_print_matrices_sage_2d(gsl_matrix* A[2][2])
{
  printf("# [%s:%d] Matrices for ADP-XOR-FI-COUNT-ODIFF generated with %s() \n", __FILE__, __LINE__, __FUNCTION__);
  printf("# Notation: A_{da a}: A10 => da = 1, a = 0\n");

  // print L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  gsl_vector_set_all(L, 1.0);
  gsl_vector_set(L, 0, 0.0);
  printf("#--- Vector L --- \n");
  printf("L = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++){
	 double e = gsl_vector_get(L, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR_FI_COUNT_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  gsl_vector_set_zero(C);
  gsl_vector_set(C, ADP_XOR_FI_COUNT_ISTATE, 1.0);
  printf("#--- Vector C --- \n");
  printf("C = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++){
	 double e = gsl_vector_get(C, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR_FI_COUNT_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print A
  for(int i = 0; i < ADP_XOR_FI_COUNT_NMATRIX_2D; i++){
	 int a = (i >> 0) & 1;		  // a
	 int b = (i >> 1) & 1;		  // da
	 printf("#---A%d%d--- \n", b, a);
	 printf("A%d%d = matrix(QQ,%d,%d,[\n", b, a, ADP_XOR_FI_COUNT_MSIZE, ADP_XOR_FI_COUNT_MSIZE);
	 for(int row = 0; row < ADP_XOR_FI_COUNT_MSIZE; row++){
		for(int col = 0; col < ADP_XOR_FI_COUNT_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b], row, col);
		  printf("%3.2f", e);
		  if((row == ADP_XOR_FI_COUNT_MSIZE - 1) && (col == ADP_XOR_FI_COUNT_MSIZE - 1)) {
			 printf(" ");
		  } else {
			 printf(", ");
		  }
		}
		printf("\n");
	 }
	 printf("])\n\n");
	 //	 printf("\n");
  }
  printf("\n");
  printf("A = [A00, A01, A10, A11]\n");
}

// special positions
void adp_xor_fi_count_odiff_min_set_size_spos(gsl_matrix* P[2][2])
{
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
  gsl_vector* R = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

  uint32_t N = (1U << ADP_XOR_FI_COUNT_MSIZE);//16;
  for(uint32_t s = 1; s < N; s++) {
	 gsl_vector_set_all(C, 0.0);
	 for(uint32_t i = 1; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
		uint32_t e = (s >> i) & 1;
		if(e != 0) {
		  gsl_vector_set(C, i, 1.0);
		}
	 }
	 for(int w = 0; w < 4; w++) {
		uint32_t  a = (w >> 0) & 1;
		uint32_t da = (w >> 1) & 1;
		gsl_vector_set_all(R, 0.0);
		gsl_blas_dgemv(CblasNoTrans, 1.0, P[a][da], C, 0.0, R);
		uint32_t nz_cnt = 0;
		for(uint32_t i = 1; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
		  double e = gsl_vector_get(R, i);
		  if(e != 0) {
			 nz_cnt++;
		  }
		}
#if 1									  // DEBUG
		if(nz_cnt > 1) {
		  printf("R^t ");
		  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
			 double e = gsl_vector_get(R, i);
			 printf("%1.0f ", e);
		  }
		  printf(" A%d%d ", da, a);
		  printf("C^t ");
		  for(int i = 0; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
			 double e = gsl_vector_get(C, i);
			 printf("%1.0f ", e);
		  }
		  printf("\n");
		}
#endif
	 }
  }

  gsl_vector_free(R);
  gsl_vector_free(C);
}

uint32_t g_cnt = 0;

void adp_xor_fi_count_odiff_min_set_size_i(uint32_t k, uint32_t n, uint32_t max_cnt, gsl_matrix* P[2][2], 
														 gsl_vector* C_in, uint32_t S_in[WORD_SIZE])
{
  if(k == n) {
	 g_cnt++;
#if 1									  // DEBUG
	 double cnt_ex = 0;
	 for(uint32_t i = 1; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
		double e = gsl_vector_get(C_in, i);
		cnt_ex += e;
	 }

	 uint32_t a = 0;
	 uint32_t da = 0;
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		 a |= ((S_in[i] & 1) << i);
		 da |= (((S_in[i] >> 1) & 1) << i);
	 }
	 double cnt_th = adp_xor_fi_count_odiff_2d(P, a, da);
	 printf("%8X %8X %f %f : ", a, da, cnt_ex, cnt_th);
#endif
#if 1									  // DEBUG
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		printf("%d", S_in[i]);
	 }
	 printf(" | ");
	 for(int i = 1; i < ADP_XOR_FI_COUNT_MSIZE; i++) {
		double e = gsl_vector_get(C_in, i);
		printf("%1.0f ", e);
	 }
	 //	 printf("\n");
	 printf(" | %20d 2^%f\n", g_cnt, log2((double)g_cnt));
#endif
	 assert(cnt_ex == cnt_th);
	 return;
  }

  for(int w = 0; w < 4; w++) {
	 gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);
	 gsl_vector* L = gsl_vector_calloc(ADP_XOR_FI_COUNT_MSIZE);

	 gsl_vector_memcpy(C, C_in);

	 uint32_t S[WORD_SIZE] = {0};
	 for(uint32_t i = 0; i < WORD_SIZE; i++) {
		S[i] = S_in[i];
	 }

	 uint32_t  a = (w >> 0) & 1;
	 uint32_t da = (w >> 1) & 1;

	 gsl_vector_set_all(R, 0.0);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, P[a][da], C, 0.0, R);

	 double cnt = 0;
	 gsl_vector_set_all(L, 1.0);
	 gsl_vector_set(L, 0, 0.0);
	 gsl_blas_ddot(L, R, &cnt);

	 if(cnt <= (double)max_cnt) {
		S[k] = w;
		gsl_vector_memcpy(C, R);
		adp_xor_fi_count_odiff_min_set_size_i(k+1, n, max_cnt, P, C, S);
	 }

	 gsl_vector_free(L);
	 gsl_vector_free(R);
	 gsl_vector_free(C);
  }
}

