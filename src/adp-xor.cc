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
 * \file  adp-xor.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of XOR \f$\mathrm{adp}^{\oplus}(da,db \rightarrow db)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif

/**
 * Allocate memory for the transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 * \see adp_xor_free_matrices
 */
void adp_xor_alloc_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 A[a][b][c] = gsl_matrix_calloc(ADP_XOR_MSIZE, ADP_XOR_MSIZE);
  }
}

/**
 * Free memory reserved by a previous call to \ref adp_xor_alloc_matrices.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 */
void adp_xor_free_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 gsl_matrix_free(A[a][b][c]);
  }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 */
void adp_xor_normalize_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;

	 for(int row = 0; row < ADP_XOR_MSIZE; row++){
		for(int col = 0; col < ADP_XOR_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  gsl_matrix_set(A[a][b][c], row, col, ADP_XOR_NORM * e);
		}
	 }
	 // check col sum
#if 1
	 for(int col = 0; col < ADP_XOR_MSIZE; col++){
		double col_sum = 0;
		for(int row = 0; row < ADP_XOR_MSIZE; row++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  col_sum += e;
		}
		assert((col_sum == 0.0) || (col_sum == 1.0));
	 }
#endif
  }
}

/**
 * Print the matrices for \f$\mathrm{adp}^{\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 */
void adp_xor_print_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("A%d%d%d \n", c, b, a);
	 for(int row = 0; row < ADP_XOR_MSIZE; row++){
		for(int col = 0; col < ADP_XOR_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f, ", e);
		}
		printf("\n");
	 }
	 printf("\n");

	 // check
#if 0
	 for(int col = 0; col < ADP_XOR_MSIZE; col++){
		uint32_t col_sum = 0;
		for(int row = 0; row < ADP_XOR_MSIZE; row++){
		  uint32_t e = gsl_matrix_get(A[a][b][c], row, col);
		  col_sum += e;
		}
		//					printf("%2d ", col_sum);
		assert((col_sum == 0) || (col_sum == 8));
	 }
#endif
  }
}

/**
 * Print the matrices for \f$\mathrm{adp}^{\oplus}\f$ in a format
 * readable by the computer algebra system Sage (http://www.sagemath.org/).
 *
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$.
 */
void adp_xor_print_matrices_sage(gsl_matrix* A[2][2][2])
{
  printf("# [%s:%d] Matrices for ADP-XOR generated with %s() \n", __FILE__, __LINE__, __FUNCTION__);

  printf("#--- Normalization factor --- \n");
  printf("f = %f\n", ADP_XOR_NORM);

  // print L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set_all(L, 1.0);
  printf("#--- Vector L --- \n");
  printf("L = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR_MSIZE; col++){
	 double e = gsl_vector_get(L, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set_zero(C);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);
  printf("#--- Vector C --- \n");
  printf("C = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR_MSIZE; col++){
	 double e = gsl_vector_get(C, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print A
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("#---AA%d%d%d--- \n", c, b, a);
	 printf("AA%d%d%d = matrix(QQ,%d,%d,[\n", c, b, a, ADP_XOR_MSIZE, ADP_XOR_MSIZE);
	 for(int row = 0; row < ADP_XOR_MSIZE; row++){
		for(int col = 0; col < ADP_XOR_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  printf("%3.2f", e);
		  if((row == ADP_XOR_MSIZE - 1) && (col == ADP_XOR_MSIZE - 1)) {
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
  for(int i = 0; i < ADP_XOR_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 printf("A%d%d%d = f * AA%d%d%d\n", c, b, a, c, b, a);
  }
  printf("\n");
  printf("A = [A000, A001, A010, A011, A100, A101, A110, A111]\n");
  printf("\n");
  printf("AA = [AA000, AA001, AA010, AA011, AA100, AA101, AA110, AA111]\n");
}

/** 
 * S-function for \f$\mathrm{adp}^{\oplus}\f$:
 * \f$\mathrm{adp}^{\oplus}(da,db \rightarrow db)\f$.
 *
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for \f$\mathrm{adp}^{\oplus}(da,db \rightarrow db)\f$.
 *
 * \f$A[2][2][2] = A[da[i]][db[i]][dc[i]]\f$, where 
 * 
 *   - \f$da[i]\f$ : the i-th bit of the first input difference.
 *   - \f$db[i]\f$ : the i-th bit of the second input difference.
 *   - \f$dc[i]\f$ : the i-th bit of the output difference.
 * 
 * \see xdp_add_sf
 */
void adp_xor_sf(gsl_matrix* A[2][2][2])
{
  // number of possible input differences
  uint32_t ndiffs = (1UL << ADP_XOR_NINPUTS);
  assert(ndiffs == 4);
  uint32_t nstates = ADP_XOR_MSIZE;
  uint32_t nvals = ndiffs;

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
	 //			 printf("%d%d\n", db, da);

	 for(int32_t u = 0; u < (int)nstates; u++) {
		int32_t t = u;
		int32_t in_s1 = t & 1;
		t /= 2;
		int32_t in_s2 = t & 1;
		t /= 2;
		int32_t in_s3 = (t & 1) - 1;
		t /= 2;
		//					printf("[%2d] %2d%2d%2d \n", u, in_s3, in_s2, in_s1);

		for(uint32_t j = 0; j < nvals; j++) {
		  uint32_t a1 = (j >> 0) & 1;
		  uint32_t b1 = (j >> 1) & 1;
		  //						  printf("%d%d\n", b1, a1);

		  // compute sf
		  uint32_t a2 = a1 ^ da ^ in_s1;
		  uint32_t b2 = b1 ^ db ^ in_s2;

		  int32_t out_s1 = (a1 + da + in_s1) >> 1;
		  int32_t out_s2 = (b1 + db + in_s2) >> 1;

		  // xor with three inputs
		  uint32_t c1 = a1 ^ b1;
		  uint32_t c2 = a2 ^ b2;
		  uint32_t dc = (c2 - c1 + in_s3) & 1;
		  assert((dc == 0) || (dc == 1));

		  int32_t out_s3 = (int32_t)(c2 - c1 + in_s3) >> 1; // signed shift i.e. -1 >> 1 == -1
		  assert((c2 - c1 + in_s3) == ((out_s3 * 2) + dc));

		  //						  printf("d2 = %d, d1 = %d, in_s3 = %d | out_s3 = %2d, dd = %2d\n", d2, d1, in_s3, out_s3, dd);

		  // checks
		  assert((out_s1 == 0) || (out_s1 == 1));
		  assert((out_s2 == 0) || (out_s2 == 1));
		  assert((out_s3 == 0) || (out_s3 == -1));

		  uint32_t v = 0;

		  // compose the output state
		  v = out_s3 + 1;
		  v *= 2;
		  v += out_s2;
		  v *= 2;
		  v += out_s1;

		  // add a link between U and V in the adjacency matrix
		  // 
		  //                   input u
		  //                     |
		  //                     V
		  //              [x] [x] [x] [x]  
		  // output v <-  [x] [x] [x] [x]  
		  //              [x] [x] [x] [x]  
		  // 
		  uint32_t col = u;
		  uint32_t row = v;
		  uint32_t e = gsl_matrix_get(A[da][db][dc], row, col);
		  e = e + 1;
		  gsl_matrix_set(A[da][db][dc], row, col, e);

		} // vals
	 }		  // states
  }			  // diffs
}

/**
 * The additive differential probability of XOR 
 * (\f$\mathrm{adp}^{\oplus}\f$). \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}\f$
 *        computed with \ref adp_xor_sf.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \returns \f$\mathrm{adp}^{\oplus}(da,db \rightarrow db)\f$.
 * \sa xdp_add
 */
double adp_xor(gsl_matrix* A[2][2][2], uint32_t da, uint32_t db, uint32_t dc)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);
  // init L
  for(int i = 0; i < ADP_XOR_MSIZE; i++)
	 gsl_vector_set(L, i, 1.0);

  R = gsl_vector_calloc(ADP_XOR_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (da >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;
	 uint32_t k = (dc >> pos) & 1;

	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));
	 assert((k == 0) || (k == 1));
	 //	 printf("[%s] --- checkpoint line #%d --- j = %d\n", __FILE__, __LINE__, pos);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j][k], C, 0.0, R);
	 //	 printf("[%s] --- checkpoint line #%d --- j = %d\n", __FILE__, __LINE__, pos);
	 gsl_vector_memcpy(C, R);

#if 1									  // DEBUG
	 double tmp_p = 0.0;
	 gsl_blas_ddot(L, R, &tmp_p);
	 if(tmp_p > p) {
		printf("[%s:%d] WARNING! %16.15f > %16.15f\n", __FILE__, __LINE__, p, tmp_p);
		//		assert(float_equals(*p, *p_max));
	 } 
#if 0
	 assert(tmp_p <= p);
#endif
	 p = tmp_p;
#endif
  }
#if 0									  // DEBUG
  printf("R  ");
  for(int i = 0; i < ADP_XOR_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_MSIZE; i++) {
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
  printf("%8X %8X %8X -> %8X : %f", da, db, dc, p);
#endif

  return p;
}

/**
 * The additive differential probability of XOR (\f$\mathrm{adp}^{\oplus}\f$)
 * computed experimentally over all inputs. \b Complexity: \f$O(2^{2n})\f$.
 * 
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \returns \f$\mathrm{adp}^{\oplus}(da,db \rightarrow db)\f$.
 * \see adp_xor
 */
double adp_xor_exper(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  assert(WORD_SIZE <= 10);
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 + da) % MOD;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 + db) % MOD;
		//		printf("%8X %8X\n", a1, b1);
		uint32_t c1 = a1 ^ b1;
		uint32_t c2 = a2 ^ b2;
		uint32_t dx = (c2 - c1 + MOD) % MOD;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc)
		  cnt++;
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}
