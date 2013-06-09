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
 * \file  adp-xor3.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of XOR with three inputs (\f$3\oplus\f$):
 *        \f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif

/**
 * Allocate memory for the transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 * \see adp_xor3_free_matrices
 */
void adp_xor3_alloc_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 int d = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d%d \n", d, c, b, a);
	 A[a][b][c][d] = gsl_matrix_calloc(ADP_XOR3_MSIZE, ADP_XOR3_MSIZE);
  }

}

/**
 * Free memory reserved by a previous call to \ref adp_xor3_alloc_matrices.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 */
void adp_xor3_free_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 int d = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d%d \n", d, c, b, a);
			 //			 if(A[a][b][c][d] != NULL)
	 gsl_matrix_free(A[a][b][c][d]);
  }
}

/**
 * Print the matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 */
void adp_xor3_print_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 int d = (i >> 3) & 1;
	 printf("A%d%d%d%d \n", d, c, b, a);
	 for(int row = 0; row < ADP_XOR3_MSIZE; row++){
		for(int col = 0; col < ADP_XOR3_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c][d], row, col);
		  printf("%3.2f, ", e);
		}
		printf("\n");
	 }
	 printf("\n");

	 // check
#if 0
	 for(int col = 0; col < ADP_XOR3_MSIZE; col++){
		uint32_t col_sum = 0;
		for(int row = 0; row < ADP_XOR3_MSIZE; row++){
		  uint32_t e = gsl_matrix_get(A[a][b][c][d], row, col);
		  col_sum += e;
		}
		//					printf("%2d ", col_sum);
		assert((col_sum == 0) || (col_sum == 8));
	 }
#endif
  }
}

/**
 * Print the matrices for \f$\mathrm{adp}^{3\oplus}\f$ in a format
 * readable by the computer algebra system Sage (http://www.sagemath.org/).
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 */
void adp_xor3_print_matrices_sage(gsl_matrix* A[2][2][2][2])
{

  printf("#--- Normalization factor --- \n");
  printf("f = %f\n", ADP_XOR3_NORM);

  // print L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);
  printf("#--- Vector L --- \n");
  printf("L = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR3_MSIZE; col++){
	 double e = gsl_vector_get(L, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR3_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_zero(C);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);
  printf("#--- Vector C --- \n");
  printf("C = vector(QQ,[ ");
  for(int col = 0; col < ADP_XOR3_MSIZE; col++){
	 double e = gsl_vector_get(C, col);
	 printf("%4.3f", e);
	 if(col == ADP_XOR3_MSIZE - 1) {
		printf(" ");
	 } else {
		printf(", ");
	 }
  }
  printf("])\n\n");

  // print A
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 int d = (i >> 3) & 1;
	 printf("#---AA%d%d%d%d--- \n", d, c, b, a);
	 printf("AA%d%d%d%d = matrix(QQ,%d,%d,[\n", d, c, b, a, ADP_XOR3_MSIZE, ADP_XOR3_MSIZE);
	 for(int row = 0; row < ADP_XOR3_MSIZE; row++){
		for(int col = 0; col < ADP_XOR3_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c][d], row, col);
		  printf("%3.2f", e);
		  if((row == ADP_XOR3_MSIZE - 1) && (col == ADP_XOR3_MSIZE - 1)) {
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
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 int d = (i >> 3) & 1;
	 printf("A%d%d%d%d = f * AA%d%d%d%d\n", d, c, b, a, d, c, b, a);
  }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$.
 */
void adp_xor3_normalize_matrices(gsl_matrix* A[2][2][2][2])
{
  for(int i = 0; i < ADP_XOR3_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;
	 int d = (i >> 3) & 1;

	 for(int row = 0; row < ADP_XOR3_MSIZE; row++){
		for(int col = 0; col < ADP_XOR3_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c][d], row, col);
		  gsl_matrix_set(A[a][b][c][d], row, col, ADP_XOR3_NORM * e);
		}
	 }
	 // check col sum
#if 1
	 for(int col = 0; col < ADP_XOR3_MSIZE; col++){
		double col_sum = 0;
		for(int row = 0; row < ADP_XOR3_MSIZE; row++){
		  double e = gsl_matrix_get(A[a][b][c][d], row, col);
		  col_sum += e;
		}
		assert((col_sum == 0.0) || (col_sum == 1.0));
	 }
#endif
  }
}

/**
 * Transform the values of the four states of the S-function
 * for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf) into an index.
 *
 * \param s1 state corresponding to the first input difference.
 * \param s2 state corresponding to the second input difference.
 * \param s3 state corresponding to the third input difference.
 * \param s4 state corresponding to the output difference.
 * \returns the index \f$i = (s_4 + 1)2^3 + s_3 2^2 + s_2 2 + s_1\f$
 */
int adp_xor3_states_to_index(int s1, int s2, int s3, int s4)
{
  int idx = ((s4 + 1) << 3) + (s3 << 2) + (s2 << 1) + s1;
  return idx; 
}

/** 
 * S-function for \f$\mathrm{adp}^{3\oplus}\f$:
 * \f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$.
 *
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for \f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$.
 *
 * \f$A[2][2][2][2] = A[da[i]][db[i]][dc[i]][dd[i]]\f$, where 
 * 
 *   - \f$da[i]\f$ : the i-th bit of the first input difference.
 *   - \f$db[i]\f$ : the i-th bit of the second input difference.
 *   - \f$dc[i]\f$ : the i-th bit of the third input difference.
 *   - \f$dd[i]\f$ : the i-th bit of the output difference.
 * 
 * \see adp_xor_sf
 */
void adp_xor3_sf(gsl_matrix* A[2][2][2][2])
{

  // number of possible input differences
  uint32_t ndiffs = (1UL << ADP_XOR3_NINPUTS);
  assert(ndiffs == 8);
  uint32_t nstates = ADP_XOR3_MSIZE;
  uint32_t nvals = ndiffs;

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
	 uint32_t dc = (i >> 2) & 1;
	 //			 printf("%d%d%d\n", dc, db, da);

	 for(int32_t u = 0; u < (int)nstates; u++) {
		int32_t t = u;
		int32_t in_s1 = t & 1;
		t /= 2;
		int32_t in_s2 = t & 1;
		t /= 2;
		int32_t in_s3 = t & 1;
		t /= 2;
		int32_t in_s4 = (t & 1) - 1;
		t /= 2;
		//					printf("[%2d] %2d%2d%2d%2d \n", u, in_s4, in_s3, in_s2, in_s1);

		for(uint32_t j = 0; j < nvals; j++) {
		  uint32_t a1 = (j >> 0) & 1;
		  uint32_t b1 = (j >> 1) & 1;
		  uint32_t c1 = (j >> 2) & 1;
		  //						  printf("%d%d%d\n", c1, b1, a1);

		  // compute sf
		  uint32_t a2 = a1 ^ da ^ in_s1;
		  uint32_t b2 = b1 ^ db ^ in_s2;
		  uint32_t c2 = c1 ^ dc ^ in_s3;

		  int32_t out_s1 = (a1 + da + in_s1) >> 1;
		  int32_t out_s2 = (b1 + db + in_s2) >> 1;
		  int32_t out_s3 = (c1 + dc + in_s3) >> 1;

		  // xor with three inputs
		  uint32_t d1 = a1 ^ b1 ^ c1;
		  uint32_t d2 = a2 ^ b2 ^ c2;
		  uint32_t dd = (d2 - d1 + in_s4) & 1;
		  assert((dd == 0) || (dd == 1));

		  int32_t out_s4 = (int32_t)(d2 - d1 + in_s4) >> 1; // signed shift i.e. -1 >> 1 == -1
		  assert((d2 - d1 + in_s4) == ((out_s4 * 2) + dd));

		  //						  printf("d2 = %d, d1 = %d, in_s4 = %d | out_s4 = %2d, dd = %2d\n", d2, d1, in_s4, out_s4, dd);

		  // checks
		  assert((out_s1 == 0) || (out_s1 == 1));
		  assert((out_s2 == 0) || (out_s2 == 1));
		  assert((out_s3 == 0) || (out_s3 == 1));
		  assert((out_s4 == 0) || (out_s4 == -1));

		  uint32_t v = 0;

		  // compose the output state
		  v = out_s4 + 1;
		  v *= 2;
		  v += out_s3;
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
		  uint32_t e = gsl_matrix_get(A[da][db][dc][dd], row, col);
		  e = e + 1;
		  gsl_matrix_set(A[da][db][dc][dd], row, col, e);

		} // vals
	 }		  // states
  }			  // diffs
}

/**
 * The additive differential probability (ADP) of 
 * \f$\mathrm{adp}^{3\oplus}\f$. \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$
 *        computed with \ref adp_xor3_sf.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd output difference.
 * \returns \f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$.
 * \see adp_xor
 */
double adp_xor3(gsl_matrix* A[2][2][2][2], uint32_t da, uint32_t db, uint32_t dc, uint32_t dd)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  C = gsl_vector_calloc(ADP_XOR3_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);
  // init L
  for(int i = 0; i < ADP_XOR3_MSIZE; i++)
	 gsl_vector_set(L, i, 1.0);

  R = gsl_vector_calloc(ADP_XOR3_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (da >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;
	 uint32_t k = (dc >> pos) & 1;
	 uint32_t l = (dd >> pos) & 1;

	 assert((i == 0) || (i == 1));
	 assert((j == 0) || (j == 1));
	 assert((k == 0) || (k == 1));
	 assert((l == 0) || (l == 1));
	 //	 printf("[%s] --- checkpoint line #%d --- j = %d\n", __FILE__, __LINE__, pos);
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i][j][k][l], C, 0.0, R);
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
  for(int i = 0; i < ADP_XOR3_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR3_MSIZE; i++) {
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
  printf("%8X %8X %8X -> %8X : %f", da, db, dc, dd, p);
#endif

  return p;
}

/**
 * The additive differential probability (ADP) of \f$\mathrm{adp}^{3\oplus}\f$ 
 * computed experimentally over all inputs. \b Complexity: \f$O(2^{3n})\f$.
 * 
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd output difference.
 * \returns \f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$.
 * \see adp_xor
 */
double adp_xor3_exper(const uint32_t da, const uint32_t db, const uint32_t dc, const uint32_t dd)
{
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 + da) % MOD;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 + db) % MOD;
		for(uint32_t c1 = 0; c1 < N; c1++) {
		  uint32_t c2 = (c1 + dc) % MOD;
		  //						  printf("%2d %2d %2d\n", a1, b1, c1);
		  uint32_t d1 = a1 ^ b1 ^ c1;
		  uint32_t d2 = a2 ^ b2 ^ c2;
		  uint32_t dx = (d2 - d1 + MOD) % MOD;
		  assert((dx >= 0) && (dx < MOD));
		  if(dx == dd)
			 cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}

