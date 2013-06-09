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
 * \file  adp-xor-fi.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of XOR with one fixed input (FI): 
 *        \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}(a,db \rightarrow db)\f$.
 * \see adp-xor.cc
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif

/**
 * Allocate memory for the transition probability matrices for 
 * \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$.
 * \see adp_xor_fixed_input_free_matrices
 */
void adp_xor_fixed_input_alloc_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_FI_NMATRIX; i++){
	 int t = i;
	 int a = t & 1;
	 t /= 2;
	 int b = t & 1;
	 t /= 2;
	 int c = t & 1;
	 t /= 2;
	 //			 printf("%d%d%d \n", c, b, a);
	 A[a][b][c] = gsl_matrix_calloc(ADP_XOR_FI_MSIZE, ADP_XOR_FI_MSIZE);
  }

}

/**
 * Free memory reserved by a previous call to adp_xor_fixed_input_alloc_matrices.
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$.
 */
void adp_xor_fixed_input_free_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_FI_NMATRIX; i++){
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
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$.
 */
void adp_xor_fixed_input_normalize_matrices(gsl_matrix* A[2][2][2])
{
  for(int i = 0; i < ADP_XOR_FI_NMATRIX; i++){
	 int a = (i >> 0) & 1;
	 int b = (i >> 1) & 1;
	 int c = (i >> 2) & 1;

	 for(int row = 0; row < ADP_XOR_FI_MSIZE; row++){
		for(int col = 0; col < ADP_XOR_FI_MSIZE; col++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  gsl_matrix_set(A[a][b][c], row, col, ADP_XOR_FI_NORM * e);
		}
	 }
	 // check col sum
#if 1
	 for(int col = 0; col < ADP_XOR_FI_MSIZE; col++){
		double col_sum = 0;
		for(int row = 0; row < ADP_XOR_FI_MSIZE; row++){
		  double e = gsl_matrix_get(A[a][b][c], row, col);
		  col_sum += e;
		}
		assert((col_sum == 0.0) || (col_sum == 1.0));
	 }
#endif
  }
}

/** 
 * S-function for \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$:
 * \f$\mathrm{adp}^{\oplus}(a,db \rightarrow db)\f$.
 *
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A.
 *
 * A[2][2][2] = A[a[i]][db[i]][dc[i]], where 
 * 
 *   - a[i] : the i-th bit of the fixed input.
 *   - db[i] : the i-th bit of the input difference.
 *   - dc[i] : the i-th bit of the output difference.
 */
void adp_xor_fixed_input_sf(gsl_matrix* A[2][2][2])
{
  // number of possible input differences
  uint32_t ndiffs = (1UL << ADP_XOR_FI_NINPUTS);
  assert(ndiffs == 4);
  uint32_t nstates = ADP_XOR_FI_MSIZE;

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t a = (i >> 0) & 1; // value, not difference!
	 uint32_t db = (i >> 1) & 1;  
	 //			 printf("%d%d\n", db, a);

	 for(int32_t u = 0; u < (int)nstates; u++) {
		int32_t t = u;
		int32_t in_s1 = t & 1;
		t /= 2;
		int32_t in_s2 = (t & 1) - 1;
		t /= 2;
		//					printf("[%2d] %2d%2d \n", u, in_s2, in_s1);

		for(uint32_t j = 0; j < 2; j++) {
		  uint32_t b1 = j;
		  uint32_t b2 = b1 ^ db ^ in_s1;
		  int32_t out_s1 = (b1 + db + in_s1) >> 1;

		  // xor with three inputs
		  uint32_t c1 = a ^ b1;
		  uint32_t c2 = a ^ b2;
		  uint32_t dc = (c2 - c1 + in_s2) & 1;
		  int32_t out_s2 = (int32_t)(c2 - c1 + in_s2) >> 1; // signed shift i.e. -1 >> 1 == -1
		  assert((dc == 0) || (dc == 1));
		  assert((c2 - c1 + in_s2) == ((out_s2 * 2) + dc));

		  // checks
		  assert((out_s1 == 0) || (out_s1 == 1));
		  assert((out_s2 == 0) || (out_s2 == -1));

		  uint32_t v = 0;

		  // compose the output state
		  v = out_s2 + 1;
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
		  uint32_t e = gsl_matrix_get(A[a][db][dc], row, col);
		  e = e + 1;
		  gsl_matrix_set(A[a][db][dc], row, col, e);

		} // vals
	 }		  // states
  }			  // diffs
}

/**
 * The additive differential probability (ADP) of 
 * \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$. \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$
 *        computed with \ref adp_xor_fixed_input_sf.
 * \param a input value.
 * \param db input difference.
 * \param dc output difference.
 * \returns \f$\mathrm{adp}^{\oplus}(a,db \rightarrow db)\f$.
 */
double adp_xor_fixed_input(gsl_matrix* A[2][2][2], uint32_t a, uint32_t db, uint32_t dc)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_XOR_FI_MSIZE);
  C = gsl_vector_calloc(ADP_XOR_FI_MSIZE);

  // init C
  gsl_vector_set(C, ADP_XOR_FI_ISTATE, 1.0);
  // init L
  for(int i = 0; i < ADP_XOR_FI_MSIZE; i++)
	 gsl_vector_set(L, i, 1.0);

  R = gsl_vector_calloc(ADP_XOR_FI_MSIZE);

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (a >> pos) & 1;
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
  for(int i = 0; i < ADP_XOR_FI_MSIZE; i++) {
	 double e = gsl_vector_get(C, i);
	 printf("%f ", e);
  }
  printf("\n");
  printf("L  ");
  for(int i = 0; i < ADP_XOR_FI_MSIZE; i++) {
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
  printf("%8X %8X %8X -> %8X : %f", a, db, dc, p);
#endif

  return p;
}

/**
 * The additive differential probability (ADP) of 
 * \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$ computed 
 * experimentally over all inputs. Complexity: \f$O(2^{n})\f$.
 * 
 * \param a input value.
 * \param db input difference.
 * \param dc output difference.
 * \returns \f$\mathrm{adp}^{\oplus}(a,db \rightarrow db)\f$.
 * \see adp_xor_fixed_input
 */
double adp_xor_fixed_input_exper(const uint32_t a, const uint32_t db, const uint32_t dc)
{
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N;				  // all input pairs

  for(uint32_t b1 = 0; b1 < N; b1++) {
	 uint32_t b2 = (b1 + db) % MOD;
	 //						  printf("%2d %2d %2d\n", a1, b1);
	 uint32_t c1 = a ^ b1;
	 uint32_t c2 = a ^ b2;
	 uint32_t dx = (c2 - c1 + MOD) % MOD;
	 assert((dx >= 0) && (dx < MOD));
	 if(dx == dc)
		cnt++;
  }
  double p = (double)cnt / (double)all;
  return p;
}
