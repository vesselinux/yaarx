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
 * \file  adp-tea-f-fk-noshift.cc
 * \brief The additive differential probability (ADP) of a modified version of 
 *        the F-function of TEA with the shift operations removed. Complexity \f$O(n)\f$.
 *
 * The F-function of TEA with the shift operations removed is denoted by F' and is defined as:
 *  \f$y = F'(k_0, k_1, \delta |~ x) = (x + k_0) \oplus (x + \delta) \oplus (x + k_1)\f$.
 *
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_NOSHIFT_H
#include "adp-tea-f-fk-noshift.hh"
#endif

/** 
 * S-function for a modified version of the TEA F-function with the shift operations
 * removed, denoted by F' and defined as:
 * 
 *  \f$y = F'(k_0, k_1, \delta |~ x) = (x + k_0) \oplus (x + \delta) \oplus (x + k_1)\f$.
 * 
 * \param A zero-initialized set of matrices.
 * \returns Transition probability matrices A for \f$F'\f$.
 *
 * \f$A[j][2][2][2][2][2] = A[j][k0[i]][k1[i]][\delta[i]][da[i]][db[i]]\f$, where 
 * 
 *   - \f$j\f$   : dummy variable for future use.
 *   - \f$k_0[i]\f$ : the i-th bit of the first round key. 
 *   - \f$k_1[i]\f$ : the i-th bit of the second round key. 
 *   - \f$\delta[i]\f$ : the i-th bit of the round constant:
 *   - \f$da[i]\f$ : the i-th bit of the input difference.
 *   - \f$db[i]\f$ : the i-th bit of the output difference.
 */
void adp_f_op_noshift_sf(gsl_matrix* A[NSPOS][2][2][2][2][2])
{
  uint32_t ninputs = (1UL << ADP_F_OP_NOSHIFT_NINPUTS); // k0, k1, delta, da
  uint32_t nstates = ADP_F_OP_NOSHIFT_MSIZE;				// 2^|{s1, s2, ..., s7}|
  uint32_t nvalues = 2;									// a1
  uint32_t i_spos = 0;									// index of special position
  assert(nstates == 128);
  assert(NSPOS == 1);

  for(uint32_t i = 0; i < ninputs; i++) {
	 uint32_t k0    = (i >> 0) & 1;
	 uint32_t k1    = (i >> 1) & 1;
	 uint32_t delta = (i >> 2) & 1;
	 uint32_t da    = (i >> 3) & 1;

	 for(int32_t u = 0; u < (int)nstates; u++) {
		int32_t t = u;
		int32_t in_s1 = t & 1;
		t /= 2;
		int32_t in_s2 = t & 1;
		t /= 2;
		int32_t in_s3 = t & 1;
		t /= 2;
		int32_t in_s4 = t & 1;
		t /= 2;
		int32_t in_s5 = t & 1;
		t /= 2;
		int32_t in_s6 = t & 1;
		t /= 2;
		int32_t in_s7 = (t & 1) - 1;
		t /= 2;
#if 0									  // DEBUG
		printf(" IN = [%3d] %2d%2d%2d%2d%2d%2d%2d \n", u, in_s7, in_s6, in_s5, in_s4, in_s3, in_s2, in_s1);
#endif
		assert(nvalues == 2);
		for(uint32_t j = 0; j < nvalues; j++) {
		  uint32_t a1 = j;

		  uint32_t x1 = a1 ^ k0 ^ in_s1;
		  int32_t out_s1 = (a1 + k0 + in_s1) >> 1;

		  uint32_t y1 = a1 ^ k1 ^ in_s2;
		  int32_t out_s2 = (a1 + k1 + in_s2) >> 1;

		  uint32_t z1 = a1 ^ delta ^ in_s3;
		  int32_t out_s3 = (a1 + delta + in_s3) >> 1;

		  uint32_t x2 = x1 ^ da ^ in_s4;
		  int32_t out_s4 = (x1 + da + in_s4) >> 1;

		  uint32_t y2 = y1 ^ da ^ in_s5;
		  int32_t out_s5 = (y1 + da + in_s5) >> 1;

		  uint32_t z2 = z1 ^ da ^ in_s6;
		  int32_t out_s6 = (z1 + da + in_s6) >> 1;

		  // xor with three inputs
		  uint32_t b1 = x1 ^ y1 ^ z1;
		  uint32_t b2 = x2 ^ y2 ^ z2;

		  uint32_t db = (b2 - b1 + in_s7) & 1;
		  assert((db == 0) || (db == 1));

		  int32_t out_s7 = (int32_t)(b2 - b1 + in_s7) >> 1; // signed shift i.e. -1 >> 1 == -1
		  assert((b2 - b1 + in_s7) == ((out_s7 * 2) + db));

		  int32_t v = 0;

		  // compose the output state
		  v = out_s7 + 1;
		  v *= 2;
		  v += out_s6;
		  v *= 2;
		  v += out_s5;
		  v *= 2;
		  v += out_s4;
		  v *= 2;
		  v += out_s3;
		  v *= 2;
		  v += out_s2;
		  v *= 2;
		  v += out_s1;
#if 0									  // DEBUG
		printf("OUT = [%3d] %2d%2d%2d%2d%2d%2d%2d \n", v, out_s7, out_s6, out_s5, out_s4, out_s3, out_s2, out_s1);
#endif
#if 1									  // DEBUG
		if(u == v) {
		  bool b_test = 
			 (in_s1 == out_s1) && (in_s2 == out_s2) && (in_s3 == out_s3) && 
			 (in_s4 == out_s4) && (in_s5 == out_s5) && (in_s6 == out_s6) && 
			 (in_s7 == out_s7);
		  assert(b_test == true);
		}
#endif

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
		  uint32_t e = gsl_matrix_get(A[i_spos][k0][k1][delta][da][db], row, col);
		  e = e + 1;
		  gsl_matrix_set(A[i_spos][k0][k1][delta][da][db], row, col, e);
		}
	 }
  }
}

/**
 * Allocate memory for the transition probability matrices for \f$F'\f$.
 * \param A transition probability matrices for \f$F'\f$.
 * \see adp_rsh_xor_free_matrices
 */
void adp_f_op_noshift_alloc_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2])
{
  for(int i_spos = 0; i_spos < NSPOS; i_spos++){
	 for(int i = 0; i < ADP_F_OP_NOSHIFT_NMATRIX; i++){
		int t = i;
		int k0 = t & 1;
		t /= 2;
		int k1 = t & 1;
		t /= 2;
		int delta = t & 1;
		t /= 2;
		int da = t & 1;
		t /= 2;
		int db = t & 1;
		t /= 2;
		A[i_spos][k0][k1][delta][da][db] = gsl_matrix_calloc(ADP_F_OP_NOSHIFT_MSIZE, ADP_F_OP_NOSHIFT_MSIZE);
	 }
  }
}

/**
 * Free memory reserved by a previous call to adp_rsh_xor_free_matrices.
 * \param A transition probability matrices for \f$F'\f$.
 */
void adp_f_op_noshift_free_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2])
{
  for(int i_spos = 0; i_spos < NSPOS; i_spos++){
	 for(int i = 0; i < ADP_F_OP_NOSHIFT_NMATRIX; i++){
		int t = i;
		int k0 = t & 1;
		t /= 2;
		int k1 = t & 1;
		t /= 2;
		int delta = t & 1;
		t /= 2;
		int da = t & 1;
		t /= 2;
		int db = t & 1;
		t /= 2;
		gsl_matrix_free(A[i_spos][k0][k1][delta][da][db]);
	 }
  }
}

/**
 * Transform the elements of A into probabilities.
 * \param A transition probability matrices for \f$F'\f$.
 */
void adp_f_op_noshift_normalize_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2])
{
  for(int i_spos = 0; i_spos < NSPOS; i_spos++){
	 for(int i = 0; i < ADP_F_OP_NOSHIFT_NMATRIX; i++){
		int k0    = (i >> 0) & 1;
		int k1    = (i >> 1) & 1;
		int delta = (i >> 2) & 1;
		int da    = (i >> 3) & 1;
		int db    = (i >> 4) & 1;

		for(int row = 0; row < ADP_F_OP_NOSHIFT_MSIZE; row++){
		  for(int col = 0; col < ADP_F_OP_NOSHIFT_MSIZE; col++){
			 double e = gsl_matrix_get(A[i_spos][k0][k1][delta][da][db], row, col);
			 gsl_matrix_set(A[i_spos][k0][k1][delta][da][db], row, col, ADP_F_OP_NOSHIFT_NORM * e);
		  }
		}
		// check col sum
#if 0
		for(int col = 0; col < ADP_F_OP_NOSHIFT_MSIZE; col++){
		  double col_sum = 0;
		  for(int row = 0; row < ADP_F_OP_NOSHIFT_MSIZE; row++){
			 double e = gsl_matrix_get(A[i_spos][k0][k1][delta][da][db], row, col);
			 col_sum += e;
		  }
		  if(col_sum != 0)
			 printf("%f ", col_sum);
		  assert((col_sum == 0.0) || (col_sum == 1.0));
		}
#endif
	 }
  }
}

/**
 * Print the elements of A.
 * \param A transition probability matrices for \f$F'\f$.
 */
void adp_f_op_noshift_print_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2])
{
  for(int i_spos = 0; i_spos < NSPOS; i_spos++){
	 for(int i = 0; i < ADP_F_OP_NOSHIFT_NMATRIX; i++){
		int k0    = (i >> 0) & 1;
		int k1    = (i >> 1) & 1;
		int delta = (i >> 2) & 1;
		int da    = (i >> 3) & 1;
		int db    = (i >> 4) & 1;

		printf("A%d|%d%d%d%d%d \n", i_spos, k0, k1, delta, da, db);
		for(int row = 0; row < ADP_F_OP_NOSHIFT_MSIZE; row++){
		  for(int col = 0; col < ADP_F_OP_NOSHIFT_MSIZE; col++){
			 double e = gsl_matrix_get(A[i_spos][k0][k1][delta][da][db], row, col);
			 if(e == 0.0)
				printf(".");
			 else
				printf("%3.2f, ", e);
		  }
		  printf("\n");
		}
		printf("\n");
	 }
  }
}

/**
 * The additive differential probability (ADP) of a modified version of 
 * the F-function of TEA with the shift operations removed, denoted by F' and defined as:
 * 
 *  \f$y = F'(k_0, k_1, \delta |~ x) = (x + k_0) \oplus (x + \delta) \oplus (x + k_1)\f$.
 * 
 * \b Complexity: \f$O(n)\f$.
 * 
 * \param A transition probability matrices for \f$F'\f$ computed with \ref adp_f_op_noshift_sf
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param da input difference.
 * \param db output difference.
 * \returns \f$\mathrm{adp}^{F'}(k_0, k_1, \delta |~ da \rightarrow db)\f$.
 * 
 */
double adp_f_op_noshift(gsl_matrix* A[NSPOS][2][2][2][2][2], 
								uint32_t k0, uint32_t k1, uint32_t delta, uint32_t da, uint32_t db)
{
  double p = 1.0;
  gsl_vector* R;
  gsl_vector* L;
  gsl_vector* C;

  L = gsl_vector_calloc(ADP_F_OP_NOSHIFT_MSIZE);
  C = gsl_vector_calloc(ADP_F_OP_NOSHIFT_MSIZE);

  // init C
  gsl_vector_set(C, ADP_F_OP_NOSHIFT_ISTATE, 1.0);
  // init L
  gsl_vector_set_all(L, 1.0);

  R = gsl_vector_calloc(ADP_F_OP_NOSHIFT_MSIZE);

  int i_spos = 0;

  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 int i = (k0 >> pos) & 1;
	 int j = (k1 >> pos) & 1;
	 int k = (delta >> pos) & 1;
	 int l = (da >> pos) & 1;
	 int m = (db >> pos) & 1;

	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[i_spos][i][j][k][l][m], C, 0.0, R);
	 gsl_vector_memcpy(C, R);
  }
  gsl_blas_ddot(L, C, &p);

  gsl_vector_free(R);
  gsl_vector_free(C);
  gsl_vector_free(L);
  return p;
}

/**
 * The additive differential probability (ADP) of F' (a modified version of 
 * the F-function of TEA with the shift operations removed) computed 
 * experimentally over all inputs. Complexity: \f$O(2^{2n})\f$.
 * 
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param da input difference.
 * \param db output difference.
 * \returns \f$\mathrm{adp}^{F'}(k_0, k_1, \delta |~ da \rightarrow db)\f$.
 * \see adp_f_op_noshift
 */
double adp_f_op_noshift_exper(uint32_t k0, uint32_t k1, uint32_t delta,
										uint32_t da, uint32_t db)
{
  uint32_t lsh_const = 0;//TEA_LSH_CONST; 
  uint32_t rsh_const = 0;//TEA_RSH_CONST;

  uint32_t cnt_pairs = 0;
  for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {
	 uint32_t x2 = ADD(x1, da);
	 uint32_t y1 = tea_f(x1, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t y2 = tea_f(x2, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t y_sub = SUB(y2, y1);
	 if(y_sub == db) {
		cnt_pairs++;
	 }
  }
  double p = (double)cnt_pairs / (double)ALL_WORDS;
#if 0									  // DEBUG
  printf("%8X %8X %8X | %8X -> %8X     %f", k0, k1, delta, da, db, p);
  printf("\n");
#endif
  return p;
}
