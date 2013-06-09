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
 * \file  max-adp-xor3-set.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The maximum ADD differential probability of XOR with three inputs, where 
 *        one of the inputs satisfies a \em set of ADD differences: 
 *        \f$\max_{dd}~\mathrm{adp}^{\oplus}_{\mathrm{SET}}(da, db, \{{dc}_0, {dc}_1, \ldots\} \rightarrow dd)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef MAX_ADP_XOR3_H
#include "max-adp-xor3.hh"
#endif
#ifndef MAX_ADP_XOR3_SET_H
#include "max-adp-xor3-set.hh"
#endif


/**
 *
 * Compute an upper bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential  
 * \f$(da[n-1:k],db[n-1:k],\{dc_0[n-1:k],dc_1[n-1:k],\ldots\} \rightarrow dd[n-1:k])\f$,
 * starting from initial state \p i of the S-function and
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(da[n-1:j],db[n-1:j],\{dc_0[n-1:j],dc_1[n-1:j],\ldots\} \rightarrow dd[n-1:j])\f$ 
 * for \f$j = k+1, k+2, \ldots, n-1\f$, where
 * \f$\{dc_0[n-1:k],dc_1[n-1:k],\ldots\}\f$ is a finite set of input differences.
 * 
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the estimated probability at bit position \p k.
 * \param dd output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc set of input differences.
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Outline:
 *
 * The bound for the set of differences is computed as the sum of the bounds
 * of the differentials obtained from each of the elements of the set:
 * \f$B[k][i] = \sum_{r}~B_{r}[k][i]\f$, where
 * \f$B_{r}[k][i]\f$ is an upper bound on the maximum probability
 * of the differential corresponding to the r-th input difference \f$dc_{r}\f$ i.e.
 * \f$\mathrm{dp}(da[n-1:k],db[n-1:k],dc_r[n-1:k] \rightarrow dd[n-1:k])\f$
 * computed as in \ref max_adp_xor_i.
 * 
 * \see max_adp_xor3_set, max_adp_xor_i
 */
void max_adp_xor3_set_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* dd,
								gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C[ADP_XOR3_SET_SIZE],  
								const uint32_t da, const uint32_t db, const uint32_t dc[ADP_XOR3_SET_SIZE], uint32_t* dd_max, 
								double* p_max)
{
  if(k == n) {
	 assert(*p >= *p_max);
	 *p_max = *p;
	 *dd_max = *dd;
	 return;
  } 

  // get the k-th bit of da, db, dc
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;

  // cycle over the possible values of the k-th bits of *dd
  for(uint32_t t = 0; t < 2; t++) { // choose the k-th bit of dd

	 double new_p = 0.0;

	 gsl_vector* R[ADP_XOR3_SET_SIZE];
	 double p[ADP_XOR3_SET_SIZE];
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		R[j] = gsl_vector_calloc(ADP_XOR3_MSIZE);
		p[j] = 0.0;
	 }

	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) { 
		uint32_t z = (dc[j] >> k) & 1;
		// L A C
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C[j], 0.0, R[j]);
		gsl_blas_ddot(B[k + 1], R[j], &p[j]);

		new_p += p[j];
	 }

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_dd = *dd | (t << k);
		max_adp_xor3_set_i(i, k+1, n, &new_p, &new_dd, A, B, R, da, db, dc, dd_max, p_max);
	 }

	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		gsl_vector_free(R[j]);
	 }
  }
  //  gsl_vector_free(L);
  return;
}

/**
 *
 * Compute the maximum differential probability over all output differences
 * for a set of input differenecs:
 * \f$\max_{dd} \mathrm{adp}^{\oplus}_{\mathrm{SET}}(da, db, \{{dc}_0, {dc}_1, \ldots\} \rightarrow dd)\f$.
 * 
 * \b Complexity c: \f$O(n R) \le c \le O(2^{nR})\f$, where \f$R\f$ is the size of the set of input differences \f$dc_r\f$.
 * 
 * \param A transition probability matrices.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc set of input difference.
 * \param dd_max maximum probability output difference.
 * \param p_dc probabilities of the set of differentials corresponding to the
 *        set of differences (used for testing and debug only).
 * \return \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}_{\mathrm{SET}}(da, db, \{{dc}_0, {dc}_1, \ldots\} \rightarrow dd)\f$.
 *
 * \b Algorithm \b Outline:
 *
 * - Compute the bounds for each of the differences in the set 
 *   \em independently using \ref max_adp_xor_bounds i.e.
 *   compute \f$B_{r}[k]\f$ - the bounds ror the \f$R\f$ differentials:
 *   \f$\mathrm{dp}(da[n-1:k],db[n-1:k],dc_r[n-1:k] \rightarrow dd[n-1:k])\f$ 
 *   corresponding to the r-th input differences \f$dc_{r}\f$ in the set.
 * - Compute a single array of bounds \f$B_{\mathrm{max}}\f$ as the maximum of 
 *   the bounds \f$B_{r}[k]\f$ at every bit position \f$0 \le k \le n\f$
 *   for every S-function state \f$0 \le i < A_{\mathrm{size}}\f$:
 *   \f$B_{\mathrm{max}}[k][i] = \mathrm{max}_{r}~B[k][i],~ 0 \le k \le n,~ 0 \le i < A_{\mathrm{size}}\f$. 
 * - Call \ref max_adp_xor3_set_i with the array of bounds \f$B_{\mathrm{max}}[k][i]\f$
 *   to compute the final maximum probability
 *   \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}_{\mathrm{SET}}\f$.
 *
 * \see max_adp_xor3_set_i, max_adp_xor_bounds, max_adp_xor
 * 
 */
double max_adp_xor3_set(gsl_matrix* A[2][2][2][2],
								const uint32_t da, const uint32_t db, 
								const uint32_t dc[ADP_XOR3_SET_SIZE], double p_dc[ADP_XOR3_SET_SIZE], 
								uint32_t* dd_max)
{
#if 0									  // DEBUG
  printf("[%s:%d] ", __FILE__, __LINE__);
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 printf("%8X (%f) ", dc[j], p_dc[j]);
  }
  printf("\n");
#endif
  gsl_vector* C[ADP_XOR3_SET_SIZE];
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 C[j] = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 //		gsl_vector_set(C[j], ADP_XOR3_ISTATE, 1.0);
	 gsl_vector_set(C[j], ADP_XOR3_ISTATE, p_dc[j]);
  }

  gsl_vector* B_max[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B_max[i] = gsl_vector_calloc(ADP_XOR3_MSIZE);
  }

  gsl_vector* B[ADP_XOR3_SET_SIZE][WORD_SIZE + 1];
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
		B[j][i] = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 }
  }

  // compute the max bounds for every difference in the set
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 max_adp_xor3_bounds(A, B[j], da, db, dc[j], dd_max);
  }

  // compute the max of the max
  for(int k = 0; k < WORD_SIZE; k++) { // bit pos
	 for(int i = 0; i < ADP_XOR3_MSIZE; i++) { // state index
		double p_max = 0.0;
		for(int j = 0; j < ADP_XOR3_SET_SIZE; j++) { // index in the set
		  double p_j = gsl_vector_get(B[j][k], i);
		  p_max = std::max(p_j, p_max);
		}
		gsl_vector_set(B_max[k], i, p_max);
	 }
  }
  gsl_vector_set_all(B_max[WORD_SIZE], 1.0);

  uint32_t n = WORD_SIZE;
  uint32_t dd_init = 0;
  uint32_t k = 0;
  uint32_t i = ADP_XOR3_ISTATE;
  double p_init = gsl_vector_get(B_max[k], i);
  double p_max = 0.0;
  max_adp_xor3_set_i(i, k, n, &p_init, &dd_init, A, B_max, C, da, db, dc, dd_max, &p_max);

#if 0									  // DEBUG
  double p_the = 0.0;
  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 double p = adp_xor3(A, da, db, dc[j], *dd_max);
	 p_the += (p * p_dc[j]);
  }
  if(p_max != p_the) {
	 printf("[%s:%d] WARNING: p_the != p_max\n", __FILE__, __LINE__);
	 printf("p_the = %41.40f = 2^%f\n", p_the, log2(p_the));
	 printf("p_max = %41.40f = 2^%f\n", p_max, log2(p_max));
  }
  //  assert(p_max == p_the);
#endif

  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
		gsl_vector_free(B[j][i]);
	 }
  }
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 gsl_vector_free(B_max[i]);
  }

  for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
	 gsl_vector_free(C[j]);
  }

  return p_max;
}

/**
 * Compute the maximum differential probability 
 * by exhaustive search over all output differences. 
 * \b Complexity: \f$O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc set of input difference.
 * \param dd_max maximum probability output difference.
 * \param p_dc probabilities of the set of differentials corresponding to the
 *        set of differences; normally set to 1 (used for testing and debug only).
 * \return \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}_{\mathrm{SET}}(da, db, \{{dc}_0, {dc}_1, \ldots\} \rightarrow dd)\f$.
 *
 * \see max_adp_xor3_set
 */
double max_adp_xor3_set_exper(gsl_matrix* A[2][2][2][2], 
										const uint32_t da, const uint32_t db, 
										const uint32_t dc[ADP_XOR3_SET_SIZE], double p_dc[ADP_XOR3_SET_SIZE], 
										uint32_t* dd_max)
{
  double p_max = 0.0;
  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {

	 double p = 0.0;
	 for(uint32_t j = 0; j < ADP_XOR3_SET_SIZE; j++) {
		double p_j = adp_xor3(A, da, db, dc[j], dd);
		p += (p_j * p_dc[j]);
	 }

	 if(p >= p_max) {
		p_max =p;
		*dd_max = dd;
	 }
  }
  return p_max;
}
