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
 * \file  max-adp-arx.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The maximum ADD differential probability of the 
 *        sequence of operations: \ref ADD, \ref LROT, \ref XOR (\ref ARX): 
 *        \f$\max_{de}~\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
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
 *
 * Compute the maximum probability output difference \f$de\f$ from \ref ARX:
 * \f$\max_{de}~\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$,
 * given upper bounds on the probabilities \f$B[s][k]\f$
 * for every initial state \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES and
 * every bit postion \f$k: 0 \le k <\f$\ref WORD_SIZE, computed
 * with \ref max_adp_arx_bounds .
 * 
 * \param k current bit position: \f$n \ge > k \ge 0\f$; initialized to 0.
 * \param n word size (\ref WORD_SIZE).
 * \param lrot_const \ref LROT constant.
 * \param p the estimated probability at bit position \f$k\f$.
 * \param de output difference.
 * \param A transition probability matrices (\ref adp_arx_sf).
 * \param B array of bounds for every initial state: \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES and
 *        every bit position \f$k: 0 \le k \le\f$\ref WORD_SIZE.
 * \param C a set of \ref ADP_ARX_NISTATES unit row vectors of size \ref ADP_ARX_MSIZE. Each one
 *        is initialized with 1 at one of the four initial states (\ref ADP_ARX_ISTATES).
 * \param dc input difference to the \ref LROT operation in \ref ARX.
 * \param dd input difference to the \ref XOR operation in \ref ARX.
 * \param de_max maximum probability output difference from \ref ARX (not used).
 * \param p_max the maximum probability.
 * \returns \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$
 *
 * \b Algorithm \b Outline:
 * 
 *  - Recursively assign values to the bits of the output difference \f$de\f$ 
 *    starting at bit popsition \f$j = 0\f$ and terminating at bit position \f$n=\f$\ref WORD_SIZE.
 *  - The recursion proceeds to bit postion \f$j + 1\f$ only if the sum of the  
 *    probabilities \f$p_j[s]\f$ of the partially constructed differential 
 *    \f$(dc[j:0], dd[j+r:r] \rightarrow de[j+r:r])\f$ computed starting from initial position \f$s\f$, 
 *    multiplied by the bound of the probability until the end \f$B[s][j+1]\f$, 
 *    is bigger than the best probability found so far i.e. if:
 *    \f$\sum_{s} (B[s][j+1]~ A_{j} A_{j-1} \ldots A_{0} C^{s}_{-1}) > p_{\mathrm{max}}\f$.
 *  - When \f$j = n\f$ update the maximum
 *    \f$p_{\mathrm{max}} \leftarrow p_{n-1} = \sum_{s} (L^{s}~ A_{n-1} A_{n-2} \ldots A_{0} C^{s}_{-1})\f$ 
 *    \f$ = \mathrm{dp}(dc[n-1:0],dd[n-1+r:r] \rightarrow de[n-1+r:r])\f$. Note that  
 *    \f$B[s][n]\f$ must be are initialized to \f$L^{s}\f$ by the caller, where
 *     \f$L^{0} = (1,1,0,0,0,0,0,0)\f$, \f$L^{1} = (0,0,1,1,0,0,0,0)\f$
 *     \f$L^{2} = (0,0,0,0,1,1,0,0)\f$, \f$L^{3} = (0,0,0,0,0,0,1,1)\f$.
 *  - At the end of the recursion \f$p_\mathrm{max} = \mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$, 
 *    since \f$\mathrm{dp}(dc,dd \rightarrow de) = \mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$,
 *    where \f$da + db = dc\f$.
 *  - Store \f$de\f$ and return \f$p_\mathrm{max}\f$.
 * 
 * \see max_adp_arx_bounds_i
 * 
 */
void max_adp_arx_bounds_0(uint32_t k, const uint32_t n, const uint32_t lrot_const,
								  double* p, uint32_t* de,
								  gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1], gsl_vector* C[ADP_ARX_NISTATES],
								  const uint32_t dc, const uint32_t dd, uint32_t* de_max, double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  uint32_t spos = 0;			  // special position
  uint32_t k_rot = ((k + lrot_const) % WORD_SIZE); // (i+r) mod n
  if(k_rot == 0) {
	 spos = 1;
  }

  // get the k-th bit of dc and the (k+r)-th bit of dd
  uint32_t x = (dc >> k) & 1;
  uint32_t y = (dd >> k_rot) & 1;

  // cycle over the possible values of the k-th bits of *de
  for(uint32_t z = 0; z < 2; z++) { 

	 double new_p = 0.0;

	 // temp
	 gsl_vector* R[ADP_ARX_NISTATES];
	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) {
		R[s] = gsl_vector_calloc(ADP_ARX_MSIZE);
	 }

	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // initial states
		// L A C
		double p_s = 0.0;
		gsl_blas_dgemv(CblasNoTrans, 1.0, A[spos][x][y][z], C[s], 0.0, R[s]);
		gsl_blas_ddot(B[s][k + 1], R[s], &p_s);
		new_p += p_s;
	 }

	 // continue only if the probability so far is still bigger than the best found so far
	 if(new_p > *p_max) {
		//		uint32_t new_de = *de | (z << k);
		uint32_t new_de = *de | (z << k_rot);
		max_adp_arx_bounds_0(k+1, n, lrot_const, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max);
	 }

	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) {
		gsl_vector_free(R[s]);
	 }

  } // z

}

/**
 *
 * For a fixed initial state \f$s\f$ and bit position \f$k\f$, 
 * compute an \em upper \em bound \f$B[s][k][i]\f$ on the probability 
 * of the differential \f$(dc[n-1:k], dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$
 * computed from initial state \f$i\f$ and terminating at final state \f$L^{s}\f$,
 * where \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES i.e.
 * compute a bound on the probability
 * \f$\mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r]) = 
 * L^{s} A_{n-1} A_{n-2} \ldots A_{k} C^{i}_{k-1}\f$, given the upper bounds 
 * \f$B[s][k]\f$ on the probabilities of the differentials
 * \f$(dc[n-1:j], dd[n-1+r:j+r] \rightarrow de[n-1+r:j+r])\f$ for \f$j = k+1, k+2, \ldots, n-1\f$,
 * where \f$L^{0} = (1,1,0,0,0,0,0,0)\f$, \f$L^{1} = (0,0,1,1,0,0,0,0)\f$
 * \f$L^{2} = (0,0,0,0,1,1,0,0)\f$, \f$L^{3} = (0,0,0,0,0,0,1,1)\f$ and 
 * \f$C^{i}_{k-1}\f$ is a column unit vector of size \ref ADP_ARX_MSIZE 
 * with 1 at position \f$i\f$, 
 * 
 * \param k current bit position: \f$n \ge > k \ge 0\f$.
 * \param n word size (\ref WORD_SIZE).
 * \param lrot_const \ref LROT constant.
 * \param p the estimated probability at bit position \f$k\f$.
 * \param de output difference.

 * \param A transition probability matrices.
 * \param B array of bounds for a fixed initial state \f$s\f$, set by the caller and
 *        every bit position \f$k: 0 \le k \le\f$\ref WORD_SIZE.
 * \param C unit row vector of size \ref ADP_ARX_MSIZE, initialized with 1 at state index \f$i\f$.
 * \param dc input difference to the \ref LROT operation in \ref ARX.
 * \param dd input difference to the \ref XOR operation in \ref ARX.
 * \param de_max maximum probability output difference from \ref ARX (not used).
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Outline:
 * 
 *  - Recursively assign values to the bits of the output difference \f$de\f$ 
 *    starting at bit popsition \f$j = k\f$ and terminating at bit position \f$n=\f$\ref WORD_SIZE.
 *  - The recursion proceeds to bit postion \f$j + 1\f$ only if the 
 *    probability \f$p_j\f$ of the partially constructed differential 
 *    \f$(dc[j:k], dd[j+r:k+r] \rightarrow de[j+r:k+r])\f$ multiplied by 
 *    the bound of the probability until the end \f$B[s][j+1]\f$, where \f$r=\mathrm{lrot\_const}\f$, 
 *    is bigger than the best probability found so far i.e. if:
 *    \f$B[s][j+1] A_{j} A_{j-1} \ldots A_{k} C^{i}_{k-1} > p_{\mathrm{max}}\f$.
 *  - When \f$j = n\f$ update the maximum
 *    \f$p_{\mathrm{max}} \leftarrow p_{n-1} = \mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$.
 *  - Store \f$p_max\f$ and return.
 * 
 * \see max_adp_arx_bounds
 */
void max_adp_arx_bounds_i(uint32_t k, const uint32_t n, const uint32_t lrot_const,
								  double* p, uint32_t* de,
								  gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,
								  const uint32_t dc, const uint32_t dd, uint32_t* de_max, double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
	 *p_max = *p;
	 *de_max = *de;
	 return;
  } 

  uint32_t spos = 0;			  // special position
  uint32_t k_rot = ((k + lrot_const) % WORD_SIZE); // (i+r) mod n
  if(k_rot == 0) {
	 spos = 1;
  }

  // get the k-th bit of dc and the (k+r)-th bit of dd
  uint32_t x = (dc >> k) & 1;
  uint32_t y = (dd >> k_rot) & 1;

  // cycle over the possible values of the k-th bits of *de
  for(uint32_t z = 0; z < 2; z++) { 

	 // temp
	 gsl_vector* R = gsl_vector_calloc(ADP_ARX_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[spos][x][y][z], C, 0.0, R);
	 gsl_blas_ddot(B[k + 1], R, &new_p);

	 // continue only if the probability so far is still bigger than the best found so far
	 if(new_p > *p_max) {
		//		uint32_t new_de = *de | (z << k);
		uint32_t new_de = *de | (z << k_rot);
		max_adp_arx_bounds_i(k+1, n, lrot_const, &new_p, &new_de, A, B, R, dc, dd, de_max, p_max);
	 }
	 gsl_vector_free(R);

  }

}

/**
 * Compute an array of bounds to be used in the computation
 * of the maximum differential probability.
 *
 * \param A transition probability matrices.
 * \param B array of bounds for every initial state: \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES and
 *        every bit position \f$k: 0 \le k \le\f$\ref WORD_SIZE.
 * \param lrot_const \ref LROT constant.
 * \param dc input difference to the \ref LROT operation in \ref ARX.
 * \param dd input difference to the \ref XOR operation in \ref ARX.
 * \param de_max maximum probability output difference from \ref ARX (not used).
 *
 * \b Algorithm \b Outline:
 * 
 *   - For each initial state \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES, \f$n =\f$\ref WORD_SIZE, initialize
 *     \f$B[s][n]\f$ to the corresponding final states (see \ref ADP_ARX_FSTATES): \f$B[s][n] = L^{s}\f$, where
 *     \f$L^{0} = (1,1,0,0,0,0,0,0)\f$, \f$L^{1} = (0,0,1,1,0,0,0,0)\f$
 *     \f$L^{2} = (0,0,0,0,1,1,0,0)\f$, \f$L^{3} = (0,0,0,0,0,0,1,1)\f$ (performed by the caller).
 *   - For every bit position k from (\ref WORD_SIZE - 1) down to 0
 *      - For every initial state \f$s\f$ from 0 to (\ref ADP_ARX_NISTATES - 1):
 *         - For every state \f$i\f$ from 0 to (\ref ADP_ARX_MSIZE - 1):
 *            - Initialize \f$B[s][k][i] \leftarrow p_{\mathrm{max}} = 0\f$    
 *            - Let \f$C^{i}_{k-1}\f$ be a column unit vector of 
 *              size \ref ADP_ARX_MSIZE with 1 at position \f$i\f$.
 *            - Recursively assign values to the bits of the output difference \f$de\f$ 
 *              starting at bit popsition \f$j = k\f$ and terminating at bit position \f$n=\f$\ref WORD_SIZE.
 *            - The recursion proceeds to bit postion \f$j + 1\f$ only if the 
 *              probability \f$p_j\f$ of the partially constructed differential 
 *              \f$(dc[j:k], dd[j+r:k+r] \rightarrow de[j+r:k+r])\f$ multiplied by 
 *              the bound of the probability until the end \f$B[s][j+1]\f$, where \f$r=\mathrm{lrot\_const}\f$, 
 *              is bigger than the best probability found so far i.e. if:
 *              \f$B[s][j+1] A_{j} A_{j-1} \ldots A_{k} C^{i}_{k-1} > p_{\mathrm{max}}\f$.
 *              \note This step is performed by \ref max_adp_arx_bounds_i .
 *            - When \f$j = n\f$ update the maximum
 *              \f$p_{\mathrm{max}} \leftarrow p_{n-1} = \mathrm{dp}(dc[n-1:k],dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$.
 *            - At the end of the recursion set the maximum value for state \f$i\f$ and initial state \f$s\f$
 *              at bit position \f$k\f$: \f$B[s][k][i] \leftarrow p_{\mathrm{max}}\f$.
 *
 * \b Meaning \b of \b the \b bounds \b B:
 *
 * For any \f$i: 0 \le i <\f$\ref ADP_ARX_MSIZE, the probability \f$B[s][k][i]\f$ computed with the above algorithm 
 * is an \em upper \em bound on on the maximum probability 
 * of the differential \f$(dc[n-1:k], dd[n-1+r:k+r] \rightarrow de[n-1+r:k+r])\f$, computed from 
 * initial state \f$i\f$ and terminating at final state \f$L^{s}\f$.
 * In other words, for any choice of the following \f$(n-k)\f$ bits of de: \f$de[n-1+r:k+r]\f$, 
 * the probability \f$ L^{s} A_{n-1} A_{n-2} \ldots A_{k} C^{i}_{k-1}\f$ will never be bigger than \f$B[s][k][i]\f$.
 * Furthermore, let \f$G[s][k] = L^{s} A_{n-1} A_{n-2} \ldots A_{k}\f$ be the multiplication of the 
 * corresponding transition probability matrices for the following \f$(n-k)\f$ bits of de: \f$de[n-1+r:k+r]\f$
 * and let \f$H[s][k-1] = A_{k-1} A_{k-2} \ldots A_{0} C^i_{k-1}\f$ and \f$H[-1] = C^{2s}\f$. 
 * Then \f$\mathrm{dp}(dc,dd \rightarrow de) = \sum_{s}(G[s][k]~ H[s][k-1]) \le \sum_{s}(B[s][k]~ H[s][k-1])\f$.
 * Threfore \f$\sum_{s}(B[s][k]~ H[s][k-1])\f$ is an upper bound on the proability 
 * \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$.
 * Note that \f$\mathrm{dp}(dc,dd \rightarrow de) = \mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$,
 * where \f$da + db = dc\f$.
 *
 * \see max_adp_arx_bounds_i, max_adp_xor_bounds
 */
void max_adp_arx_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1],
								const uint32_t lrot_const, 
								const uint32_t dc, const uint32_t dd, uint32_t* de_max)
{
  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) { // bit postion

	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // initial state

		for(uint32_t i = 0; i < ADP_ARX_MSIZE; i++) { // state

		  gsl_vector* C = gsl_vector_calloc(ADP_ARX_MSIZE);
		  gsl_vector_set(C, i, 1.0);

		  uint32_t n = WORD_SIZE;
		  uint32_t de_init = 0;
		  double p_init = gsl_vector_get(B[s][k], i);
		  double p_max_i = 0.0;
		  max_adp_arx_bounds_i(k, n, lrot_const, &p_init, &de_init, A, B[s], C, dc, dd, de_max, &p_max_i);
		  gsl_vector_set(B[s][k], i, p_max_i);
#if 0									  // DEBUG
		  printf("[%s:%d] k %2d, s %2d, i %2d | %f\n", __FILE__, __LINE__, k, s, i, p_max_i);
#endif
		  gsl_vector_free(C);
		}
	 }
  }
}

/**
 * Print the array of bounds computed with \ref max_adp_arx_bounds .
 *
 * \param B array of bounds for every initial state: \f$s: 0 \le s <\f$\ref ADP_ARX_NISTATES and
 *        every bit position \f$k: 0 \le k \le\f$\ref WORD_SIZE.
 * 
 * \see max_adp_arx_bounds.
 * 
 */
void max_adp_arx_print_bounds(gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1])
{
  printf("[%s:%d]\n", __FILE__, __LINE__);
  for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // initial state
	 printf("[%s:%d] --- istate [%2d] ---\n", __FILE__, __LINE__, s);
	 for(uint32_t k = WORD_SIZE; k > 0; k--) { // bit postion
		printf("[%2d] ", k);
		for(uint32_t i = 0; i < ADP_ARX_MSIZE; i++) { // state
		  double p_i = gsl_vector_get(B[s][k], i);
		  printf("%f ", p_i);
		} // i
		printf("\n");
	 }	// k
	 printf("\n\n");
  } // s
}

/**
 *
 * Compute the maximum probability output difference \f$de\f$ from \ref ARX:
 * \f$\max_{de}~\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$ --
 * a wrapper function for \ref max_adp_arx+bounds_0 .
 * 
 * \param A transition probability matrices.
 * \param lrot_const the rotation constant of the \ref LROT operation in \ref ARX.
 * \param da first input difference (input to the \ref ADD in \ref ARX).
 * \param db second input difference (input to the \ref ADD in \ref ARX).
 * \param dd third input difference (input to the \ref XOR in \ref ARX).
 * \param de_max maximum probability output difference from \ref ARX (computed).
 * \returns \f$\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$
 *
 * \see max_adp_arx_bounds, max_adp_arx_bounds_i, max_adp_arx_bounds_0
 */
double max_adp_arx(gsl_matrix* A[2][2][2][2], const uint32_t lrot_const, 
						 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max)
{
  uint32_t dc = ADD(da, db);
  uint32_t de = 0;

  // alloc separate vector of bounds for each initial state
  gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // 4 initial states
		B[s][i] = gsl_vector_calloc(ADP_ARX_MSIZE);
	 }
  }

  // init the final states B[i][n] corresponding to each initial state
  for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // start state
	 for(uint32_t f = 0; f < ADP_ARX_NFSTATES; f++) { // final states
		uint32_t fstate = ADP_ARX_FSTATES[s][f];
		gsl_vector_set(B[s][WORD_SIZE], fstate, 1.0); // init B[n] to the final states
	 }
  }

  max_adp_arx_bounds(A, B, lrot_const, dc, dd, &de);

#if 0									  // DEBUG
  max_adp_arx_print_bounds(B);
#endif

  // alloc the four initial states C
  gsl_vector* C[ADP_ARX_NISTATES];
  for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) {
	 C[s] = gsl_vector_calloc(ADP_ARX_MSIZE);
  }

  // init the four initial states C[i], i = 0,1,2,3 and the 
  for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) {
	 gsl_vector_set_all(C[s], 0.0);
	 uint32_t istate = ADP_ARX_ISTATES[s];
	 gsl_vector_set(C[s], istate, 1.0);
  }

  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  double p_init = 0.0;
  uint32_t de_init = 0;
  double p_max = 0.0;

  max_adp_arx_bounds_0(k, n, lrot_const, &p_init, &de_init, A, B, C, dc, dd, de_max, &p_max);

  double p_the = adp_arx(A, lrot_const, da, db, dd, *de_max);
#if 0
  printf("[%s:%d] ADP_ARX_MAX[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, lrot_const, da, db, dd, *de_max, p_max);
  printf("[%s:%d] ADP_ARX_THE[(%2d|%8X,%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, lrot_const, da, db, dd, *de_max, p_the);
#endif
  assert(p_max == p_the);


  // free array of vectors for the initial states
  for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) {
	 gsl_vector_free(C[s]);
  }

  // free the vector of bounds for each initial state
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 for(uint32_t s = 0; s < ADP_ARX_NISTATES; s++) { // 4 initial states
		gsl_vector_free(B[s][i]);
	 }
  }

  return p_max;
}


/**
 * Compute the maximum differential probability 
 * by exhaustive search over all output differences. 
 * \b Complexity: \f$O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param lrot_const the rotation constant of the \ref LROT operation in \ref ARX.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd third input difference.
 * \param de_max maximum probability output difference.
 * \return \f$\max_{de}~\mathrm{adp}^{\mathrm{ARX}}(da,db,dd \rightarrow de)\f$
 *
 * \see max_adp_xor
 */
double max_adp_arx_exper(gsl_matrix* A[2][2][2][2], const uint32_t lrot_const, 
								 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max)
{
  double p_max = 0.0;
  for(uint32_t de = 0; de < ALL_WORDS; de++) {
	 double p = adp_arx(A, lrot_const, da, db, dd, de);
	 if(p >= p_max) {
		p_max = p;
		*de_max = de;
	 }
  }
  return p_max;
}
