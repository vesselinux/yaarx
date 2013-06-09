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
 * \file  max-adp-xor3.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The maximum ADD differential probability of XOR with three inputs:
 *        \f$\max_{dd}~\mathrm{adp}^{3\oplus}(da, db, dc \rightarrow dd)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif

/**
 *
 * Compute an upper bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential \f$(da[n-1:k], db[n-1:k], dc[n-1:k] \rightarrow dd[n-1:k])\f$
 * starting from initial state \p i of the S-function 
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(da[n-1:j], db[n-1:j], dc[n-1:j] \rightarrow dd[n-1:j])\f$ 
 * for \f$j = k+1, k+2, \ldots, n-1\f$.
 * 
 * \param i index of the state of the S-function: \p A_size \f$> i \ge 0\f$.
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the transition probability of state \p i at bit position \p k.
 * \param dd output difference.
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param C unit row vector of size \p A_size rows, initialized with 1 at state index \p i.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \see max_adp_xor_i
 */
void max_adp_xor3_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* dd,
						  gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,  
						  const uint32_t da, const uint32_t db, const uint32_t dc, uint32_t* dd_max, 
						  double* p_max)
{
  if(k == n) {
	 assert(*p > *p_max);
#if 0									  // DEBUG
	 printf("[%s:%d] B[%2d] update 2^%f -> 2^%f\n", __FILE__, __LINE__, i, log2(*p_max), log2(*p));
#endif
	 *p_max = *p;
	 *dd_max = *dd;
	 return;
  } 

  // get the k-th bit of da, db, dc
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;
  uint32_t z = (dc >> k) & 1;

  // cycle over the possible values of the k-th bits of *dd
  for(uint32_t t = 0; t < 2; t++) { 

	 // temp
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
	 gsl_blas_ddot(B[k + 1], R, &new_p);

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_dd = *dd | (t << k);
		max_adp_xor3_i(i, k+1, n, &new_p, &new_dd, A, B, R, da, db, dc, dd_max, p_max);
	 }
	 gsl_vector_free(R);

  }
  //  gsl_vector_free(L);
  return;
}

/**
 * Compute an array of bounds that can be used in the computation
 * of the maximum differential probability.
 *
 * \param A transition probability matrices.
 * \param B array of size \p A_size rows by (\p n + 1) columns containing upper bounds on the 
 *        maximum probabilities of all \p j bit differentials \f$n \ge j \ge 1\f$
 *        beginning from any state \p i: \p A_size \f$> i \ge 0\f$.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 *
 * \see max_adp_xor_bounds, max_adp_xor3_i
 */
void max_adp_xor3_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1],
								 const uint32_t da, const uint32_t db, const uint32_t dc,
								 uint32_t* dd_max)
{
  gsl_vector_set_all(B[WORD_SIZE], 1.0);

  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 for(uint32_t i = 0; i < ADP_XOR3_MSIZE; i++) {

		gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
		gsl_vector_set(C, i, 1.0);

		uint32_t n = WORD_SIZE;
		uint32_t dd_init = 0;
		double p_init = gsl_vector_get(B[k], i);
		double p_max_i = 0.0;
		max_adp_xor3_i(i, k, n, &p_init, &dd_init, A, B, C, da, db, dc, dd_max, &p_max_i);
		gsl_vector_set(B[k], i, p_max_i);

		gsl_vector_free(C);
	 }

  }
}

/**
 * Compute the maximum differential probability over all output differences:
 * \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}(da,db,dc \rightarrow dd)\f$.
 * \b Complexity c: \f$O(n) \le c \le O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 *
 * \see max_adp_xor3_bounds, max_adp_xor3_i
 */
double max_adp_xor3(gsl_matrix* A[2][2][2][2],
							const uint32_t da, const uint32_t db, const uint32_t dc,
							uint32_t* dd_max)
{
  gsl_vector* C = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set(C, ADP_XOR3_ISTATE, 1.0);

  gsl_vector* B[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B[i] = gsl_vector_calloc(ADP_XOR3_MSIZE);
  }

  max_adp_xor3_bounds(A, B, da, db, dc, dd_max);

  uint32_t n = WORD_SIZE;
  uint32_t dd_init = 0;
  uint32_t k = 0;
  uint32_t i = ADP_XOR3_ISTATE;
  double p_init = gsl_vector_get(B[k], i);
  double p_max = 0.0;
  max_adp_xor3_i(i, k, n, &p_init, &dd_init, A, B, C, da, db, dc, dd_max, &p_max);

#if 1									  // DEBUG
  double p_the = adp_xor3(A, da, db, dc, *dd_max);
#if 0
  printf("[%s:%d] ADP_XOR3_THE[(%8X,%8X,%8X)->%8X] = %f = 2^%f\n", 
			__FILE__, __LINE__, da, db, dc, *dd_max, p_the, log2(p_the));
#endif
  assert(p_max == p_the);
#endif

  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 gsl_vector_free(B[i]);
  }

  gsl_vector_free(C);

  return p_max;
}

/**
 * 
 * Recursively compute the maximum differential probability over all output differences
 * of the partial \f$(n-k)\f$-bit differential
 * \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}(da[n-1:k],db[n-1:k],dc[n-1:k] \rightarrow dd[n-1:k])\f$.
 * 
 * \param k current bit position: \f$ n > k \ge 0\f$.
 * \param n word size.
 * \param p the probability at bit position \p k.
 * \param dd output difference.
 * \param A transition probability matrices.
 * \param C unit row vector initialized with 1 at the nitial state.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 *
 * \b Algorithm \b Outline:
 *
 * The function recursively assigns the bits of the output difference
 * starting at the LS bit position \f$k = 0\f$ and proceeding to \f$k+1\f$ 
 * only if the probability so far is still above
 * the maximum that was found up to now. The initial value for the maximum 
 * probability \p p_max is 0 and is updated dynamically during the process
 * every time a higher probability is encountered. The recursion
 * stops at the MSB \f$k = n\f$.
 * 
 * See also: max_adp_xor3_rec()
 * 
 */
void max_adp_xor3_rec_i(const uint32_t k, const uint32_t n, double* p, uint32_t* dd,
								gsl_matrix* A[2][2][2][2], gsl_vector* C, 
								const uint32_t da, const uint32_t db, const uint32_t dc, uint32_t* dd_max, 
								double* p_max)
{
  if(k == n) {
	 double p_the = adp_xor3(A, da, db, dc, *dd);
#if 0									  // DEBUG
	 printf("[%s:%d] ADP_XOR3_THE[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, da, db, dc, *dd, p_the);
	 printf("[%s:%d] ADP_XOR3_REC[(%8X,%8X,%8X)->%8X] = %6.5f\n", 
			  __FILE__, __LINE__, da, db, dc, *dd, *p);
	 printf("%8X %8X %8X -> %8X : %f = 2^%4.2f\n", da, db, dc, *dd, *p, log2(*p));
#endif
	 assert(*p > *p_max);
	 assert(*p == p_the);
#if 0									  // DEBUG
	 printf("[%s:%d] Max update 2^%f -> 2^%f | *dd_max = %8X\n", __FILE__, __LINE__, log2(*p_max), log2(*p), *dd);
#endif
	 *p_max = *p;
	 *dd_max = *dd;
	 return;
  } else {
#if 0									  // DEBUG
	 printf("[%s:%d] k = %d\n", __FILE__, __LINE__, k);
#endif
  }

  // init L
  gsl_vector* L = gsl_vector_calloc(ADP_XOR3_MSIZE);
  gsl_vector_set_all(L, 1.0);

  // get the k-th bit of da, db, dc
  uint32_t x = (da >> k) & 1;
  uint32_t y = (db >> k) & 1;
  uint32_t z = (dc >> k) & 1;

  // cycle over the possible values of the k-th bits of *dd
  for(uint32_t t = 0; t < 2; t++) { 

	 // temp
	 gsl_vector* R = gsl_vector_calloc(ADP_XOR3_MSIZE);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][z][t], C, 0.0, R);
	 gsl_blas_ddot(L, R, &new_p);

	 // continue only if the probability so far is still bigger than the threshold 
	 if(new_p > *p_max) {
		uint32_t new_dd = *dd | (t << k);
		max_adp_xor3_rec_i(k+1, n, &new_p, &new_dd, A, R, da, db, dc, dd_max, p_max);
	 }
	 gsl_vector_free(R);

  }
  gsl_vector_free(L);
  return;
}

/**
 * 
 * Recursively compute the maximum differential probability over all output differences:
 * \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}(da,db,dc \rightarrow dd)\f$.
 * \b Complexity c: \f$O(n) \le c \le O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param C unit row vector initialized with 1 at the nitial state.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}(da,db,dc \rightarrow dd)\f$
 *
 * \note This function \ref max_adp_xor3_rec is more efficient than exhaustive search over all 
 *       output differences \ref max_adp_xor3_exper, but is less efficient
 *       than the function \ref max_adp_xor3 that uses bounds.
 *       The reason is that at every bit position, \ref max_adp_xor3_rec (by \ref max_adp_xor3_rec_i)
 *       implicitly assumes that the remaining probability until 
 *       the end (i.e. until the MSB) is 1, while the bounds computed by \ref max_adp_xor3
 *       are tighter and thus more branches of the recursion are cut
 *       earlier in the computation.
 * 
 * See also: max_adp_xor3_i()
 * 
 */
double max_adp_xor3_rec(gsl_matrix* A[2][2][2][2], gsl_vector* C, 
								const uint32_t da, const uint32_t db, const uint32_t dc,
								uint32_t* dd_max)
{
  uint32_t n = WORD_SIZE;
  uint32_t k = 0;
  double p_max = 0.0;
  double p_init = 0.0;
  uint32_t dd_init = 0;

  max_adp_xor3_rec_i(k, n, &p_init, &dd_init, A, C, da, db, dc, dd_max, &p_max);

#if 0									  // DEBUG
  printf("[%s:%d] p_max = %f, dd_max = %8X\n", __FILE__, __LINE__, p_max, *dd_max);
#endif
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
 * \param dc third input difference.
 * \param dd_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dd}~\mathrm{adp}^{\oplus}(da,db,dc \rightarrow dd)\f$
 *
 * \see max_adp_xor
 */
double max_adp_xor3_exper(gsl_matrix* A[2][2][2][2], 
								  const uint32_t da, const uint32_t db, const uint32_t dc,
								  uint32_t* dd_max)
{
  double p_max = 0.0;
  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
	 double p = adp_xor3(A, da, db, dc, dd);
	 if(p >= p_max) {
		p_max =p;
		*dd_max = dd;
	 }
  }
  return p_max;
}
