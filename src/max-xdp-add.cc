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
 * \file  max-xdp-add.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief The maximum XOR differential probability of ADD: \f$\max_{dc} \mathrm{xdp}^{+}(da, db \rightarrow dc)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif

/**
 *
 * Compute an \em upper \em bound \f$B[k][i]\f$ on the maximum probability 
 * of the differential \f$(da[n-1:k], db[n-1:k] \rightarrow dc[n-1:k])\f$
 * starting from initial state \p i of the S-function i.e.
 * \f$\mathrm{dp}(da[n-1:k],db[n-1:k] \rightarrow dc[n-1:k]) = 
 * L A_{n-1} A_{n-2} \ldots A_{k} C^{i}_{k-1}\f$,
 * given the upper bounds \f$B[k][i]\f$ on the probabilities of the differentials
 * \f$(da[n-1:j], db[n-1:j] \rightarrow dc[n-1:j])\f$ for \f$j = k+1, k+2, \ldots, n-1\f$,
 * where \f$L = [1~1~\ldots~1]\f$ is a row vector of size \p A_size and \f$C^{i}_{k-1}\f$ 
 * is a unit column vector of size \p A_size with 1 at position \f$i\f$
 * and \f$C^{i}_{-1} = C\f$.
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
 * \param dd_max maximum probability output difference.
 * \param p_max the maximum probability.
 * \param A_size size of the square transition probability matrices
 *        (equivalently, the number of states of the S-function).
 *
 * \see max_adp_xor_i
 */
void max_xdp_add_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* dd,
						 gsl_matrix* A[2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,  
						 const uint32_t da, const uint32_t db, uint32_t* dd_max, 
						 double* p_max, uint32_t A_size)
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

  // cycle over the possible values of the k-th bits of *dd
  for(uint32_t t = 0; t < 2; t++) { 

	 // temp
	 //	 gsl_vector* R = gsl_vector_calloc(ADP_XOR_MSIZE);
	 gsl_vector* R = gsl_vector_calloc(A_size);
	 double new_p = 0.0;

	 // L A C
	 gsl_blas_dgemv(CblasNoTrans, 1.0, A[x][y][t], C, 0.0, R);
	 gsl_blas_ddot(B[k + 1], R, &new_p);

	 // continue only if the probability so far is still bigger than the prob. so far
	 if(new_p > *p_max) {
		uint32_t new_dd = *dd | (t << k);
		max_xdp_add_i(i, k+1, n, &new_p, &new_dd, A, B, R, da, db, dd_max, p_max, A_size);
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
 * \param dd_max maximum probability output difference.
 * \param A_size size of the square transition probability matrices
 *        (equivalently, the number of states of the S-function).
 *
 * \see max_xdp_add_i, max_adp_xor_bounds
 */
void max_xdp_add_bounds(gsl_matrix* A[2][2][2], gsl_vector* B[WORD_SIZE + 1],
								const uint32_t da, const uint32_t db, 
								uint32_t* dd_max, uint32_t A_size)
{
  gsl_vector_set_all(B[WORD_SIZE], 1.0);

  for(uint32_t k = (WORD_SIZE - 1); k > 0; k--) {

	 //	 for(uint32_t i = 0; i < ADP_XOR_MSIZE; i++) {
	 for(uint32_t i = 0; i < A_size; i++) {

		//		gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
		gsl_vector* C = gsl_vector_calloc(A_size);
		gsl_vector_set(C, i, 1.0);

		uint32_t n = WORD_SIZE;
		uint32_t dd_init = 0;
		double p_init = gsl_vector_get(B[k], i);
		double p_max_i = 0.0;
		max_xdp_add_i(i, k, n, &p_init, &dd_init, A, B, C, da, db, dd_max, &p_max_i, A_size);
		gsl_vector_set(B[k], i, p_max_i);

		gsl_vector_free(C);
	 }
  }
}

/**
 * Compute the maximum differential probability over all output differences:
 * \f$\mathrm{max}_{dc}~\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$.
 * \b Complexity c: \f$O(n) \le c \le O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param da first input difference.
 * \param db second input difference.
 * \param dd_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$.
 *
 * \see max_xdp_add, max_xdp_add_i, max_adp_xor
 */
double max_xdp_add(gsl_matrix* A[2][2][2],
						 const uint32_t da, const uint32_t db,
						 uint32_t* dd_max)
{
  gsl_vector* C = gsl_vector_calloc(XDP_ADD_MSIZE);
  gsl_vector_set(C, XDP_ADD_ISTATE, 1.0);

  gsl_vector* B[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B[i] = gsl_vector_calloc(XDP_ADD_MSIZE);
  }

  max_xdp_add_bounds(A, B, da, db, dd_max, XDP_ADD_MSIZE);

  uint32_t n = WORD_SIZE;
  uint32_t dd_init = 0;
  uint32_t k = 0;
  uint32_t i = XDP_ADD_ISTATE;
  double p_init = gsl_vector_get(B[k], i);
  double p_max = 0.0;
  max_xdp_add_i(i, k, n, &p_init, &dd_init, A, B, C, da, db, dd_max, &p_max, XDP_ADD_MSIZE);

#if 1									  // DEBUG
  double p_the = xdp_add(A, da, db, *dd_max);
#if 0
  printf("[%s:%d] XDP_ADD_THE[(%8X,%8X)->%8X] = %f = 2^%f\n", 
			__FILE__, __LINE__, da, db, *dd_max, p_the, log2(p_the));
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
 * Compute the maximum differential probability 
 * by exhaustive search over all output differences. 
 * \b Complexity: \f$O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param da first input difference.
 * \param db second input difference.
 * \param dc_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$.
 *
 * \see max_xdp_add
 */
double max_xdp_add_exper(gsl_matrix* A[2][2][2], 
								 const uint32_t da, const uint32_t db, 
								 uint32_t* dc_max)
{
  double p_max = 0.0;
  for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
	 double p = xdp_add(A, da, db, dc);
	 if(p >= p_max) {
		p_max =p;
		*dc_max = dc;
	 }
  }
  return p_max;
}


/**
 * The maximum differential probability over all output differences:
 * in linear time as proposed in [Lipmaa, Moriai, FSE 2001]:
 * \f$\mathrm{max}_{dc}~\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$.
 * \b Complexity c: \f$O(n)\f$.
 *
 * \param da first input difference.
 * \param db second input difference.
 * \param dc_ret maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$.
 *
 * \see max_xdp_add
 */
double max_xdp_add_lm(uint32_t da, uint32_t db, uint32_t* dc_ret)
{
  uint32_t n = WORD_SIZE;
  double p_max = 0.0;
  uint32_t dc = 0;

  dc |= (da & 1) ^ (db & 1);

  uint32_t C = cap(da, db);

  for(uint32_t i = 1; i < n; i++) {
	 uint32_t C_this = (C >> i) & 1;
	 uint32_t da_prev = (da >> (i - 1)) & 1;
	 uint32_t db_prev = (db >> (i - 1)) & 1;
	 uint32_t dc_prev = (dc >> (i - 1)) & 1;
	 uint32_t da_this = (da >> i) & 1;
	 uint32_t db_this = (db >> i) & 1;
	 uint32_t dc_this = 0;		  // to be determined
	 if(is_eq(da_prev, db_prev, dc_prev)) {
		dc_this = (da_this ^ db_this ^ da_prev);
	 } else {
		if((i == (n-1)) || (da_this != db_this) || (C_this == 1)) {
		  dc_this = 0;				  // can be 0/1
		} else {
		  dc_this = da_this;
		}
	 }
	 dc |= (dc_this << i);
  }
  *dc_ret = dc;
  p_max = xdp_add_lm(da, db, dc);

#if 0
  printf("\nda = ");
  print_binary(da);
  printf("\ndb = ");
  print_binary(db);
  printf("\ndc = ");
  print_binary(dc);
  printf("\n C = ");
  print_binary(C);
  printf("\n");
#endif

  return p_max;
}
