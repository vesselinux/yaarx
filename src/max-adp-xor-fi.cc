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
 * \file  max-adp-xor-fi.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The maximum ADD differential probability of XOR with one fixed input:
 *        \f$\max_{dc} \mathrm{adp}^{\oplus}_{\mathrm{FI}}(a, db \rightarrow dc)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef MAX_ADP_XOR_H
#include "max-adp-xor.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif

/**
 * Compute the maximum differential probability over all output differences:
 * \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}_{\mathrm{FI}}(da,db \rightarrow dc)\f$.
 * \b Complexity c: \f$O(n) \le c \le O(2^n)\f$.
 * 
 * \param A transition probability matrices.
 * \param a input value.
 * \param db input difference.
 * \param dd_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}_{\mathrm{FI}}(da,db \rightarrow dc)\f$.
 *
 * \see max_adp_xor_bounds, max_adp_xor_i
 */
double max_adp_xor_fixed_input(gsl_matrix* A[2][2][2],
										 const uint32_t a, const uint32_t db,
										 uint32_t* dd_max)
{
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_FI_MSIZE);
  gsl_vector_set(C, ADP_XOR_FI_ISTATE, 1.0);

  gsl_vector* B[WORD_SIZE + 1];
  for(uint32_t i = 0; i < WORD_SIZE + 1; i++) {
	 B[i] = gsl_vector_calloc(ADP_XOR_FI_MSIZE);
  }

  max_adp_xor_bounds(A, B, a, db, dd_max, ADP_XOR_FI_MSIZE);

  uint32_t n = WORD_SIZE;
  uint32_t dd_init = 0;
  uint32_t k = 0;
  uint32_t i = ADP_XOR_FI_ISTATE;
  double p_init = gsl_vector_get(B[k], i);
  double p_max = 0.0;
  max_adp_xor_i(i, k, n, &p_init, &dd_init, A, B, C, a, db, dd_max, &p_max, ADP_XOR_FI_MSIZE);

#if 1									  // DEBUG
  double p_the = adp_xor_fixed_input(A, a, db, *dd_max);
#if 0
  printf("[%s:%d] ADP_XOR_FI_THE[(%8X,%8X)->%8X] = %f = 2^%f\n", 
			__FILE__, __LINE__, a, db, *dd_max, p_the, log2(p_the));
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
 * \param da input value.
 * \param db input difference.
 * \param dc_max maximum probability output difference.
 * \return \f$\mathrm{max}_{dc}~\mathrm{adp}^{\oplus}_{\mathrm{FI}}(da,db \rightarrow dc)\f$.
 *
 * \see max_adp_xor_fixed_input
 */
double max_adp_xor_fixed_input_exper(gsl_matrix* A[2][2][2], 
												 const uint32_t da, const uint32_t db, 
												 uint32_t* dc_max)
{
  double p_max = 0.0;
  for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
	 double p = adp_xor_fixed_input(A, da, db, dc);
	 if(p >= p_max) {
		p_max =p;
		*dc_max = dc;
	 }
  }
  return p_max;
}
