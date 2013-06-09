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
 * \file  adp-rsh-xor.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-rsh-xor.cc: \copybrief adp-rsh-xor.cc.
 */ 
#ifndef ADP_RSH_XOR_H
#define ADP_RSH_XOR_H

#ifndef ADP_RSH_XOR_NSTATES
#define ADP_RSH_XOR_NSTATES	3 /**< Number of states of the S-function for \f$\mathrm{adp}^{\gg\oplus}\f$. */
#endif
#ifndef ADP_RSH_XOR_NPOS
#define ADP_RSH_XOR_NPOS 3 /**< Special bit positions in the computation of \f$\mathrm{adp}^{\gg\oplus}\f$. */
#endif
#ifndef ADP_RSH_XOR_MSIZE
#define ADP_RSH_XOR_MSIZE (1L << ADP_RSH_XOR_NSTATES) /**< Size of the transition probability matrices for \f$\mathrm{adp}^{\gg\oplus}\f$. */
#endif
#ifndef ADP_RSH_XOR_NINPUTS
#define ADP_RSH_XOR_NINPUTS 2	/**< Number of inputs to the operation \f$(\gg\oplus)\f$.*/
#endif
#ifndef ADP_RSH_XOR_NOUTPUTS
#define ADP_RSH_XOR_NOUTPUTS 1 /**< Number of outputs from the operation \f$(\gg\oplus)\f$.*/
#endif
#ifndef ADP_RSH_XOR_COLSUM
#define ADP_RSH_XOR_COLSUM 4 /**< Sum of the non-zero elements in one column of the \f$\mathrm{adp}^{\gg\oplus}\f$ matrices. */
#endif
#ifndef ADP_RSH_XOR_NORM			  // two independent inputs
#define ADP_RSH_XOR_NORM 1.0 /(double)ADP_RSH_XOR_COLSUM /**< Normalization factor for transforming the elements of the matrices into probabilities. */
#endif

uint32_t rsh_xor(uint32_t a, uint32_t x, int r);

double adp_rsh_xor_exper(const uint32_t da, const uint32_t dx, const uint32_t db, const int r);

void adp_rsh_xor_alloc_matrices(gsl_matrix* A[3][2][2][2]);

void adp_rsh_xor_free_matrices(gsl_matrix* A[3][2][2][2]);

void adp_rsh_xor_normalize_matrices(gsl_matrix* A[3][2][2][2]);

void adp_rsh_xor_print_matrices(gsl_matrix* A[3][2][2][2]);

void adp_rsh_xor_sf(gsl_matrix* A[3][2][2][2]);

double adp_rsh_xor(gsl_matrix* A[3][2][2][2], uint32_t da, uint32_t dx, uint32_t db, int r);

double adp_rsh_xor_approx(uint32_t da, uint32_t dx, uint32_t db, int r);

#endif  // #ifndef ADP_RSH_XOR_H
