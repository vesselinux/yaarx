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
 * \file  adp-xor3.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-xor3.cc: \copybrief adp-xor3.cc.
 */ 
#ifndef ADP_XOR3_H
#define ADP_XOR3_H

#ifndef ADP_XOR3_MSIZE
#define ADP_XOR3_MSIZE 16 /**< Number of state values in the \f$\mathrm{adp}^{3\oplus}\f$ S-functions. */
#endif
#ifndef ADP_XOR3_NMATRIX
#define ADP_XOR3_NMATRIX 16 /**< Number of \f$\mathrm{adp}^{3\oplus}\f$ matrices. */
#endif
#ifndef ADP_XOR3_NINPUTS
#define ADP_XOR3_NINPUTS 3 /**< Number of inputs to the \f$3\oplus\f$ operation. */
#endif
#ifndef ADP_XOR3_ISTATE
#define ADP_XOR3_ISTATE 8 /**< Initial state for computing the \f$\mathrm{adp}^{3\oplus}\f$ S-function. */
#endif
#ifndef ADP_XOR3_COLSUM
#define ADP_XOR3_COLSUM 8 /**< Sum of non-zero elements in one column of the \f$3\oplus\f$ matrices. */
#endif
#ifndef ADP_XOR3_NORM
#define ADP_XOR3_NORM 1.0 /(double)ADP_XOR3_COLSUM /**< Normalization factor for the \f$\mathrm{adp}^{3\oplus}\f$ matrices. */
#endif

void adp_xor3_alloc_matrices(gsl_matrix* A[2][2][2][2]);

void adp_xor3_free_matrices(gsl_matrix* A[2][2][2][2]);

void adp_xor3_print_matrices(gsl_matrix* A[2][2][2][2]);

void adp_xor3_print_matrices_sage(gsl_matrix* A[2][2][2][2]);

void adp_xor3_normalize_matrices(gsl_matrix* A[2][2][2][2]);

int adp_xor3_states_to_index(int s1, int s2, int s3, int s4);

void adp_xor3_sf(gsl_matrix* A[2][2][2][2]);

double adp_xor3(gsl_matrix* A[2][2][2][2], uint32_t da, uint32_t db, uint32_t dc, uint32_t dd);

double adp_xor3_exper(const uint32_t da, const uint32_t db, const uint32_t dc, const uint32_t dd);

#endif  // #ifndef ADP_XOR3_H
