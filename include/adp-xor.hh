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
 * \file  adp-xor.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-xor.cc: \copybrief adp-xor.cc.
 */ 
#ifndef ADP_XOR_H
#define ADP_XOR_H

#ifndef ADP_XOR_MSIZE
#define ADP_XOR_MSIZE 8 /**< Number of state values in the \f$\mathrm{adp}^{\oplus}\f$ S-function. */
#endif
#ifndef ADP_XOR_NMATRIX
#define ADP_XOR_NMATRIX 8 /**< Number of \f$\mathrm{adp}^{\oplus}\f$ matrices. */
#endif
#ifndef ADP_XOR_NINPUTS
#define ADP_XOR_NINPUTS 2 /**< Number of inputs to the XOR operation. */
#endif
#ifndef ADP_XOR_ISTATE
#define ADP_XOR_ISTATE 4 /**< Initial state for computing the \f$\mathrm{adp}^{\oplus}\f$ S-function. */
#endif
#ifndef ADP_XOR_COLSUM
#define ADP_XOR_COLSUM 4 /**< Sum of non-zero elements in one column of the \f$\mathrm{adp}^{\oplus}\f$ matrices. */
#endif
#ifndef ADP_XOR_NORM
#define ADP_XOR_NORM 1.0 /(double)ADP_XOR_COLSUM /**< Normalization factor for the \f$\mathrm{adp}^{\oplus}\f$ matrices. */
#endif

void adp_xor_alloc_matrices(gsl_matrix* A[2][2][2]);

void adp_xor_free_matrices(gsl_matrix* A[2][2][2]);

void adp_xor_normalize_matrices(gsl_matrix* A[2][2][2]);

void adp_xor_print_matrices(gsl_matrix* A[2][2][2]);

void adp_xor_print_matrices_sage(gsl_matrix* A[2][2][2]);

void adp_xor_sf(gsl_matrix* A[2][2][2]);

double adp_xor(gsl_matrix* A[2][2][2], uint32_t da, uint32_t db, uint32_t dc);

double adp_xor_exper(const uint32_t da, const uint32_t db, const uint32_t dc);

#endif  // #ifndef ADP_XOR_H
