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
 * \file  adp-tea-f-fk-noshift.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-tea-f-fk-noshift.cc: \copybrief adp-tea-f-fk-noshift.cc.
 */ 
#ifndef ADP_TEA_F_FK_NOSHIFT_H
#define ADP_TEA_F_FK_NOSHIFT_H

#ifndef ADP_F_OP_NOSHIFT_NINPUTS
#define ADP_F_OP_NOSHIFT_NINPUTS 4	 /**< Number of inputs to F': \f$k_0,k_1,\delta,da\f$. */
#endif
#ifndef ADP_F_OP_NOSHIFT_MSIZE
#define ADP_F_OP_NOSHIFT_MSIZE (1L << 7) /**< Number of states of the S-function for F'. */
#endif
#ifndef ADP_F_OP_NOSHIFT_NMATRIX
#define ADP_F_OP_NOSHIFT_NMATRIX 32	/**< Number of transition probability matrices for F'. */
#endif
#ifndef ADP_F_OP_NOSHIFT_COLSUM
#define ADP_F_OP_NOSHIFT_COLSUM 2 /**< Sum of the non-zero elements in one column of the F' matrices. */
#endif
#ifndef ADP_F_OP_NOSHIFT_NORM
#define ADP_F_OP_NOSHIFT_NORM 1.0 /(double)ADP_F_OP_NOSHIFT_COLSUM /**< Normalization factor for transforming the elements of the matrices into probabilities. */
#endif
#ifndef ADP_F_OP_NOSHIFT_ISTATE
#define ADP_F_OP_NOSHIFT_ISTATE 64 /**< Initial state for start of the compuation of the ADP of F'. */
#endif
#ifndef NSPOS
#define NSPOS 1  /**< Number of special positions for ADP of F'. */
#endif

void adp_f_op_noshift_sf(gsl_matrix* A[NSPOS][2][2][2][2][2]);

void adp_f_op_noshift_alloc_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2]);

void adp_f_op_noshift_free_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2]);

void adp_f_op_noshift_normalize_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2]);

void adp_f_op_noshift_print_matrices(gsl_matrix* A[NSPOS][2][2][2][2][2]);

double adp_f_op_noshift(gsl_matrix* A[NSPOS][2][2][2][2][2], 
								uint32_t k0, uint32_t k1, uint32_t delta, uint32_t da, uint32_t db);

double adp_f_op_noshift_exper(uint32_t k0, uint32_t k1, uint32_t delta,
										uint32_t da, uint32_t db);

#endif  // #ifndef ADP_TEA_F_FK_NOSHIFT_H
