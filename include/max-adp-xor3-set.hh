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
 * \file  max-adp-xor3-set.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for max-adp-xor3-set.cc. \copybrief max-adp-xor3-set.cc.
 */ 
#ifndef MAX_ADP_XOR3_SET_H
#define MAX_ADP_XOR3_SET_H

#ifndef ADP_XOR3_SET_SIZE
#define ADP_XOR3_SET_SIZE 4 /**< Number of input differences in the set. */
#endif

void max_adp_xor3_set_i(const int i, const uint32_t k, const uint32_t n, double* p, uint32_t* dd,
								gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C[ADP_XOR3_SET_SIZE],  
								const uint32_t da, const uint32_t db, const uint32_t dc[ADP_XOR3_SET_SIZE], uint32_t* dd_max, 
								double* p_max);

double max_adp_xor3_set(gsl_matrix* A[2][2][2][2],
								const uint32_t da, const uint32_t db, 
								const uint32_t dc[ADP_XOR3_SET_SIZE], double p_dc[ADP_XOR3_SET_SIZE], 
								uint32_t* dd_max);

double max_adp_xor3_set_exper(gsl_matrix* A[2][2][2][2], 
										const uint32_t da, const uint32_t db, 
										const uint32_t dc[ADP_XOR3_SET_SIZE], double p_dc[ADP_XOR3_SET_SIZE], 
										uint32_t* dd_max);

#endif  // #ifndef MAX_ADP_XOR3_SET_H
