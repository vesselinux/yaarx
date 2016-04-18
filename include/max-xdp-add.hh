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
 * \file  max-xdp-add.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for max-xdp-add.cc. \copybrief max-xdp-add.cc.
 */ 
#ifndef MAX_XDP_ADD_H
#define MAX_XDP_ADD_H

void max_xdp_add_i(const int i, const uint32_t k, const uint32_t n, double* p, WORD_T* dd,
						 gsl_matrix* A[2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,  
						 const WORD_T da, const WORD_T db, WORD_T* dd_max, 
						 double* p_max, uint32_t A_size);

void max_xdp_add_bounds(gsl_matrix* A[2][2][2], gsl_vector* B[WORD_SIZE + 1],
								const WORD_T da, const WORD_T db, 
								WORD_T* dd_max, uint32_t A_size);

double max_xdp_add(gsl_matrix* A[2][2][2],
						 const WORD_T da, const WORD_T db,
						 WORD_T* dd_max);

double max_xdp_add_exper(gsl_matrix* A[2][2][2], 
								 const WORD_T da, const WORD_T db, 
								 WORD_T* dc_max);

double max_xdp_add_lm(WORD_T da, WORD_T db, WORD_T* dc_ret);

#endif  // #ifndef MAX_XDP_ADD_H
