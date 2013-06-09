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
 * \file  max-adp-arx.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for max-adp-arx.cc: \copybrief max-adp-arx.cc.
 */ 
#ifndef MAX_ADP_ARX_H
#define MAX_ADP_ARX_H

void max_adp_arx_bounds_0(uint32_t k, const uint32_t n, const uint32_t lrot_const,
								  double* p, uint32_t* de,
								  gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1], gsl_vector* C[ADP_ARX_NISTATES],
								  const uint32_t dc, const uint32_t dd, uint32_t* de_max, double* p_max);

void max_adp_arx_bounds_i(uint32_t k, const uint32_t n, const uint32_t lrot_const,
								  double* p, uint32_t* de,
								  gsl_matrix* A[2][2][2][2], gsl_vector* B[WORD_SIZE + 1], gsl_vector* C,
								  const uint32_t dc, const uint32_t dd, uint32_t* de_max, double* p_max);

void max_adp_arx_bounds(gsl_matrix* A[2][2][2][2], gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1],
								const uint32_t lrot_const, 
								const uint32_t dc, const uint32_t dd, uint32_t* de_max);

double max_adp_arx(gsl_matrix* A[2][2][2][2], const uint32_t lrot_const, 
						 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max);


void max_adp_arx_print_bounds(gsl_vector* B[ADP_ARX_NISTATES][WORD_SIZE + 1]);


double max_adp_arx_exper(gsl_matrix* A[2][2][2][2], const uint32_t lrot_const, 
								 const uint32_t da, const uint32_t db, const uint32_t dd, uint32_t* de_max);

#endif  // #ifndef MAX_ADP_ARX_H
