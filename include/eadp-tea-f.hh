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
 * \file  eadp-tea-f.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for eadp-tea-f.cc. \copybrief eadp-tea-f.cc.
 */ 
#ifndef EADP_TEA_F_H
#define EADP_TEA_F_H

double eadp_tea_f(gsl_matrix* A[2][2][2][2], const uint32_t da, const uint32_t db, double* prob_db,
						uint32_t lsh_const, uint32_t rsh_const);

double eadp_tea_f_exper(const uint32_t dx, const uint32_t dy, uint32_t lsh_const, uint32_t rsh_const);

double max_eadp_tea_f(gsl_matrix* A[2][2][2][2], const uint32_t da, uint32_t* dd_max, double* prob_max,
							 uint32_t lsh_const, uint32_t rsh_const);

double max_eadp_tea_f_exper(gsl_matrix* A[2][2][2][2], const uint32_t da, uint32_t* dd_max, double* prob_max,
									 uint32_t lsh_const, uint32_t rsh_const);

void nz_eadp_tea_f_i(const uint32_t k, const uint32_t n, 
							gsl_matrix* A[2][2][2][2], gsl_vector* C, 
							const uint32_t da, const uint32_t db, const uint32_t dc, uint32_t* dd, 
							double* p, double* p_thres, uint32_t* ret_dd, double* ret_p, uint32_t* cnt, uint32_t max_cnt);

//double nz_eadp_tea_f(gsl_matrix* A[2][2][2][2], uint32_t da, uint32_t* ret_dd);
double nz_eadp_tea_f(gsl_matrix* A[2][2][2][2], double p_thres, uint32_t da, uint32_t* ret_dd);

#endif  // #ifndef EADP_TEA_F_H
