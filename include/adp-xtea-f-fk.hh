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
 * \file  adp-xtea-f-fk.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-xtea-f-fk.cc: \copybrief adp-xtea-f-fk.cc.
 */ 
#ifndef ADP_XTEA_F_FK_H
#define ADP_XTEA_F_FK_H

double adp_xtea_f_exper(const uint32_t da, const uint32_t db, 
							   const uint32_t k, const uint32_t delta, 
								const uint32_t lsh_const, const uint32_t rsh_const);


double adp_xtea_f_approx(const uint32_t ninputs, 
								 const uint32_t da, const uint32_t db, 
								 const uint32_t k, const uint32_t delta, 
								 const uint32_t lsh_const, const uint32_t rsh_const);

double max_dy_adp_xtea_f_exper(const uint32_t dx, uint32_t* dy_max, 
										 const uint32_t k, const uint32_t delta, 
										 const uint32_t lsh_const, const uint32_t rsh_const);

double max_dx_adp_xtea_f_exper(uint32_t *dx_max, const uint32_t dy, 
										 const uint32_t k, const uint32_t delta, 
										 const uint32_t lsh_const, const uint32_t rsh_const);

double adp_xtea_f_lxr_exper(const uint32_t da, const uint32_t db, uint32_t lsh_const, uint32_t rsh_const);

double adp_xtea_f_lxr_approx(const uint32_t ninputs, const uint32_t da, const uint32_t db, uint32_t lsh_const, uint32_t rsh_const);

bool adp_xtea_f_lxr_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t dx, const uint32_t dy, const uint32_t x);

bool adp_xtea_f_lxr_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
									const uint32_t dx, const uint32_t dy, int32_t x);

uint32_t adp_xtea_f_lxr_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
												 const uint32_t lsh_const, const uint32_t rsh_const,
												 const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob);

double adp_xtea_f_lxr(const uint32_t n, const uint32_t dx, const uint32_t dy, 
							 const uint32_t lsh_const, const uint32_t rsh_const);

double adp_xtea_f_approx(const uint32_t n, gsl_matrix* A[2][2][2],
								 const uint32_t dx, const uint32_t dy, 
								 const uint32_t k, const uint32_t delta, 
								 const uint32_t lsh_const, const uint32_t rsh_const);

bool adp_xtea_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
								const uint32_t k, const uint32_t delta,
								const uint32_t dx, const uint32_t dy, 
								const uint32_t x);

bool adp_xtea_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
							  const uint32_t k, const uint32_t delta,
							  const uint32_t dx, const uint32_t dy, const uint32_t x);

uint32_t adp_xtea_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
											const uint32_t x, const uint32_t key, const uint32_t  delta, 
											const uint32_t lsh_const, const uint32_t rsh_const, 
											const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob);

uint32_t adp_xtea_f_assign_bit_x_dx(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
												const uint32_t lsh_const, const uint32_t rsh_const,
												const uint32_t key, const uint32_t delta,
												const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
												double* ret_prob, uint32_t* ret_dx);

uint32_t adp_xtea_f_assign_bit_x_dy(const uint32_t n, const uint32_t i, const uint32_t mask_i, const uint32_t x, 
												const uint32_t lsh_const, const uint32_t rsh_const,
												const uint32_t key, const uint32_t delta,
												const uint32_t dx, const uint32_t dy, uint64_t* x_cnt, 
												double* ret_prob, uint32_t* ret_dy);

double adp_xtea_f(const uint32_t n, const uint32_t dx, const uint32_t dy, 
						const uint32_t key, const uint32_t  delta, 
						const uint32_t lsh_const, const uint32_t rsh_const);

double max_dy_adp_xtea_f(const uint32_t n, const uint32_t dx, uint32_t* ret_dy,
								 const uint32_t key, const uint32_t delta,
								 const uint32_t lsh_const, const uint32_t rsh_const);

double max_dx_adp_xtea_f(const uint32_t n, uint32_t* ret_dx, const uint32_t dy,
								 const uint32_t key, const uint32_t delta,
								 const uint32_t lsh_const, const uint32_t rsh_const);

double first_nz_adp_xtea_f(gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], 
									const uint32_t key, const uint32_t delta,
									const uint32_t da, uint32_t* ret_dd, 
									uint32_t lsh_const, uint32_t rsh_const);

#endif  // #ifndef ADP_XTEA_F_FK_H
