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
 * \file  xdp-xtea-f-fk.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-xtea-f-fk.cc. \copybrief xdp-xtea-f-fk.cc.
 */ 
#ifndef XDP_XTEA_F_FK_H
#define XDP_XTEA_F_FK_H

double xdp_xtea_f_fk_exper(const uint32_t da, const uint32_t db, 
									const uint32_t k, const uint32_t delta, 
									const uint32_t lsh_const, const uint32_t rsh_const);

double xdp_xtea_f_fk_approx(const uint32_t ninputs, 
									 const uint32_t da, const uint32_t db, 
									 const uint32_t k, const uint32_t delta, 
									 const uint32_t lsh_const, const uint32_t rsh_const);

bool xdp_xtea_f_check_x(const uint32_t lsh_const, const uint32_t rsh_const,
								const uint32_t k, const uint32_t delta,
								const uint32_t dx, const uint32_t dy, 
								const uint32_t x);

bool xdp_xtea_f_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
							  const uint32_t k, const uint32_t delta,
							  const uint32_t dx, const uint32_t dy, const uint32_t x);


uint32_t xdp_xtea_f_assign_bit_x(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
											const uint32_t x, const uint32_t key, const uint32_t  delta, 
											const uint32_t lsh_const, const uint32_t rsh_const, 
											const uint32_t dx, const uint32_t dy, uint32_t* x_cnt, double* prob);

double xdp_xtea_f_fk(const uint32_t n, const uint32_t dx, const uint32_t dy, 
							const uint32_t key, const uint32_t  delta, 
							const uint32_t lsh_const, const uint32_t rsh_const);

double xdp_xtea_f2_fk_exper(const uint32_t daa, const uint32_t da, const uint32_t db, 
									 const uint32_t k, const uint32_t delta, 
									 const uint32_t lsh_const, const uint32_t rsh_const);

double xdp_xtea_f2_fk_approx(const uint32_t ninputs, 
									  const uint32_t daa, const uint32_t da, const uint32_t db, 
									  const uint32_t k, const uint32_t delta, 
									  const uint32_t lsh_const, const uint32_t rsh_const);

bool xdp_xtea_f2_check_x_xx(const uint32_t lsh_const, const uint32_t rsh_const,
									 const uint32_t k, const uint32_t delta,
									 const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
									 const uint32_t xx, const uint32_t x);

bool xdp_xtea_f2_is_sat(const uint32_t mask_i, const uint32_t lsh_const, const uint32_t rsh_const,
								const uint32_t k, const uint32_t delta,
								const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
								const uint32_t xx, const uint32_t x);

uint32_t xdp_xtea_f2_assign_bit_x_xx(const uint32_t n, const uint32_t i, const uint32_t mask_i, 
												 const uint32_t xx, const uint32_t x, 
												 const uint32_t key, const uint32_t  delta, 
												 const uint32_t lsh_const, const uint32_t rsh_const, 
												 const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
												 uint64_t* x_cnt, double* prob);

double xdp_xtea_f2_fk(const uint32_t n, const uint32_t dxx, const uint32_t dx, const uint32_t dy, 
							 const uint32_t key, const uint32_t  delta, 
							 const uint32_t lsh_const, const uint32_t rsh_const);

double nz_xdp_xtea_f(gsl_matrix* A[2][2][2], const uint32_t dx, uint32_t* dy,
							uint32_t lsh_const, uint32_t rsh_const);

#endif  // #ifndef XDP_XTEA_F_FK_H
