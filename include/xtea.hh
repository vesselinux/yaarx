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
 * \file  xtea.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xtea.cc. \copybrief xtea.cc.
 */ 
#ifndef XTEA_H
#define XTEA_H

#ifndef XTEA_XOR_P_THRES
#define XTEA_XOR_P_THRES 0.08//0.120 /**< Probability threshold for XOR differences. */
#endif
#ifndef XTEA_ADD_P_THRES
#define XTEA_ADD_P_THRES 0.05	/**< Probability threshold for ADD differences. */
#endif
#ifndef XTEA_XOR_MAX_PDDT_SIZE // 2^20 ~= 1,048,576
#define XTEA_XOR_MAX_PDDT_SIZE (1U << 20) /**< Maximum size of the pDDT for XOR differences. */ 
#endif
#ifndef XTEA_ADD_MAX_PDDT_SIZE
#define XTEA_ADD_MAX_PDDT_SIZE (1U << 20) /**< Maximum size of the pDDT for ADD differences. */
#endif

void xtea_r(uint32_t nrounds, uint32_t v[2], uint32_t const k[4], uint32_t lsh_const, uint32_t rsh_const);

uint32_t xtea_f(uint32_t x, uint32_t k, uint32_t delta, 
					 uint32_t lsh_const, uint32_t rsh_const);

uint32_t xtea_f_i(const uint32_t mask_i, 
						const uint32_t lsh_const, const uint32_t rsh_const,
						const uint32_t x_in, const uint32_t k, const uint32_t delta);

uint32_t xtea_f2(uint32_t xx, uint32_t x, uint32_t k, uint32_t delta, 
					  uint32_t lsh_const, uint32_t rsh_const);

uint32_t xtea_f2_i(const uint32_t mask_i, 
						 const uint32_t lsh_const, const uint32_t rsh_const,
						 const uint32_t xx_in, const uint32_t x_in, 
						 const uint32_t k, const uint32_t delta);

uint32_t xtea_f_lxr(uint32_t x, uint32_t lsh_const, uint32_t rsh_const);

uint32_t xtea_f_lxr_i(const uint32_t mask_i, 
							 const uint32_t lsh_const, const uint32_t rsh_const, const uint32_t x_in);

void xtea_all_round_keys_and_deltas(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64]);



double xtea_one_round_xor_differential_exper(uint64_t npairs, int round_idx, 
															uint32_t key, uint32_t delta,
															uint32_t daa, uint32_t da, uint32_t db);

double xtea_one_round_add_differential_exper(uint64_t npairs, int round_idx, 
															uint32_t key, uint32_t delta,
															uint32_t da, uint32_t db);

double xtea_xor_differential_exper_v2(uint64_t npairs, int r, 
												  uint32_t key[4], uint32_t da[2], uint32_t db[2],
												  uint32_t lsh_const, uint32_t rsh_const);

double xtea_add_differential_exper_v2(uint64_t npairs, int r, 
												  uint32_t key[4], uint32_t da[2], uint32_t db[2],
												  uint32_t lsh_const, uint32_t rsh_const);

uint32_t xtea_xor_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t lsh_const, uint32_t rsh_const,
												  uint32_t key[4], uint32_t dxx_init, differential_t trail[NROUNDS]);

uint32_t xtea_add_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t lsh_const, uint32_t rsh_const,
												  uint32_t key[4], differential_t trail[NROUNDS]);

uint32_t xtea_xor_verify_trail(uint32_t nrounds, uint32_t npairs, 
										 uint32_t round_key[64], uint32_t round_delta[64],
										 uint32_t dxx_init, differential_t trail[NROUNDS]);

uint32_t xtea_add_verify_trail(uint32_t nrounds, uint32_t npairs, 
										 uint32_t round_key[64], uint32_t round_delta[64],
										 differential_t trail[NROUNDS]);


#endif  // #ifndef XTEA_H
