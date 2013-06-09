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
 * \file  tea.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for tea.cc. \copybrief tea.cc.
 */ 
#ifndef TEA_H
#define TEA_H

#ifndef TEA_ADD_P_THRES
#define TEA_ADD_P_THRES 0.05//0.0002//0.001//0.008//0.05 /**< Probability threshold for ADD differences. */
#endif
#ifndef TEA_ADD_MAX_PDDT_SIZE	// 2^20 ~= 1,048,576
#define TEA_ADD_MAX_PDDT_SIZE (1U << 25) /**< Maximum size of the pDDT for ADD differences. */
#endif
#ifndef TEA_NCYCLES
#define TEA_NCYCLES 32 /**< Cycles in TEA: 1 cycle = 2 rounds. */
#endif

void tea_encrypt(uint32_t* v, uint32_t* k, int nrounds);

uint32_t tea_f(uint32_t x, uint32_t k0, uint32_t k1, uint32_t delta, uint32_t lsh_const, uint32_t rsh_const);

uint32_t tea_f_i(const uint32_t mask_i, 
					  const uint32_t k0, const uint32_t k1, const uint32_t delta,
					  const uint32_t lsh_const, const uint32_t rsh_const, const uint32_t x_in);

void tea_compute_delta_const(uint32_t D[TEA_NCYCLES]);

double tea_add_diff_adjust_to_key(const uint64_t npairs, const int round_idx, 
											 const uint32_t da, const uint32_t db, 
											 const  uint32_t key[4]);

double tea_differential_thres_exper_fk(uint64_t npairs, int r, uint32_t key[4], uint32_t da[2], uint32_t db[2]);

uint32_t tea_add_verify_trail(uint32_t nrounds, uint32_t npairs, uint32_t key[4], differential_t trail[NROUNDS]);

uint32_t tea_add_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t key[4], differential_t trail[NROUNDS]);

void print_trail_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS]);

#endif  // #ifndef TEA_H
