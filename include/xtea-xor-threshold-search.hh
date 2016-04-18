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
 * \file  xtea-xor-threshold-search.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xtea-xor-threshold-search.cc. \copybrief xtea-xor-threshold-search.cc.
 */ 
#ifndef XTEA_XOR_THRESHOLD_SEARCH_H
#define XTEA_XOR_THRESHOLD_SEARCH_H

double xtea_xor_init_estimate(uint32_t next_round, uint32_t lsh_const, uint32_t rsh_const, uint32_t npairs,
										gsl_matrix* A[2][2][2], double B[NROUNDS], differential_t trail[NROUNDS], 
										std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,										
										uint32_t round_key[64], uint32_t round_delta[64]);

void xtea_xor_threshold_search(const int n, const int nrounds, const uint32_t npairs, 
										 const uint32_t round_key[64], const uint32_t round_delta[64],
										 gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
										 const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										 uint32_t lsh_const, uint32_t rsh_const,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										 uint32_t dxx_init, uint32_t* dxx_init_in);

//void xtea_xor_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64]);
//uint32_t xtea_xor_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64],
//										 double B[NROUNDS], differential_t trail[NROUNDS]);
uint32_t xtea_xor_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64],
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 double B[NROUNDS], differential_t trail[NROUNDS]);

//void xtea_xor_trail_search_full(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64]);
uint32_t xtea_xor_trail_search_full(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64],
												std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy,
												std::multiset<differential_t, struct_comp_diff_p> diff_mset_p,
												double BB[NROUNDS], differential_t trail[NROUNDS]);

#endif  // #ifndef XTEA_XOR_THRESHOLD_SEARCH_H
