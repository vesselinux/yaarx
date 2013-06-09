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
 * \file  xtea-add-threshold-search.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xtea-add-threshold-search.cc. \copybrief xtea-add-threshold-search.cc
 */ 
#ifndef XTEA_ADD_THRESHOLD_SEARCH_H
#define XTEA_ADD_THRESHOLD_SEARCH_H

void xtea_add_threshold_search(const int n, const int nrounds, const uint32_t npairs, 
										 const uint32_t round_key[64], const uint32_t round_delta[64],
										 gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], double B[NROUNDS], double* Bn,
										 const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										 uint32_t lsh_const, uint32_t rsh_const,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy);

void xtea_add_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64]);


#endif  // #ifndef XTEA_ADD_THRESHOLD_SEARCH_H
