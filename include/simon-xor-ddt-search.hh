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
 * \file  simon-xor-ddt-search.hh
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-rot-and.cc: \copybrief simon-xor-ddt-search.cc .
 */ 
#ifndef SIMON_XOR_DDT_SEARCH_H
#define SIMON_XOR_DDT_SEARCH_H 

double** simon_ddt_alloc();
void simon_ddt_free(double** T);
differential_t** simon_rsddt_alloc();
void simon_rsddt_free(differential_t** T);
void simon_ddt_sort_rows(differential_t** T);
bool simon_comp_differentials_npairs(differential_t a, differential_t b);
bool simon_comp_differentials_diffs(differential_t a, differential_t b);
void simon_ddt_sort(differential_t* SDDT);
differential_t* simon_sddt_alloc();
void simon_sddt_free(differential_t* ST);
void simon_ddt_to_list(double** DDT, differential_t* SDDT);
void simon_ddt_to_diff_struct(double** DDT, differential_t** SDDT);
void simon_rot_and_ddt(double** D, const uint32_t s, const uint32_t t, const double p_thres);
void simon_xor_ddt_search(const int n, const int nrounds, 
								  double B[NROUNDS], double* Bn,
								  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
								  const uint32_t dyy_init,
								  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
								  differential_t* SDDT, // sorted DDT
								  differential_t** RSDDT, // row-sorted DDT
								  double p_thres);
uint32_t simon_xor_ddt_trail_search(uint32_t key[SIMON_MAX_NROUNDS], double B[NROUNDS], differential_t trail[NROUNDS], uint32_t num_rounds);

// Next: max HW = 5
uint32_t gen_word_hw(const uint32_t n, const uint32_t hw, 
							std::vector<uint32_t>* X);
uint32_t gen_word_hw_all(const uint32_t word_size, const uint32_t hw);
void simon_diff_update_max(const differential_t input_diff, const differential_t output_diff, differential_t* max_diff);
void simon_compute_full_ddt(std::unordered_map<uint32_t, std::vector<differential_t>>* T);
void simon32_ddt_file_write(const char* filename,
									 std::unordered_map<uint32_t, std::vector<differential_t>>* T);
void simon32_ddt_file_read(const char* filename, 
									std::unordered_map<uint32_t, std::vector<differential_t>>* T);
void simon_diff_search(const uint32_t nrounds, 
							  const uint32_t dx_in, 
							  const uint32_t dy_in, 
							  const uint32_t hw_max,
							  std::unordered_map<uint32_t, std::vector<differential_t>>* T,
							  std::unordered_map<uint32_t, differential_t>* D, // all output diffs after D_round
							  const uint32_t D_round,
							  const char* logfile);
void simon_compute_partial_ddt(std::unordered_map<uint32_t, std::vector<differential_t>>* T,
										 std::vector<uint32_t> DX, const uint32_t hw_max);


#endif  // #ifndef SIMON_XOR_THRESHOLD_SEARCH_H
