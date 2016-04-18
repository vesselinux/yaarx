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
 * \file  speck-xor-threshold-search.hh
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-rot-and.cc: \copybrief speck-xor-threshold-search.cc.
 */ 
#ifndef SPECK_XOR_THRESHOLD_SEARCH_H
#define SPECK_XOR_THRESHOLD_SEARCH_H 

#if(WORD_SIZE == 32)
extern double g_B[SPECK_TRAIL_LEN];
extern differential_t g_trail[SPECK_TRAIL_LEN];
#endif
#if(WORD_SIZE == 24)
extern double g_B[SPECK_TRAIL_LEN];
extern differential_t g_trail[SPECK_TRAIL_LEN];
#endif
#if(WORD_SIZE == 16)
extern double g_B[SPECK_TRAIL_LEN];
extern differential_t g_trail[SPECK_TRAIL_LEN];
#endif

void speck_print_round_diffs_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS + 1]);
uint32_t speck_verify_xor_differential(uint32_t nrounds, uint32_t npairs, 
													WORD_T key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
													const WORD_T dx_init, const WORD_T dy_init,
													uint32_t right_rot_const, uint32_t left_rot_const);
uint32_t speck_verify_xor_differential_decrypt(uint32_t nrounds, uint32_t npairs, 
															  uint32_t key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
															  const uint32_t dx_init, const uint32_t dy_init,
															  uint32_t right_rot_const, uint32_t left_rot_const);
uint32_t speck_verify_xor_trail ( uint32_t nrounds, uint32_t npairs, 
										  uint32_t key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
										  const uint32_t dx_init, const uint32_t dy_init,
										  uint32_t right_rot_const, uint32_t left_rot_const);
uint32_t speck_verify_xor_trail_decrypt ( uint32_t nrounds, uint32_t npairs, 
													 uint32_t key_in[SPECK_MAX_NROUNDS], differential_t trail[NROUNDS],
													 const uint32_t dx_init, const uint32_t dy_init,
													 uint32_t right_rot_const, uint32_t left_rot_const);
uint32_t speck_xor_trail_search(uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS],
										  WORD_T* dx_input, WORD_T* dy_input, 
										  differential_t best_trail[NROUNDS], uint32_t num_rounds);
uint32_t speck_xor_trail_search_encrypt ( uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS], 
														const WORD_T dx_input, const WORD_T dy_input, 
														differential_t best_trail[NROUNDS], const uint32_t num_rounds,
														std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
														std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
														gsl_matrix* A[2][2][2]);
uint32_t speck_xor_trail_search_decrypt ( uint32_t key[SPECK_MAX_NROUNDS], double B[NROUNDS], 
														const WORD_T dx_input, const WORD_T dy_input, 
														differential_t best_trail[NROUNDS], const uint32_t num_rounds,
														std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
														std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
														gsl_matrix* A[2][2][2]);
void speck_xdp_add_pddt(uint32_t n, double p_thres, uint32_t hw_thres, const uint64_t max_size,
								std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
								std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p);
void speck_trail_cluster_search_boost(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, speck_trail_hash, speck_trail_equal_to>* trails_hash_map,
												  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
												  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
												  uint32_t dx_input, uint32_t dy_input,  
												  double B[NROUNDS], differential_t trail_in[NROUNDS], uint32_t trail_len);
void speck_xor_threshold_search(const int n, const int nrounds, gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
										  const differential_t diff_in[NROUNDS], uint32_t dx_init_in, uint32_t dy_init_in, 
										  differential_t trail[NROUNDS], uint32_t* dx_init, uint32_t* dy_init,
										  uint32_t right_rot_const, uint32_t left_rot_const,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p, // highways
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
										  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p, // country roads
										  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
										  double p_thres, bool b_speck_cluster_trails);
#endif  // #ifndef SPECK_XOR_THRESHOLD_SEARCH_H
