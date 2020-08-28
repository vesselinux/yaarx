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
 * \file  xdp-rot-and.hh
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-rot-and.cc: \copybrief xdp-rot-and.cc.
 */ 
#ifndef XDP_ROT_AND_H
#define XDP_ROT_AND_H

#define XDP_ROT_AND_MSIZE 4
#define XDP_ROT_AND_NISTATES 2  // number of initial states
#define XDP_ROT_AND_MAX_DIFF_CNT (1ULL << 7)//70ULL//(1ULL << 3)//70ULL//(1ULL << 6)//(1ULL << 7)//(1ULL << 8)
#define XDP_ROT_AND_P_THRES 0.06//0.06//0.016//0.0.06//0.12//0.2//0.1//0.05//0.01//(1.0 / (double)(1UL << 4))//0.1//0.1//0.05
#define XDP_ROT_AND_P_LOW_THRES 0.0//(1.0 / (double)(1UL << 6))
#define XDP_ROT_AND_MAX_HW 4//vv20200828
#define TRAIL_MAX_HW 32
#define XDP_ROT_PDDT_GEN_RANDOM false

double xdp_rot_and_exper(uint32_t da, uint32_t dc,
			 uint32_t rot_const_1, uint32_t rot_const_2);
void xdp_rot_and_alloc_matrices(gsl_matrix* A[WORD_SIZE]);
void xdp_rot_and_free_matrices(gsl_matrix* A[WORD_SIZE]);
void xdp_rot_and_print_graph(gsl_matrix* A[WORD_SIZE]);
void xdp_rot_and_print_matrix(gsl_matrix* A);
void xdp_rot_and_print_vector(gsl_vector* R);
void xdp_rot_and_compute_subgraph(gsl_matrix* A, 
											 uint32_t da_in, uint32_t db_in, uint32_t dc_in,
											 uint32_t da_out, uint32_t db_out, uint32_t dc_out);
void xdp_rot_and_compute_graph(gsl_matrix* A[WORD_SIZE], uint32_t i_start, uint32_t cycle_len,
										 uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										 const uint32_t da, const uint32_t db, const uint32_t dc);
double xdp_rot_and(const uint32_t delta, const uint32_t dc, 
						 const uint32_t s, const uint32_t t);
void xdp_rot_and_index_debug(uint32_t s, uint32_t t);
void xdp_rot_and_xcond_init(uint32_t XCOND[2][2][2][2]);
void xdp_and_print_equations(uint32_t E[WORD_SIZE][WORD_SIZE + 1]);
uint32_t xdp_and_add_equation(uint32_t i, uint32_t E[WORD_SIZE][WORD_SIZE + 1],
										uint32_t da_i, uint32_t db_i, uint32_t dc_i,
										uint32_t x_i, uint32_t y_i); 
double xdp_rot_and_constraints(const uint32_t delta, const uint32_t dc,
										 const uint32_t s_in, const uint32_t t_in);
uint32_t xdp_rot_compute_indices(uint32_t s, uint32_t t, bool b_is_marked[WORD_SIZE], 
											uint32_t i_start, uint32_t start_idx,
											uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE]);
void xdp_rot_and_compute_graph_i(gsl_matrix* A[WORD_SIZE], uint32_t i_start, uint32_t cycle_len,
											uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
											const uint32_t da, const uint32_t db, const uint32_t dc);
void xdp_rot_and_normalize_matrix(gsl_matrix* A, double f);
void max_xdp_rot_and_bounds_0(uint32_t k, const uint32_t k_start, const uint32_t n, double* p, uint32_t* dc,
										gsl_matrix* A, gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE], gsl_vector* C[2],
										uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										const uint32_t da, const uint32_t db, 
										uint32_t* dc_max, double* p_max);
void max_xdp_rot_and_bounds_i(uint32_t k, const uint32_t k_start, const uint32_t n, double* p, uint32_t* dc,
										gsl_matrix* A, gsl_vector* B[WORD_SIZE], gsl_vector* C,
										uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
										const uint32_t da, const uint32_t db, 
										uint32_t* dc_max, double* p_max);
void max_xdp_rot_and_bounds(gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE],
									 uint32_t i_start, uint32_t cycle_len,
									 uint32_t da_idx[WORD_SIZE], uint32_t db_idx[WORD_SIZE],
									 const uint32_t da, const uint32_t db, uint32_t* dc_max);
void max_xdp_rot_and_print_bounds(gsl_vector* B[XDP_ROT_AND_NISTATES][WORD_SIZE]);
double max_xdp_rot_and_exper(uint32_t da, uint32_t* dc_max,
									  uint32_t s, uint32_t t);
double max_xdp_rot_and(const uint32_t delta, uint32_t* dc, 
							  const uint32_t s, const uint32_t t);
uint64_t xdp_rot_and_pddt(std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
								  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
								  const uint32_t s, const uint32_t t, const uint64_t max_cnt, const double p_thres);
void xdp_rot_and_print_mset_hw(std::multiset<differential_t, struct_comp_diff_hw> hways_diff_mset_hw);
void xdp_rot_and_print_mset_p(std::multiset<differential_t, struct_comp_diff_p> hways_diff_mset_p);
void xdp_rot_and_print_set_dx_dy(std::set<differential_t, struct_comp_diff_dx_dy> hways_diff_set_dx_dy);
uint64_t xdp_rot_and_dx_pddt(const uint32_t delta, const uint32_t delta_prev, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy, // initial highways
									  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy, // all highways
									  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, 
									  std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy, // ocuntryroads
									  std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p,
									  const uint32_t s, const uint32_t t, const uint32_t u,
									  const uint64_t max_cnt, const double p_thres, bool b_backto_hway);
bool xdp_rot_and_is_dx_in_set_dx_dy(uint32_t dy, uint32_t dx, uint32_t dx_prev, uint32_t lrot_const_u,
												std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy);
void xdp_rot_and_ddt(std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
							std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
							const uint32_t s, const uint32_t t, const double p_thres);
#endif  // #ifndef XDP_ROT_AND_H
