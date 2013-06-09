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
 * \file  tea-f-add-pddt.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for tea-f-add-pddt.cc. \copybrief tea-f-add-pddt.cc.
 */ 
#ifndef TEA_F_ADD_PDDT_H
#define TEA_F_ADD_PDDT_H

bool rsh_condition_is_sat(const uint32_t k, const uint32_t new_da, const uint32_t new_dc);

bool lsh_condition_is_sat(const uint32_t k, const uint32_t new_da, const uint32_t new_db);

void tea_f_add_pddt_i(const uint32_t k, const uint32_t n, 
							 const uint32_t lsh_const,  const uint32_t rsh_const,
							 gsl_matrix* A[2][2][2][2], gsl_vector* C, 
							 uint32_t* da, uint32_t* db, uint32_t* dc, uint32_t* dd, 
							 double* p, const double p_thres, 
							 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy);

void tea_f_add_pddt(uint32_t n, double p_thres, uint32_t lsh_const, uint32_t rsh_const,
						  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy);

bool is_dx_in_set_dx_dy(uint32_t dy, uint32_t dx_prev, std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy);

void tea_f_da_add_pddt_i(const uint32_t k, const uint32_t n, 
								 const uint32_t lsh_const,  const uint32_t rsh_const,
								 gsl_matrix* A[2][2][2][2], gsl_vector* C,
								 const uint32_t da, uint32_t* db, uint32_t* dc, uint32_t* dd, 
								 double* p, const double p_thres, 
								 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
								 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
								 uint32_t* cnt_new);

uint32_t tea_f_da_add_pddt(uint32_t n, double p_thres, 
									uint32_t lsh_const, uint32_t rsh_const, const uint32_t da, const uint32_t da_prev,
									std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
									std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p,
									std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
									std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p);

void tea_f_add_pddt_adjust_to_key(uint32_t nrounds, uint32_t npairs, uint32_t key[4], double p_thres,
											 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy);


void tea_f_add_pddt_dxy_to_dp(std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy);

void tea_f_add_pddt_exper(gsl_matrix* A[2][2][2][2], uint32_t n, double p_thres,
								  uint32_t lsh_const, uint32_t rsh_const, 
								  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p);

void tea_f_add_pddt_fk_exper(uint32_t n, double p_thres, 
									  uint32_t delta, uint32_t k0, uint32_t k1,
									  uint32_t lsh_const, uint32_t rsh_const,
									  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p);

#endif  // #ifndef TEA_F_ADD_PDDT_H
