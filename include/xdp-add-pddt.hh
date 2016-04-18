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
 * \file  xdp-add-pddt.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-add-pddt.cc. \copybrief xdp-add-pddt.cc
 */ 
#ifndef XDP_ADD_PDDT_H
#define XDP_ADD_PDDT_H

uint32_t xdp_add_pddt_exper(std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_set, double p_thres);

void xdp_add_pddt_i(const uint32_t k, const uint32_t n, const double p_thres, 
						  gsl_matrix* A[2][2][2], gsl_vector* C, 
						  uint32_t* da, uint32_t* db, uint32_t* dc, double* p, 
						  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
						  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p,
						  uint64_t max_size);

void xdp_add_pddt(uint32_t n, double p_thres, const uint64_t max_size,
						std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* diff_set_dx_dy_dz,
						std::multiset<differential_3d_t, struct_comp_diff_3d_p>* diff_mset_p);

bool xdp_add_is_dz_in_set_dx_dy_dz(uint32_t dx, uint32_t dy,
											  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz> diff_set_dx_dy_dz);

void xdp_add_dx_dy_pddt_i(const uint32_t k, const uint32_t n, gsl_matrix* A[2][2][2], gsl_vector* C, 
								  const uint32_t da, const uint32_t db, uint32_t* dc, double* p, 
								  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
								  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
								  std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
								  std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
								  uint32_t right_rot_const, uint32_t left_rot_const,
								  const double p_thres, uint32_t max_size);

uint32_t xdp_add_dx_dy_pddt(uint32_t da, uint32_t db, 
									 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* hways_diff_set_dx_dy_dz,
									 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* hways_diff_mset_p,
									 std::set<differential_3d_t, struct_comp_diff_3d_dx_dy_dz>* croads_diff_set_dx_dy_dz,
									 std::multiset<differential_3d_t, struct_comp_diff_3d_p>* croads_diff_mset_p,
									 uint32_t right_rot_const, uint32_t left_rot_const,
									 double p_thres, uint32_t max_size);

#endif  // #ifndef XDP_ADD_PDDT_H
