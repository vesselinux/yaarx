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
						  uint32_t* da, uint32_t* db, uint32_t* dc,
						  double* p, std::multiset<differential_3d_t, struct_comp_diff_3d_p> *diff_set);

void xdp_add_pddt(uint32_t n, double p_thres);

#endif  // #ifndef XDP_ADD_PDDT_H
