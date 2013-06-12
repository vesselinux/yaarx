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
 * \file  threefish-xor.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for threefish.cc: \copybrief threefish-xor.cc.
 */ 
#ifndef THREEFISH_XOR_H
#define THREEFISH_XOR_H

void xdp_add_dset_threefish32_mix(gsl_matrix* A[3][3][3], 
											 diff_set_t DX[4], diff_set_t DY[4], double P[4],
											 uint32_t rot_const_0, uint32_t rot_const_1,
											 bool b_single_diff);

double xdp_add_dset_threefish32(uint32_t nrounds, uint32_t rot_const[THREEFISH_MAX_NROUNDS][2], 
										  gsl_matrix* A[3][3][3],
										  diff_set_t DX_in[4], diff_set_t DY_in[4],
										  diff_set_t DT[THREEFISH_MAX_NROUNDS][4], double P[THREEFISH_MAX_NROUNDS][4]);

double xdp_add_dset_threefish32_exper(uint32_t nrounds, uint32_t rot_const[THREEFISH_MAX_NROUNDS][2], 
												  uint32_t npairs, uint32_t DX[4], diff_set_t DY_set[4]);

#endif  // #ifndef THREEFISH_XOR_H
