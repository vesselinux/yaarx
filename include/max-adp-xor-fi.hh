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
 * \file  max-adp-xor-fi.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for max-adp-xor-fi.cc. \copybrief max-adp-xor-fi.cc.
 */ 
#ifndef MAX_ADP_XOR_FI_H
#define MAX_ADP_XOR_FI_H

double max_adp_xor_fixed_input(gsl_matrix* A[2][2][2],
										 const uint32_t a, const uint32_t db,
										 uint32_t* dd_max);

double max_adp_xor_fixed_input_exper(gsl_matrix* A[2][2][2], 
												 const uint32_t da, const uint32_t db, 
												 uint32_t* dc_max);

#endif  // #ifndef MAX_ADP_XOR_FI_H
