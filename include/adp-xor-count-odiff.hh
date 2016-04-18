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
 * \file  adp-xor-count-odiff.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-xor-count-odiff.cc: \copybrief adp-xor-count-odiff.cc .
 */ 
#ifndef ADP_XOR_COUNT_ODIFF_H
#define ADP_XOR_COUNT_ODIFF_H

#define ADP_XOR_COUNT_MSIZE 256
#define ADP_XOR_COUNT_NMATRIX_3D 8
#define ADP_XOR_COUNT_NMATRIX_2D 4
#define ADP_XOR_COUNT_ISTATE 16 // s =  16: 0 0 0 0 1 0 0 0 

void adp_xor_count_odiff_alloc_matrices_3d(gsl_matrix* P[2][2][2]);
void adp_xor_count_odiff_free_matrices_3d(gsl_matrix* P[2][2][2]);
void adp_xor_count_odiff_alloc_matrices_2d(gsl_matrix* P[2][2]);
void adp_xor_count_odiff_free_matrices_2d(gsl_matrix* P[2][2]);
void adp_xor_count_odiff_matrices_3d_to_2d(gsl_matrix* P[2][2][2], gsl_matrix* PP[2][2]);
void adp_xor_count_odiff_sf(gsl_matrix* P[2][2][2], gsl_matrix* A[2][2][2]);
double adp_xor_count_odiff_3d(gsl_matrix* A[2][2][2], uint32_t da, uint32_t db);
double adp_xor_count_odiff_2d(gsl_matrix* A[2][2], uint32_t da, uint32_t db);
double adp_xor_count_odiff_exper(const uint32_t da, const uint32_t db);


#endif  // #ifndef ADP_XOR_COUNT_ODIFF_H
