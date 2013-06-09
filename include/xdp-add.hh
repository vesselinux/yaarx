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
 * \file  xdp-add.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-add.cc: \copybrief xdp-add.cc.
 */ 
#ifndef XDP_ADD_H
#define XDP_ADD_H

#ifndef XDP_ADD_MSIZE
#define XDP_ADD_MSIZE 4 /**< Number of state values in the \f$\mathrm{xdp}^{+}\f$ S-function. */
#endif
#ifndef XDP_ADD_NMATRIX
#define XDP_ADD_NMATRIX 8 /**< Number of \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif
#ifndef XDP_ADD_NINPUTS
#define XDP_ADD_NINPUTS 2 /**< Number of inputs to the XOR operation. */
#endif
#ifndef XDP_ADD_ISTATE
#define XDP_ADD_ISTATE 0 /**< Initial state for computing the \f$\mathrm{xdp}^{+}\f$ S-function. */
#endif
#ifndef XDP_ADD_COLSUM
#define XDP_ADD_COLSUM 4 /**< Sum of non-zero elements in one column of the \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif
#ifndef XDP_ADD_NORM
#define XDP_ADD_NORM 1.0 /(double)XDP_ADD_COLSUM /**< Normalization factor for the \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif

void xdp_add_alloc_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_free_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_normalize_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_print_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_print_matrices_sage(gsl_matrix* A[2][2][2]);

void xdp_add_sf(gsl_matrix* A[2][2][2]);

double xdp_add(gsl_matrix* A[2][2][2], uint32_t da, uint32_t db, uint32_t dc);

double xdp_add_exper(const uint32_t da, const uint32_t db, const uint32_t dc);

uint32_t aop(uint32_t x, uint32_t n);

uint32_t cap(uint32_t x, uint32_t y);

bool is_eq(uint32_t x, uint32_t y, uint32_t z);

uint32_t eq(uint32_t x, uint32_t y, uint32_t z);

double xdp_add_lm(uint32_t da, uint32_t db, uint32_t dc);

#endif  // #ifndef XDP_ADD_H
