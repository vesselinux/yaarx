/*
 *    Copyright (c) 2012-2014 Luxembourg University,
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
 * \file  add-approx.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2014
 * \brief Header file for add-approx.cc: \copybrief add-approx.cc .
 */ 
#ifndef ADD_APPROX_H
#define ADD_APPROX_H

// ADD
WORD_T add_bitwise(const WORD_T x, const WORD_T y);
WORD_T add_approx_o1(const WORD_T x, const WORD_T y);
WORD_T add_approx_o2_fast(const WORD_T x, const WORD_T y);
WORD_T add_approx_o2(const WORD_T x, const WORD_T y);
WORD_T add_approx_o3(const WORD_T x, const WORD_T y);
WORD_T add_approx_o4(const WORD_T x, const WORD_T y);
WORD_T add_approx_o5(const WORD_T x, const WORD_T y);
WORD_T add_approx_o6(const WORD_T x, const WORD_T y);
WORD_T add_approx(const WORD_T x, const WORD_T y, const uint32_t order);
WORD_T add_approx_any_order(const WORD_T x, const WORD_T y, const uint32_t order);
WORD_T add_block_approx(const WORD_T x, const WORD_T y, const uint32_t block_size);
// SUB
WORD_T sub_bitwise(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o1(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o2_fast(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o2(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o3(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o4(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o5(const WORD_T x, const WORD_T y);
WORD_T sub_approx_o6(const WORD_T x, const WORD_T y);
WORD_T sub_approx(const WORD_T x, const WORD_T y, const uint32_t order);
WORD_T sub_approx_any_order(const WORD_T x, const WORD_T y, const uint32_t order);
WORD_T sub_approx_any_order_equiv(const WORD_T x_in, const WORD_T y_in, const uint32_t order_in);
// XDP-ADD-APPROX
double xdp_add_approx_exper(const WORD_T da, const WORD_T db, const WORD_T dc, uint32_t order);
void xdp_add_approx_rec_i(const uint32_t i, const uint32_t order,
								  const WORD_T dx, const WORD_T dy, const WORD_T dz,
								  const WORD_T x, const WORD_T y, uint64_t* cnt_xy);
double xdp_add_approx_rec(const WORD_T dx, const WORD_T dy, const WORD_T dz, uint32_t order);
double xdp_add_fixed_x_approx_exper(const WORD_T a1, const WORD_T a2,  const WORD_T db, const WORD_T dc, uint32_t order);
void xdp_add_fixed_x_approx_rec_i(const uint32_t i, const uint32_t order,
											 const WORD_T dy, const WORD_T dz, const WORD_T x, const WORD_T xx, 
											 const WORD_T y, uint64_t* cnt_y);
double xdp_add_fixed_x_approx_rec(const WORD_T x, const WORD_T xx, const WORD_T dy, const WORD_T dz, uint32_t order);
// XDP-SUB-APPROX
double xdp_sub_approx_exper(const WORD_T da, const WORD_T db, const WORD_T dc, uint32_t order);
void xdp_sub_approx_rec_i(const uint32_t i, const uint32_t order,
								  const WORD_T dx, const WORD_T dy, const WORD_T dz,
								  const WORD_T x, const WORD_T y, uint64_t* cnt_xy);
double xdp_sub_approx_rec(const WORD_T dx, const WORD_T dy, const WORD_T dz, uint32_t order);
double xdp_sub_fixed_x_approx_exper(const WORD_T a1, const WORD_T a2,  const WORD_T db, const WORD_T dc, uint32_t order);
void xdp_sub_fixed_x_approx_rec_i(const uint32_t i, const uint32_t order,
											 const WORD_T dy, const WORD_T dz, const WORD_T x, const WORD_T xx, 
											 const WORD_T y, uint64_t* cnt_y);
double xdp_sub_fixed_x_approx_rec(const WORD_T x, const WORD_T xx, const WORD_T dy, const WORD_T dz, uint32_t order);


#endif // #ifndef ADD_APPROX_H
