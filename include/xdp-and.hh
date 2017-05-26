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
 * \file  xdp-and.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-and.cc: \copybrief xdp-and.cc.
 */ 
#ifndef XDP_AND_H
#define XDP_AND_H

void xdp_and_sf(uint32_t A[2][2][2]);
void xdp_and_bf(uint32_t A[2][2][2]);
double xdp_and(uint32_t A[2][2][2], uint32_t da, uint32_t db, uint32_t dc);
bool xdp_and_is_nonzero(uint32_t da, uint32_t db, uint32_t dc);
double xdp_and_exper(uint32_t da, uint32_t db, uint32_t dc);
int xdp_and_closed(uint32_t da, uint32_t db, uint32_t dc);
bool xdp_and_is_zero(uint32_t da, uint32_t db, uint32_t dc);

#endif  // #ifndef XDP_AND_H
