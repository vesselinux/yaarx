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
 * \file  adp-shift.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-shift.cc: \copybrief adp-shift.cc.
 */ 
#ifndef ADP_SHIFT_H
#define ADP_SHIFT_H

double adp_lsh_exper(uint32_t da, uint32_t db, int l);

void adp_lrot_odiffs(const uint32_t da, const int r, uint32_t dx[4], double P[4]);

double adp_lsh(uint32_t da, uint32_t db, int l);

double adp_rsh_exper(const uint32_t da, const uint32_t db, const int r);

double adp_rsh(uint32_t da, uint32_t db, int r);

void adp_rsh_odiffs(uint32_t dx[4], const uint32_t da, int r);

#endif  // #ifndef ADP_SHIFT_H
