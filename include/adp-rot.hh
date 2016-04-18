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
 * \file  adp-rot.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for adp-rot.cc: \copybrief adp-rot.cc.
 */ 
#ifndef ADP_ROT_H
#define ADP_ROT_H

double adp_lrot(WORD_T da, WORD_T db, int r);

void adp_lrot_odiffs(const WORD_T da, const int r, WORD_T dx[4], double P[4]);

double adp_lrot_exper(const WORD_T da, const WORD_T db, const int r);

double adp_lrot2_exper(const WORD_T da, const WORD_T db_r, const WORD_T db_s, const int r, const int s);

#endif  // #ifndef ADP_ROT_H
