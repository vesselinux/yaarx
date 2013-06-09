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
 * \file  bsdr.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for bsdr.cc: \copybrief bsdr.cc.
 */ 
#ifndef BSDR_H
#define BSDR_H

// signed difference structure
// val == {-1,0,+1}
// sign == 0 if val == +1 or 0
// sign == 1 if val == -1
/**
 * A structure for the binary signed digit (BSD) 
 * representatoin of an integer.
 */
struct bsd_t
{
	  uint32_t val;
	  uint32_t sign;
};

bsd_t naf(uint32_t x);

#endif  // #ifndef BSDR_H
