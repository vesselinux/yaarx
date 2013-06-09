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
 * \file  bsdr.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Functions related to binary-signed digit representation (BSDR) of integers.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef BSDR_H
#include "bsdr.hh"
#endif

/**
 * Compute the non-adjacent form (NAF) representation
 * of the integer \p x 
 *
 * \param x input value.
 * \returns the non-adjacent form (NAF) of x.
 */
bsd_t naf(uint32_t x)
{
  bsd_t n = {0, 0};
	  
  for (uint32_t b = 1; x != 0; b <<= 1) {
	 const uint32_t v = x & b;
	 const uint32_t s = (x >> 1) & b & v;

	 n.val |= v;
	 n.sign |= s;
			 
	 if (s == 0)
		x -=  v;
	 else
		x -= -v;
  }

  return n;
}
