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
 * \file  adp-lsh-program.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The probability \f$\mathrm{adp}^{\ll}\f$ with user-provided input.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif

/**
 * Program for computing \f$\mathrm{adp}^{\ll}\f$ with user-provided
 * input.
 */
void adp_lsh_program()
{
  uint32_t da, db, l;

  printf("ADP_LSH: n = %d. Enter r (dec), da, db (hex). Ctrl-D to exit.\n", WORD_SIZE);
  while (EOF != scanf("%d %x %x", &l, &da, &db)) {
	 da &= MASK;
	 db &= MASK;
	 l %= WORD_SIZE;
	 double p = adp_lsh(da, db, l);
	 printf("[%s:%d] ADP_LSH[(%8X -%d-> %8X)] = %6.5f\n", 
			  __FILE__, __LINE__, da, l, db, p);

  }
  printf("Exiting...\n");
}

/** 
 * Main function for the \f$\mathrm{adp}^{\ll}\f$ program.
 */ 
int main()
{
	 srandom(time(NULL));
	 printf("[%s:%d]\n", __FILE__, __LINE__);

	 adp_lsh_program();
	 return 0;
}
