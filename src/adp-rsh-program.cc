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
 * \file  adp-rsh-program.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The probability \f$\mathrm{adp}^{\gg}\f$ with user-provided input.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif

/**
 * Program for computing \f$\mathrm{adp}^{\gg}\f$ with user-provided
 * input.
 */
void adp_rsh_program()
{
  uint32_t da, db, r;
  //  uint32_t r = TEA_RSH_CONST;

  printf("ADP_RSH: n = %d. Enter r (dec), da, db (hex). Ctrl-D to exit.\n", WORD_SIZE);
  while (EOF != scanf("%d %x %x", &r, &da, &db)) {
	 da &= MASK;
	 db &= MASK;
	 r %= WORD_SIZE;
#if 0									  // one
	 double pp = adp_rsh(da, db, r);
	 printf("[%s:%d] ADP_RSH[(%8X -%d-> %8X)] = %6.5f\n", 
			  __FILE__, __LINE__, da, r, db, pp);
#else									  // all
	 uint32_t dx[4] = {0};
	 double p[4] = {0.0};
	 adp_rsh_odiffs(dx, da, r);
	 for(uint32_t j = 0; j < 4; j++) {
		p[j] = adp_rsh(da, dx[j], r);
		printf("[%s:%d] ADP_RSH[(%8X -%d-> %8X)] = %6.5f\n", 
				 __FILE__, __LINE__, da, r, dx[j], p[j]);
	 }
#endif

  }
  printf("Exiting...\n");
}

/** 
 * Main function for the \f$\mathrm{adp}^{\gg}\f$ program.
 */ 
int main()
{
	 srandom(time(NULL));
	 printf("[%s:%d]\n", __FILE__, __LINE__);

	 adp_rsh_program();
	 return 0;
}
