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
 * \file  adp-xor3-program.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The probability (\f$\mathrm{adp}^{3\oplus}\f$) with user-provided input.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif

/**
 * Program for computing \f$\mathrm{adp}^{3\oplus}\f$ with user-provided
 * input.
 */
void adp_xor3_program()
{
  uint32_t da, db, dc, dd;
  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  printf("ADP_XOR3: n = %d. Enter da, db, dc, dd (hex):\n", WORD_SIZE);
  while (EOF != scanf("%x %x %x %x", &da, &db, &dc, &dd)) {
	 da &= MASK;
	 db &= MASK;
	 dc &= MASK;
	 dd &= MASK;
	 double p1 = adp_xor3(A, da, db, dc, dd);
	 assert((p1 >= 0.0) && (p1 <= 1.0));
	 printf("[%s:%d] ADP_XOR3[(%8X,%8X,%8X)->%8X] = %16.15f = 2^%3.2f\n", 
			  __FILE__, __LINE__, da, db, dc, dd, p1, log2(p1));
  }
  printf("Exiting...\n");
  adp_xor3_free_matrices(A);
}

/** 
 * Main function for the \f$\mathrm{adp}^{3\oplus}\f$ program.
 */ 
int main()
{
	 srandom(time(NULL));
	 printf("[%s:%d]\n", __FILE__, __LINE__);

	 adp_xor3_program();
	 return 0;
}
