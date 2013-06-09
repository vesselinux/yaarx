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
 * \file  eadp-tea-f-program.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The probability \f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$ with user-provided input.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef EADP_TEA_F_H
#include "eadp-tea-f.hh"
#endif

/**
 * Program for computing \f$\mathrm{eadp}^{F}\f$ with user-provided
 * input.
 */
void eadp_tea_f_program()
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint32_t dx;
  uint32_t dy;

  printf("EADP_TEA_F: n = %d. Enter dx, dy (hex). Ctrl-D to exit:\n", WORD_SIZE);
  while (EOF != scanf("%x %x", &dx, &dy)) {
	 //			 printf("%x %x %x %x\n", da, db, dc, dd);
	 dx &= MASK;
	 dy &= MASK;
	 double p1 = eadp_tea_f(A, dx, dy, &p1, lsh_const, rsh_const);
	 assert((p1 >= 0.0) && (p1 <= 1.0));
	 printf("[%s:%d] %2d %2d | EADP_TEA_F(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p1);
  }
  printf("Exiting...\n");
  adp_xor3_free_matrices(A);
}

/** 
 * Main function for the \f$\mathrm{eadp}^{F}\f$ program.
 */ 
int main()
{
	 srandom(time(NULL));
	 printf("[%s:%d]\n", __FILE__, __LINE__);

	 eadp_tea_f_program();
	 return 0;
}
