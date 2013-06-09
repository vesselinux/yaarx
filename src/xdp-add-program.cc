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
 * \file  xdp-add-program.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Program for computing \f$\mathrm{xdp}^{+}\f$ with user-provided input.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif

/** 
 * Compute XDP-ADD with user-provided input.
 */ 
void xdp_add_program()
{
  uint32_t da, db, dc;
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

  printf("XDP_ADD: n = %d. Enter da, db, dc (hex) or Ctrl-D to exit:\n", WORD_SIZE);
  while (EOF != scanf("%x %x %x", &da, &db, &dc)) {
	 double p1 = xdp_add(A, da, db, dc);
	 assert((p1 >= 0.0) && (p1 <= 1.0));
	 printf("[%s:%d] XDP_ADD[%8X,%8X->%8X] = %16.15f = 2^%3.2f\n", 
			  __FILE__, __LINE__, da, db, dc, p1, log2(p1));
  }
  printf("Exiting...\n");
  xdp_add_free_matrices(A);
}

/** 
 * Main function for the XDP-ADD program.
 */ 
int main()
{
	 srandom(time(NULL));
	 printf("[%s:%d]\n", __FILE__, __LINE__);

	 xdp_add_program();
	 return 0;
}
