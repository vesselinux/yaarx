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
 * \file  adp-rsh-xor-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-rsh-xor.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef ADP_RSH_XOR_H
#include "adp-rsh-xor.hh"
#endif

void test_adp_rsh_xor_alloc()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[3][2][2][2];
  adp_rsh_xor_alloc_matrices(A);
  adp_rsh_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_rsh_xor_sf()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[3][2][2][2];
  adp_rsh_xor_alloc_matrices(A);
  adp_rsh_xor_sf(A);
#if 0
  adp_rsh_xor_normalize_matrices(A);
  adp_rsh_xor_print_matrices(A);
#endif
  adp_rsh_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_rsh_xor()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  gsl_matrix* A[3][2][2][2];	  // matrices to compute ADP
  adp_rsh_xor_alloc_matrices(A);
  adp_rsh_xor_sf(A);
  adp_rsh_xor_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 //	 uint32_t dx = da;
	 for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		for(uint32_t db = 0; db < ALL_WORDS; db++) {
		  for(uint32_t r = 1; r < WORD_SIZE; r++) {

			 double p1 = adp_rsh_xor_exper(da, dx, db, r);
			 double p2 = adp_rsh_xor(A, da, dx, db, r);
			 double p5 = adp_rsh_xor_approx(da, dx, db, r);
#if DEBUG_ADP_RSH_XOR_TESTS
			 printf("[%s:%d] ADP_RSH_XOR_EX(%2d -%d-> %2d) = %6.5f\n", __FILE__, __LINE__, da, r, db, p1);
			 printf("[%s:%d] ADP_RSH_XOR_TH(%2d -%d-> %2d) = %6.5f\n", __FILE__, __LINE__, da, r, db, p2);
			 printf("[%s:%d] ADP_RSH_XOR_AP(%2d -%d-> %2d) = %6.5f\n", __FILE__, __LINE__, da, r, db, p5);
			 printf("\n");
#endif
			 assert((p5 >= 0.0) && (p5 <= 1.0));
			 assert((p2 >= 0.0) && (p2 <= 1.0));
			 assert(p1 == p2);
		  }
		}
	 }
  }
  adp_rsh_xor_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Main function of ADP-RSH-XOR tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  test_adp_rsh_xor_alloc();
  test_adp_rsh_xor_sf();
  if(WORD_SIZE < 6) {
	 test_adp_rsh_xor();
  }
  return 0;
}
