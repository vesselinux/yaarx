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
 * \file  xdp-and-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for \f$\mathrm{xdp}^{\wedge}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif

void test_xdp_and_sf()
{
  uint32_t A[2][2][2] = {{{0}}};
  xdp_and_sf(A);
}

void test_xdp_and()
{

  uint32_t A[2][2][2] = {{{0}}};

  uint32_t da = xrandom() & MASK;
  uint32_t db = xrandom() & MASK;
  uint32_t dc = xrandom() & MASK;

#if 0
  xdp_and_sf(A);
#else
  xdp_and_bf(A);
#endif

#if 0									  // DEBUG
  for(uint32_t a = 0; a < 8; a++) {
	 uint32_t i = (a >> 2) & 1;
	 uint32_t j = (a >> 1) & 1;
	 uint32_t k = (a >> 0) & 1;
	 printf("A%d%d%d[%2d] ", i, j, k, A[i][j][k]);
  }
  printf("\n");
#endif

  double p1 = xdp_and(A, da, db, dc);
  double p2 = xdp_and_exper(da, db, dc);

  assert((p1 >= 0.0) && (p1 <= 1.0));
  assert((p2 >= 0.0) && (p2 <= 1.0));

  printf("[%s:%d] XDP_AND_TH[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p1);
  printf("[%s:%d] XDP_AND_EX[(%8X,%8X)->%8X] = %6.5f\n", 
			__FILE__, __LINE__, da, db, dc, p2);

  assert(p1 == p2);
}

void test_xdp_and_all()
{

  uint32_t A[2][2][2] = {{{0}}};

#if 0
  xdp_and_sf(A);
#else
  xdp_and_bf(A);
#endif

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {
		for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {

		  double p1 = xdp_and(A, da, db, dc);
		  double p2 = xdp_and_exper(da, db, dc);
		  int w = xdp_and_closed(da, db, dc);
		  double p3 = std::pow(2, w);

		  assert((p1 >= 0.0) && (p1 <= 1.0));
		  assert((p2 >= 0.0) && (p2 <= 1.0));

		  printf("[%s:%d] XDP_AND_TH[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p1);
		  printf("[%s:%d] XDP_AND_EX[(%8X,%8X)->%8X] = %6.5f\n", 
					__FILE__, __LINE__, da, db, dc, p2);
		  printf("[%s:%d] XDP_AND_CL[(%8X,%8X)->%8X] = %6.5f\n\n", 
					__FILE__, __LINE__, da, db, dc, p3);

		  assert(p1 == p2);
		  assert(p1 == p3);
		}
	 }
  }
}

void test_xdp_and_fbool()
{
  for(uint32_t a = 0; a < 8; a++) {
	 uint32_t x = (a >> 2) & 1;
	 uint32_t y = (a >> 1) & 1;
	 uint32_t z = (a >> 0) & 1;

	 uint32_t not_x = (~x) & 1;
	 uint32_t not_y = (~y) & 1;
	 uint32_t not_z = (~z) & 1;

	 //	 uint32_t f = 4 * (not_x & not_y & not_z);
	 //	 uint32_t f = 2 * (~(not_x & not_y) & 1);
	 uint32_t f = (4 * (not_x & not_y & not_z)) + (2 * (~(not_x & not_y) & 1));

	 printf("%d %d %d | %d\n", x, y, z, f);

  }
}

// {--- MORUS tests ---
void test_anddp_and_all()

{
  for(uint32_t x = 0; x < ALL_WORDS; x++) {
	 for(uint32_t y = 0; y < ALL_WORDS; y++) {
		for(uint32_t da = 0; da < ALL_WORDS; da++) {
		  for(uint32_t db = 0; db < ALL_WORDS; db++) {
			 uint32_t xx = x & da;
			 uint32_t yy = y & db;
			 uint32_t z = x & y;
			 uint32_t zz = xx & yy;
			 uint32_t dz = z & ~zz;
			 printf("[%s:%d] dz %X\n", __FILE__, __LINE__, dz);

		  }
		}
	 }
  }
}


// --- MORUS tests ---}

/**
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));

  // {--- MORUS tests ---
  //  test_anddp_and_all();
  // --- MORUS tests ---}

  //test_xdp_and();
  //  test_xdp_and_fbool();
  //  test_xdp_and_sf();
  test_xdp_and_all();
  return 0;
}
