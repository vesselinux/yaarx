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
 * \file  adp-mul-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xor.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_MUL_H
#include "adp-mul.hh"
#endif

void test_adp_mul()
{
  uint32_t x = random32() & MASK;
  uint32_t y = random32() & MASK;
  uint32_t z = MUL(x, y);

  printf("[%s:%d] %d %d = %d\n", __FILE__, __LINE__, x, y, z);

  uint32_t da = random32() & MASK;
  uint32_t db = random32() & MASK;
  uint32_t dc = random32() & MASK;
  assert(WORD_SIZE <= 10);

  uint64_t N = (1ULL << WORD_SIZE);
  for(da = 0; da < N; da++) {
	 for(db = 0; db < N; db++) {
		for(dc = 0; dc < N; dc++) {
		  double p1 = adp_mul(da, db, dc);
		  double p2 = adp_mul_exper(da, db, dc);
		  printf("[%s:%d] ADP_MUL_TH[(%d,%d)->%d] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p1, log2(p1));
		  printf("[%s:%d] ADP_MUL_EX[(%d,%d)->%d] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p2, log2(p2));
		  assert(p1 == p2);
		}
	 }
  }
}

/**
 * Main function of ADP-XOR tests.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  assert(WORD_SIZE <= 10);
  test_adp_mul();
  return 0;
}
