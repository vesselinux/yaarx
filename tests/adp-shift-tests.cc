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
 * \file  adp-shift-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-shift.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif

// --- TESTS ---

void test_adp_lsh()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t da = xrandom() & MASK;
  uint32_t db = xrandom() & MASK;
  uint32_t l = xrandom() % WORD_SIZE;

  double p = adp_lsh_exper(da, db, l);
  double pp = adp_lsh(da, db, l);
  assert(pp == p);
  assert((p == 0.0) || (p == 1.0));

  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_lsh_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint64_t n = 1ULL << WORD_SIZE;
  for(uint32_t da = 0; da < n; da++) {
	 for(uint32_t db = 0; db < n; db++) {
		for(uint32_t l = 0; l < WORD_SIZE; l++) {

		  double p = adp_lsh_exper(da, db, l);
		  double pp = adp_lsh(da, db, l);
#if DEBUG_ADP_SHIFT_TESTS
		  printf("[%s:%d] ADP_LSH_TH[(%3d -%2d-> %3d)] = %6.5f\n", 
					__FILE__, __LINE__, da, l, db, pp);
		  printf("[%s:%d] ADP_LSH_EX[(%3d -%2d-> %3d)] = %6.5f\n", 
					__FILE__, __LINE__, da, l, db, p);
		  printf("\n");
#endif
		  assert(pp == p);
		  assert((p == 0.0) || (p == 1.0));
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_rsh()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t da = xrandom() & MASK; // 9
  uint32_t r  = xrandom() % WORD_SIZE; // 3
  uint32_t db = xrandom() & MASK; // 15
  double pp = adp_rsh(da, db, r);
  double p = adp_rsh_exper(da, db, r);
#if DEBUG_ADP_SHIFT_TESTS
  printf("[%s:%d] ADP_RSH_TH[(%3d -%2d-> %3d)] = %6.5f\n", 
			__FILE__, __LINE__, da, r, db, pp);
  printf("[%s:%d] ADP_RSH_EX[(%3d -%2d-> %3d)] = %6.5f\n", 
			__FILE__, __LINE__, da, r, db, p);
  printf("\n");
#endif
  assert(pp == p);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_rsh_all()
{
  uint64_t n = 1ULL << WORD_SIZE;
  for(uint32_t da = 0; da < n; da++) {
	 for(uint32_t db = 0; db < n; db++) {
		for(uint32_t r = 0; r < WORD_SIZE; r++) {

		  double pp = adp_rsh(da, db, r);
		  double p = adp_rsh_exper(da, db, r);
#if DEBUG_ADP_SHIFT_TESTS
		  printf("[%s:%d] ADP_RSH_TH[(%3d -%2d-> %3d)] = %6.5f\n", 
					__FILE__, __LINE__, da, r, db, pp);
		  printf("[%s:%d] ADP_RSH_EX[(%3d -%2d-> %3d)] = %6.5f\n", 
					__FILE__, __LINE__, da, r, db, p);
		  printf("\n");
#endif
		  assert(pp == p);
		  assert((p >= 0.0) && (p <= 1.0));
		  assert((pp >= 0.0) && (pp <= 1.0));

		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  srandom(time(NULL));
  test_adp_lsh();
  test_adp_lsh_all();
  test_adp_rsh();
  test_adp_rsh_all();
  //  adp_lsh_program();
  //  adp_rsh_program();
  return 0;
}
