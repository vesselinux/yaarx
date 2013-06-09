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
 * \file  eadp-tea-f-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for eadp-tea-f.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef MAX_ADP_XOR3_SET_H
#include "max-adp-xor3-set.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef EADP_TEA_F_H
#include "eadp-tea-f.hh"
#endif

// 
// Experimentally verifies the following fact:
// 
// For every da, db: adp_lsh(da->db) != 0.0, dc: adp_rsh(da->dc) != 0.0 | adp_xor3(da,db,dc->dd) != 0.0 => eadp_tea_f(da -> dd) != 0.0
// 
// Note that the reverse is not necessarily true ie. 
//
// if eadp_tea_f(da -> dd) != 0.0, there may exist dc: adp_rsh(da->dc) != 0.0 such that adp_xor3(da,db,dc->dd) == 0.0
// 
void test_adp_xor3_vs_eadp_tea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t cnt_xor3 = 0;			  // count non-zero adp-xor3
  uint32_t cnt_f = 0;			     // count non-zero adp-f

  gsl_matrix* A[2][2][2][2];
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {

	 // one diff after LSH
	 uint32_t db = LSH(da, TEA_LSH_CONST);

	 // four diffs after RSH
	 uint32_t dx[4] = {0, 0, 0, 0};
	 adp_rsh_odiffs(dx, da, TEA_RSH_CONST);

	 for(int i = 0; i < 4; i++) {
		uint32_t dc = dx[i];
		double p_rsh = adp_rsh(da, dc, TEA_RSH_CONST);

		// continue only if dc holds with non-zero probability
		if(p_rsh != 0.0) {
		  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
			 double p_xor3 = adp_xor3(A, da, db, dc, dd);
			 assert((p_xor3 >= 0.0) && (p_xor3 <= 1.0));
			 double p_f = eadp_tea_f(A, da, dd, &p_f, TEA_LSH_CONST, TEA_RSH_CONST);
			 // adp_xor3(da,db,dc->dd) != 0.0 => eadp_tea_f(da -> dd) != 0.0
			 if(p_xor3 != 0.0) {
#if 0									  // DEBUG
				printf("[%s:%d] ADP_XOR3[(%8X,%8X,%8X)->%8X] = %f = 2^%4.2f| %10lld\n", 
						 __FILE__, __LINE__, da, db, dc, dd, p_xor3, log2(p_xor3), cnt_xor3);
#endif
#if 1									  // DEBUG
				if(p_f == 0.0) {
				  printf("[%s:%d] %8X %8X %f %f %f\n", __FILE__, __LINE__, da, dd, p_f, p_rsh, p_xor3);
				  cnt_f++;
				}
#endif
				assert(p_f != 0.0);
				cnt_xor3++;
			 }
		  }
		}
	 }
  }
  adp_xor3_free_matrices(A);
#if DEBUG_EADP_TEA_F_TESTS
  printf("[%s:%d] nz_xor3 = %d, z_f = %d\n", __FILE__, __LINE__, cnt_xor3, cnt_f);
#endif  // #if DEBUG_EADP_TEA_F_TESTS
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_eadp_tea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  uint32_t dx = random32() & MASK;
  uint32_t dy = random32() & MASK;

  double p = eadp_tea_f(A, dx, dy, &p, lsh_const, rsh_const);
#if DEBUG_EADP_TEA_F_TESTS
  printf("[%s:%d] %2d %2d | EEADP_TEA_F(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p);
#endif  // #if DEBUG_EADP_TEA_F_TESTS

  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_eadp_tea_f_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const;
  uint32_t rsh_const;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(lsh_const = 0; lsh_const < WORD_SIZE; lsh_const++) {
	 for(rsh_const = 0; rsh_const < WORD_SIZE; rsh_const++) {
		if((lsh_const + rsh_const) > WORD_SIZE)
		  continue;

		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
			 double p1 = eadp_tea_f(A, dx, dy, &p1, lsh_const, rsh_const);
			 double p2 = eadp_tea_f_exper(dx, dy, lsh_const, rsh_const);
#if DEBUG_EADP_TEA_F_TESTS
			 printf("[%s:%d] %2d %2d | EADP_TEA_F_THE(%2d -> %2d) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p1);
			 printf("[%s:%d] %2d %2d | EADP_TEA_F_EXP(%2d -> %2d) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p2);
#endif  // #if DEBUG_EADP_TEA_F_TESTS
			 assert(p1 == p2);
		  }
		}
	 }
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_eadp_tea_f_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const;
  uint32_t rsh_const;

  // init matrices
  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  for(lsh_const = 0; lsh_const < WORD_SIZE; lsh_const++) {
	 for(rsh_const = 0; rsh_const < WORD_SIZE; rsh_const++) {
		if((lsh_const + rsh_const) > WORD_SIZE)
		  continue;

		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  uint32_t dy_the = 0;
		  double p_the = max_eadp_tea_f(A, dx, &dy_the, &p_the, lsh_const, rsh_const);
		  uint32_t dy_exp = 0;
		  double p_exp = max_eadp_tea_f_exper(A, dx, &dy_exp, &p_exp, lsh_const, rsh_const);
#if DEBUG_EADP_TEA_F_TESTS
		  printf("[%s:%d] %d %d | MAX_EADP_TEA_F_THE(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy_the, p_the);
		  printf("[%s:%d] %d %d | MAX_EADP_TEA_F_EXP(%8X -> %8X) = %6.5f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy_exp, p_exp);
#endif  // #if DEBUG_EADP_TEA_F_TESTS
		  assert(p_the == p_exp);

		  double p_eadp = eadp_tea_f(A, dx, dy_the, &p_eadp, lsh_const, rsh_const);
		  if(p_the != p_eadp) {
			 printf("[%s:%d] WARNING:     p_eadp = 2^%f !=  p_max_eadp = 2^%f\n", __FILE__, __LINE__, log2(p_eadp), log2(p_the));
		  }
		  //		  printf("[%s:%d] %d %d | MAX_EADP_TEA_F_TH2(%8X -> %8X) = %31.30f = 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, p2, log2(p2));
		  assert(p_the == p_eadp);
		}
	 }
  }
  adp_xor3_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/**
 * Main function of EADP-TEA-F tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  assert(WORD_SIZE <= 10);
  srandom(time(NULL));

  test_adp_xor3_vs_eadp_tea_f();
  test_eadp_tea_f();
  if(WORD_SIZE <= 4) {
	 test_eadp_tea_f_vs_exper_all();
  }
  test_max_eadp_tea_f_is_max();
  return 0;
}

