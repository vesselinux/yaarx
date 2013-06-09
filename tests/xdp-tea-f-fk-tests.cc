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
 * \file  xdp-tea-f-fk-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for xdp-tea-f-fk.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef XDP_TEA_F_FK_H
#include "xdp-tea-f-fk.hh"
#endif

void test_xdp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 
  const uint32_t n = WORD_SIZE;

  uint32_t dx = random32() & MASK;
  uint32_t dy = random32() & MASK;

  uint32_t k0 = random32() & MASK;
  uint32_t k1 = random32() & MASK;

  double p_the = xdp_f_fk(n, dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = xdp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_XDP_TEA_F_FK_TESTS
  printf("[%s:%d] n %d, key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] p_the(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] p_exp(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_XDP_TEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_f_fk_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT;
  const uint32_t n = WORD_SIZE;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		if(l >= r)
		  continue;
		if(WORD_SIZE < (r * 2))			  // assert(n >= (rsh_const * 2));
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		  for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
			 for(uint32_t da = 0; da < ALL_WORDS; da++) {
				for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
				  double p1 = xdp_f_fk(n, da, dd, k0, k1, delta, lsh_const, rsh_const);
				  double p2 = xdp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // DEBUG
				  printf("\r[%s:%d] %d %d %f %f %8X -> %8X", __FILE__, __LINE__, l, r, p1, p2, da, dd);
				  fflush(stdout);
#endif
				  if(p1 != p2) {
					 printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X, dy %8X\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const, da, dd);
				  }
				  assert(p1 == p2);
				}
			 }
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_xdp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 

  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dx = 0;
  uint32_t dy = 0;

  printf("[%s:%d] n %2d key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);

  double p_the = max_dx_xdp_f_fk(WORD_SIZE, &dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = xdp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_XDP_TEA_F_FK_TESTS
  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_XDP_TEA_F_FK_TESTS

  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_xdp_f_fk_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT & MASK;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		if(l >= r)
		  continue;
		if(WORD_SIZE < (r * 2))			  // assert(n >= (rsh_const * 2));
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		  for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
			 uint32_t max_da = 0;
			 uint32_t max_da_exper = 0;
			 for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
				double p1 = max_dx_xdp_f_fk(WORD_SIZE, &max_da, dd, k0, k1, delta, lsh_const, rsh_const);
				double p2 = xdp_f_fk_exper(max_da, dd, k0, k1, delta, lsh_const, rsh_const);
				double p3 = max_xdp_f_fk_dx_exper(&max_da_exper, dd, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // DEBUG
				printf("\r[%s:%d] %d %d %f %f %f %8X %8X -> %8X", __FILE__, __LINE__, l, r, p1, p2, p3, max_da, max_da_exper, dd);
				fflush(stdout);
#endif
				if((p1 != p2) || (p1 != p3)) {
				  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx (%8X %f| %8X %f) dy %8X\n", __FILE__, __LINE__, k0, k1, delta, l, r, max_da, p1, max_da_exper, p3, dd);
				}
				assert(p1 == p2);
				assert(p1 == p3);
			 }
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_xdp_f_fk_vs_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT & MASK;

  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  assert(WORD_SIZE >= (rsh_const * 2));
  uint32_t k0 = random32() & MASK;
  uint32_t k1 = random32() & MASK;
  uint32_t max_da = random32() & MASK;
  uint32_t max_da_exper = random32() & MASK;
  uint32_t dd = random32() & MASK;
  double p1 = max_dx_xdp_f_fk(WORD_SIZE, &max_da, dd, k0, k1, delta, lsh_const, rsh_const);
  double p2 = xdp_f_fk_exper(max_da, dd, k0, k1, delta, lsh_const, rsh_const);
  double p3 = max_xdp_f_fk_dx_exper(&max_da_exper, dd, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // DEBUG
  printf("\r[%s:%d] %d %d %f %f %f %8X %8X -> %8X", __FILE__, __LINE__, lsh_const, rsh_const, p1, p2, p3, max_da, max_da_exper, dd);
  fflush(stdout);
#endif
  if((p1 != p2) || (p1 != p3)) {
	 printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx (%8X %f| %8X %f) dy %8X\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const, max_da, p1, max_da_exper, p3, dd);
  }
  printf("\n");
  assert(p1 == p2);
  assert(p1 == p3);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dy_xdp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 

  const uint32_t k0 = random32() & MASK; 
  const uint32_t k1 = random32() & MASK; 
  const uint32_t dx = random32() & MASK;
  uint32_t dy = 0;

  double p_the = max_dy_xdp_f_fk(WORD_SIZE, dx, &dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = xdp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_max = max_xdp_f_fk_dy_exper(dx, &dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_XDP_TEA_F_FK_TESTS
  printf("[%s:%d] n %2d key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
  printf("[%s:%d] P_MAX(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_max, log2(p_max));
#endif  // #if DEBUG_XDP_TEA_F_FK_TESTS
  assert(p_the == p_exp);
  assert(p_max == p_max);		  // to avoid compilation warnings
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare max_dy_xdp_f_fk with the experimental estimation
// over all input and output XOR differences da, dd, and
// over all keys k0 k1, all shift constants R, L and fixed delta
// Tests also if this is the max
// 
void test_max_dy_xdp_f_fk_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT & MASK;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		if(l >= r)
		  continue;
		if(WORD_SIZE < (r * 2))			  // assert(n >= (rsh_const * 2));
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		  for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
			 uint32_t max_dd = 0;
			 uint32_t max_dd_exper = 0;
			 for(uint32_t da = 0; da < ALL_WORDS; da++) {
				double p1 = max_dy_xdp_f_fk(WORD_SIZE, da, &max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p2 = xdp_f_fk_exper(da, max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p3 = max_xdp_f_fk_dy_exper(da, &max_dd_exper, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // DEBUG
				printf("\r[%s:%d] %d %d %f %f %f %8X %8X -> %8X", __FILE__, __LINE__, l, r, p1, p2, p3, da, max_dd, max_dd_exper);
				fflush(stdout);
#endif
				if((p1 != p2) || (p1 != p3)) {
				  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X dy (%8X %f| %8X %f)\n", __FILE__, __LINE__, k0, k1, delta, l, r, da, max_dd, p1, max_dd_exper, p3);
				}
				assert(p1 == p2);
				assert(p1 == p3);
			 }
		  }
		}
	 }
  }
  printf("OK\n");
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X ", __FILE__, __LINE__, WORD_SIZE, MASK);
  printf("TEA_LSH_CONST = %d, TEA_RSH_CONST = %d\n", TEA_LSH_CONST, TEA_RSH_CONST);
  srandom(time(NULL));

  test_xdp_f_fk();
  test_xdp_f_fk_vs_exper_all();
  test_max_dy_xdp_f_fk();
  test_max_dy_xdp_f_fk_vs_exper_all();
  test_max_dx_xdp_f_fk();
  test_max_dx_xdp_f_fk_vs_exper();
  test_max_dx_xdp_f_fk_vs_exper_all();
  return 0;
}
