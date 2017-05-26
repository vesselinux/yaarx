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
 * \file  adp-tea-f-fk-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-tea-f-fk.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_H
#include "adp-tea-f-fk.hh"
#endif

void test_adp_f_fk_v2_vs_adp_f_fk_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT;
  uint32_t k0 = random32() & MASK;;
  uint32_t k1 = random32() & MASK;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t da = 0; da < ALL_WORDS; da++) {
		  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
			 double p1 = adp_f_fk_v2(da, dd, k0, k1, delta, lsh_const, rsh_const);
			 double p2 = adp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
			 printf("\r%d %d %f %f", lsh_const, rsh_const, p1, p2);
			 fflush(stdout);
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

			 assert(p1 == p2);
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_fk_v2_vs_adp_f_fk_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		  for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
			 for(uint32_t da = 0; da < ALL_WORDS; da++) {
				for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
				  double p1 = adp_f_fk_v2(da, dd, k0, k1, delta, lsh_const, rsh_const);
				  double p2 = adp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
				  printf("\r %d %d %f %f", l, r, p1, p2);
				  fflush(stdout);
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

				  assert(p1 == p2);
				}
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 
  const uint32_t n = WORD_SIZE;
  double p_the = 0.0;

  uint32_t dx = random32() & MASK; //0xF08
  uint32_t dy = random32() & MASK;
  uint32_t k0 = random32() & MASK;
  uint32_t k1 = random32() & MASK;

  p_the = adp_f_fk(n, dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] n %d, key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] ADP_F_FK(%d %d | %8X %8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, delta, k0, k1, dx, dy, p_the, log2(p_the));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
  assert(p_the == p_the);		  // avoid compilation warnings
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_adp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 

  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dy = random32() & MASK; 

  uint32_t new_dx = 0;
  uint32_t max_dx = 0;

  double p_the = max_dx_adp_f_fk(WORD_SIZE, &new_dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_max = max_dx_adp_f_fk_exper(&max_dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = adp_f_fk_exper(new_dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] n %2d key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, new_dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, new_dx, dy, p_exp, log2(p_exp));
  printf("[%s:%d] P_MAX(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, max_dx, dy, p_max, log2(p_max));
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

  assert(p_the == p_exp);
  assert(p_the == p_max);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_key_dx_adp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 
  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dx = random32() & MASK;
  uint32_t dy = random32() & MASK; 

  double p_the = max_key_dx_adp_f_fk(WORD_SIZE, &dx, dy, &k0, &k1, delta, lsh_const, rsh_const);
  double p_exp = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, k0, k1, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, k0, k1, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_dy_adp_f_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT & MASK; 

  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dx = random32() & MASK;
  uint32_t dy = random32() & MASK; 

  double p_the = max_dx_dy_adp_f_fk(WORD_SIZE, &dx, &dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, k0, k1, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, k0, k1, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}


// 
// Compare adp_f_fk_dx with the experimental estimation
// over all input and output differences da, dd, all keys k0 k1, all shift constants R, L and fixed delta
// Tests also if this is the max
// 
void test_max_adp_f_fk_dx_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = DELTA_INIT & MASK;
  //  const uint32_t n = WORD_SIZE;

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
				double p1 = max_dx_adp_f_fk(WORD_SIZE, &max_da, dd, k0, k1, delta, lsh_const, rsh_const);
				double p2 = adp_f_fk_exper(max_da, dd, k0, k1, delta, lsh_const, rsh_const);
				double p3 = max_dx_adp_f_fk_exper(&max_da_exper, dd, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK_TESTS
				if((p1 != p2) || (p1 != p3)) {
				  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx (%8X %f| %8X %f) dy %8X\n", __FILE__, __LINE__, k0, k1, delta, l, r, max_da, p1, max_da_exper, p3, dd);
				}
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
				assert(p1 == p2);
				assert(p1 == p3);
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_fk_vs_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t delta = DELTA_INIT; 
  const uint32_t n = WORD_SIZE;

  uint32_t k0 = random32() & MASK; 
  uint32_t k1 = random32() & MASK; 
  uint32_t dx = random32() & MASK;
  uint32_t dy = random32() & MASK; 

  double p_the = adp_f_fk(n, dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] p_the(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] p_exp(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare adp_f_fk (fixed key) with the experimental estimation
// over all input and output differences da, dd, all keys k0 k1, all shift constants R, L and fixed delta
// 
void test_adp_f_fk_vs_exper_all()
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
				  double p1 = adp_f_fk(n, da, dd, k0, k1, delta, lsh_const, rsh_const);
				  double p2 = adp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK_TESTS
				  if(p1 != p2) {
					 printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X, dy %8X\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const, da, dd);
				  }
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
				  assert(p1 == p2);
				}
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare adp_f_fk (fixed key) with the experimental estimation
// over all input and output differences da, dd, all shift constants R, L and 
// fixed delta and keys k0, k1
// 
void test_adp_f_fk_vs_exper_all_shconst_and_diffs()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = random32() & MASK;//DELTA_INIT;
  uint32_t k0 = random32() & MASK;
  uint32_t k1 = random32() & MASK;
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
		for(uint32_t da = 0; da < ALL_WORDS; da++) {
		  for(uint32_t dd = 0; dd < ALL_WORDS; dd++) {
			 double p1 = adp_f_fk(n, da, dd, k0, k1, delta, lsh_const, rsh_const);
			 double p2 = adp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK_TESTS
			 if(p1 != p2) {
				printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X, dy %8X\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const, da, dd);
			 }
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
			 assert(p1 == p2);
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare adp_f_fk (fixed key) with the experimental estimation
// over all all shift constants R, L and fixed input and output differences da, dd and
// fixed delta and keys k0, k1
// 
void test_adp_f_fk_vs_exper_all_shconst()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t delta = random32() & MASK;//DELTA_INIT;
  uint32_t k0 = random32() & MASK;
  uint32_t k1 = random32() & MASK;
  uint32_t da = random32() & MASK;
  uint32_t dd = random32() & MASK;
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
		double p1 = adp_f_fk(n, da, dd, k0, k1, delta, lsh_const, rsh_const);
		double p2 = adp_f_fk_exper(da, dd, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK_TESTS
		if(p1 != p2) {
		  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X, dy %8X\n", __FILE__, __LINE__, k0, k1, delta, lsh_const, rsh_const, da, dd);
		}
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
		assert(p1 == p2);
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dy_adp_f_fk()
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

  double p_the = max_dy_adp_f_fk(WORD_SIZE, dx, &dy, k0, k1, delta, lsh_const, rsh_const);
  double p_exp = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);
  double p_max = max_dy_adp_f_fk_exper(dx, &dy, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
  printf("[%s:%d] n %2d key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
  printf("[%s:%d] P_MAX(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_max, log2(p_max));
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

  assert(p_the == p_exp);
  assert(p_the == p_max);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_all_dy_adp_f_fk()
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

  uint64_t* x_cnt = (uint64_t *)calloc((size_t)ALL_WORDS, sizeof(uint64_t));
  if(x_cnt == NULL) {
	 printf("[%s:%d] ERROR: Bad calloc. Not enough memory. Exiting...\n", __FILE__, __LINE__);
	 exit(1);
  }

  double p_the = all_dy_adp_f_fk(WORD_SIZE, dx, &dy, k0, k1, delta, lsh_const, rsh_const, x_cnt);

  for(uint32_t i = 0; i < ALL_WORDS; i++) {

	 dy = i;
	 p_the = (double)x_cnt[i] / (double)ALL_WORDS;
	 double p_exp = adp_f_fk_exper(dx, dy, k0, k1, delta, lsh_const, rsh_const);

#if 1//DEBUG_ADP_TEA_F_FK_TESTS
	 if(p_the != p_exp) {
		printf("[%s:%d] n %2d key %8X %8X, delta %8X, L %d, R %d\n", __FILE__, __LINE__, WORD_SIZE, k0, k1, delta, lsh_const, rsh_const);
		printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
		printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
	 }
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

	 assert(p_the == p_exp);
  }
  free(x_cnt);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare max_dy_adp_f_fk with the experimental estimation
// over all input and output XOR differences da, dd, and
// over all keys k0 k1, all shift constants R, L and fixed delta
// Tests also if this is the max
// 
void test_max_dy_adp_f_fk_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE < 9);
  uint32_t delta = DELTA_INIT & MASK;
  //  const uint32_t n = WORD_SIZE;

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
			 //			 for(uint32_t da = 0; da < ALL_WORDS; da++) 
			 uint32_t max_dd = 0;
			 uint32_t max_dd_exper = 0;
			 for(uint32_t da = 0; da < ALL_WORDS; da++) {
				double p1 = max_dy_adp_f_fk(WORD_SIZE, da, &max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p2 = adp_f_fk_exper(da, max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p3 = max_dy_adp_f_fk_exper(da, &max_dd_exper, k0, k1, delta, lsh_const, rsh_const);
#if DEBUG_ADP_TEA_F_FK_TESTS
				printf("\r[%s:%d] %d %d %f %f %f %8X %8X -> %8X", __FILE__, __LINE__, l, r, p1, p2, p3, da, max_dd, max_dd_exper);
				fflush(stdout);
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
#if DEBUG_ADP_TEA_F_FK_TESTS
				if((p1 != p2) || (p1 != p3)) {
				  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X dy (%8X %f| %8X %f)\n", __FILE__, __LINE__, k0, k1, delta, l, r, da, max_dd, p1, max_dd_exper, p3);
				}
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
				assert(p1 == p2);
				assert(p1 == p3);
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_dy_adp_f_fk_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE < 9);
  uint32_t delta = DELTA_INIT & MASK;
  //  const uint32_t n = WORD_SIZE;

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
			 uint32_t max_dd = 0;
			 uint32_t max_dd_exper = 0;
			 for(uint32_t da = 0; da < ALL_WORDS; da++) {
				double p1 = max_dx_dy_adp_f_fk(WORD_SIZE, &max_da, &max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p2 = adp_f_fk_exper(max_da, max_dd, k0, k1, delta, lsh_const, rsh_const);
				double p3 = max_dx_dy_adp_f_fk_exper(&max_da_exper, &max_dd_exper, k0, k1, delta, lsh_const, rsh_const);

#if DEBUG_ADP_TEA_F_FK_TESTS
				printf("\r[%s:%d] %d %d %8X %8X | %f %f %f %8X %8X %8X %8X", __FILE__, __LINE__, l, r, k0, k1, p1, p2, p3, max_da, max_da_exper, max_dd, max_dd_exper);
				fflush(stdout);
#if DEBUG_ADP_TEA_F_FK_TESTS

#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS
				if((p1 != p2) || (p1 != p3)) {
				  printf("[%s:%d] key %8X %8X, delta %8X, L %d, R %d, dx %8X dy (%8X %f| %8X %f)\n", __FILE__, __LINE__, k0, k1, delta, l, r, da, max_dd, p1, max_dd_exper, p3);
				}
#endif  // #if DEBUG_ADP_TEA_F_FK_TESTS

				assert(p1 == p2);
				assert(p1 == p3);
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X ", __FILE__, __LINE__, WORD_SIZE, MASK);
  printf("TEA_LSH_CONST = %d, TEA_RSH_CONST = %d\n", TEA_LSH_CONST, TEA_RSH_CONST);
  srandom(time(NULL));

  test_adp_f_fk_v2_vs_adp_f_fk_exper();
  test_adp_f_fk();
  test_max_dx_adp_f_fk();
  test_max_key_dx_adp_f_fk();
  test_max_dx_dy_adp_f_fk();
  test_adp_f_fk_vs_exper();
  test_adp_f_fk_vs_exper_all_shconst_and_diffs();
  test_adp_f_fk_vs_exper_all_shconst();
  test_max_dy_adp_f_fk();
  test_all_dy_adp_f_fk();

  if(WORD_SIZE < 6) {
	 test_adp_f_fk_v2_vs_adp_f_fk_exper_all();
	 test_max_adp_f_fk_dx_vs_exper_all();
	 test_adp_f_fk_vs_exper_all();
	 test_max_dy_adp_f_fk_vs_exper_all();
	 test_max_dx_dy_adp_f_fk_vs_exper_all();
  }
  return 0;
}

