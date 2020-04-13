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
 * \file  adp-xtea-f-fk-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-xtea-f-fk.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef MAX_ADP_XOR_H
#include "max-adp-xor.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif
#ifndef MAX_ADP_XOR_FI_H
#include "max-adp-xor-fi.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef ADP_XTEA_F_FK_H
#include "adp-xtea-f-fk.hh"
#endif

void test_adp_xtea_f_lxr()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = xrandom() & MASK; 

  double p_the = adp_xtea_f_lxr(n, dx, dy, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_lxr_exper(dx, dy, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xtea_f_lxr_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);
  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		uint32_t dx = xrandom() & MASK; // i
		uint32_t dy = xrandom() & MASK; // j
		double p_the = adp_xtea_f_lxr(n, dx, dy, lsh_const, rsh_const);
#if 1
		if(p_the) {
		  printf("[%s:%d] P_THE(%8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, dx, dy, p_the, log2(p_the));
		}
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// 
// Compare adp_xtea_f_lxr() with the experimental estimation
// over all input and output differences da, dd and all shift constants R, L
// 
void test_adp_xtea_f_lxr_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  const uint32_t n = WORD_SIZE;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		if(l >= r)
		  continue;
		if(n < (2*r))
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
		  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
			 double p_the = adp_xtea_f_lxr(n, dx, dy, lsh_const, rsh_const);
			 double p_exp = adp_xtea_f_lxr_exper(dx, dy, lsh_const, rsh_const);
#if 1
			 printf("\r[%s:%d] %d %d %8X -> %8X %f %f", __FILE__, __LINE__, l, r, dx, dy, p_the, p_exp);
			 fflush(stdout);
#endif
#if DEBUG_ADP_XTEA_F_FK_TESTS
			 if(p_the != p_exp) {
				printf("[%s:%d] L %d, R %d, %8X -> %8X: 2^%f != 2^%f\n", __FILE__, __LINE__, lsh_const, rsh_const, dx, dy, log2(p_the), log2(p_exp));
			 }
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
			 assert(p_exp == p_the);
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xtea_f_approx()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = xrandom() & MASK; 
  uint32_t k = xrandom() & MASK;
  uint32_t delta = 0;

  double p_approx = adp_xtea_f_approx(n, A, dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%d] P_APROX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_approx, log2(p_approx));
  printf("[%s:%d] P_EXPER(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_approx == p_approx);
  assert(p_exp == p_exp);		  // to avoiod compilation warning
  adp_xor_fixed_input_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xtea_f_approx_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

  uint32_t delta = 0;
  const uint32_t n = WORD_SIZE;

  for(uint32_t k = 0; k < ALL_WORDS; k++) {
	 for(uint32_t l = 0; l < WORD_SIZE; l++) {
		for(uint32_t r = 0; r < WORD_SIZE; r++) {
		  if((l + r) > WORD_SIZE)
			 continue;
		  if((l == 0) || (r == 0))
			 continue;
		  if(l >= r)
			 continue;
		  if(n < (2*r))
			 continue;
		  uint32_t lsh_const = l;
		  uint32_t rsh_const = r;
		  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
			 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
				double p_approx = adp_xtea_f_approx(n, A, dx, dy, k, delta, lsh_const, rsh_const);
				double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
				if((p_exp != p_approx) && ((p_exp == 0.0) || (p_approx == 0.0)) ) {
				  printf("\n[%s:%d] P_APROX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_approx, log2(p_approx));
				  printf("[%s:%d] P_EXPER(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
				}
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
				assert(p_approx == p_approx);
				assert(p_exp == p_exp);		  // to avoiod compilation warning
			 }
		  }
		}
	 }
  }
  adp_xor_fixed_input_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xtea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = xrandom() & MASK; 
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  double p_the = adp_xtea_f(n, dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  if(p_the) {
	 printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
	 printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
  }
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_xtea_f_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;

  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
	 for(uint32_t k = 0; k < ALL_WORDS; k++) {
		for(uint32_t l = 0; l < WORD_SIZE; l++) {
		  for(uint32_t r = 0; r < WORD_SIZE; r++) {
			 if((l + r) > WORD_SIZE)
				continue;
			 if((l == 0) || (r == 0))
				continue;
			 if(l >= r)
				continue;
			 if(n < (2*r))
				continue;
			 uint32_t lsh_const = l;
			 uint32_t rsh_const = r;
			 for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
				for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
				  double p_the = adp_xtea_f(n, dx, dy, k, delta, lsh_const, rsh_const);
				  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
				  printf("\r[%s:%d] (%8X %8X | %8X -> %8X) = %f %f", __FILE__, __LINE__, delta, k, dx, dy, p_the, p_exp);
				  fflush(stdout);
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
				  if(p_exp != p_the) {
					 printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
					 printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
				  }
				  assert(p_the == p_exp);
				}
			 }
		  }
		}
	 }
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dy_adp_xtea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = 0;
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  double p_the = max_dy_adp_xtea_f(n, dx, &dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_adp_xtea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = 0;
  uint32_t dy = xrandom() & MASK;
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  double p_the = max_dx_adp_xtea_f(n, &dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%s:%d] ? -> %8X\n", __FILE__, __FUNCTION__, __LINE__, dy);
  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dy_adp_xtea_f_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = 0;
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  uint32_t dyy = 0;

  double p_the = max_dy_adp_xtea_f(n, dx, &dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
  double p_max = max_dy_adp_xtea_f_exper(dx, &dyy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
  printf("[%s:%d] P_MAX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dyy, p_max, log2(p_max));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  assert(p_the == p_max);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_adp_xtea_f_is_max()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dx = 0;
  uint32_t dy = xrandom() & MASK;
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  uint32_t dxx = 0;
  double p_the = max_dx_adp_xtea_f(n, &dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
  double p_max = max_dx_adp_xtea_f_exper(&dxx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
  printf("[%s:%d] P_MAX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dxx, dy, p_max, log2(p_max));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  assert(p_the == p_max);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dy_adp_xtea_f_is_max_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;

  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
	 for(uint32_t k = 0; k < ALL_WORDS; k++) {
		for(uint32_t l = 0; l < WORD_SIZE; l++) {
		  for(uint32_t r = 0; r < WORD_SIZE; r++) {
			 if((l + r) > WORD_SIZE)
				continue;
			 if((l == 0) || (r == 0))
				continue;
			 if(l >= r)
				continue;
			 if(n < (2*r))
				continue;
			 uint32_t lsh_const = l;
			 uint32_t rsh_const = r;
			 for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
				uint32_t dy = 0;
				uint32_t dy_max = 0;
				double p_the = max_dy_adp_xtea_f(n, dx, &dy, k, delta, lsh_const, rsh_const);
				double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
				double p_max = max_dy_adp_xtea_f_exper(dx, &dy_max, k, delta, lsh_const, rsh_const);
#if 1
				printf("\r[%s:%d] (%8X %8X | %8X -> %8X (%8X)) = %f %f %f", __FILE__, __LINE__, delta, k, dx, dy, dy_max, p_the, p_exp, p_max);
				fflush(stdout);
#endif
#if DEBUG_ADP_XTEA_F_FK_TESTS
				if((p_exp != p_the) || (p_the != p_max)) {
				  printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
				  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
				  printf("[%s:%d] P_MAX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy_max, p_max, log2(p_max));
				}
#endif
				assert(p_the == p_exp);
				assert(p_the == p_max);
			 }
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_dx_adp_xtea_f_is_max_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;

  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
	 for(uint32_t k = 0; k < ALL_WORDS; k++) {
		for(uint32_t l = 0; l < WORD_SIZE; l++) {
		  for(uint32_t r = 0; r < WORD_SIZE; r++) {
			 if((l + r) > WORD_SIZE)
				continue;
			 if((l == 0) || (r == 0))
				continue;
			 if(l >= r)
				continue;
			 if(n < (2*r))
				continue;
			 uint32_t lsh_const = l;
			 uint32_t rsh_const = r;
			 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
				uint32_t dx = 0;
				uint32_t dx_max = 0;
				double p_the = max_dx_adp_xtea_f(n, &dx, dy, k, delta, lsh_const, rsh_const);
				double p_exp = adp_xtea_f_exper(dx, dy, k, delta, lsh_const, rsh_const);
				double p_max = max_dx_adp_xtea_f_exper(&dx_max, dy, k, delta, lsh_const, rsh_const);
#if 1
				printf("\r[%s:%d] (%8X %8X | %8X (%8X) -> %8X) = %f %f %f", __FILE__, __LINE__, delta, k, dx, dx_max, dy, p_the, p_exp, p_max);
				fflush(stdout);
#endif
#if DEBUG_ADP_XTEA_F_FK_TESTS
				if((p_exp != p_the) || (p_the != p_max)) {
				  printf("[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
				  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
				  printf("[%s:%d] P_MAX(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx_max, dy, p_max, log2(p_max));
				}
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
				assert(p_the == p_exp);
				assert(p_the == p_max);
			 }
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

double test_first_nz_adp_xtea_f()
{
  //  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  // init A
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // init AA (A for adp_xor with one fixed input)
  gsl_matrix* AA[2][2][2];
  adp_xor_fixed_input_alloc_matrices(AA);
  adp_xor_fixed_input_sf(AA);
  adp_xor_fixed_input_normalize_matrices(AA);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  uint32_t delta = 0;
  uint32_t key = xrandom() & MASK;
  uint32_t da = xrandom() & MASK;;
  uint32_t dd = 0;

  //  uint32_t cnt = 0;
  double p = first_nz_adp_xtea_f(A, AA, key, delta, da, &dd, lsh_const, rsh_const);
  uint32_t ninputs = (1U << 15);
  double p_approx = adp_xtea_f_approx(ninputs, da, dd, key, delta, lsh_const, rsh_const);
#if DEBUG_ADP_XTEA_F_FK_TESTS
  printf("[%s:%d] %8X | %8X -> %8X %f (2^%f) | (2^%f)\n", __FILE__, __LINE__, key, da, dd, p, log2(p), log2(p_approx));
  printf("[%s:%d] %8X | %8X -> %8X %f (2^%f)\n", __FILE__, __LINE__, key, da, dd, p, log2(p));
#endif  // DEBUG_ADP_XTEA_F_FK_TESTS
  assert(p_approx == p_approx); // to avoiod compilation warning

  gsl_vector_free(C);
  adp_xor_free_matrices(A);
  adp_xor_fixed_input_free_matrices(AA);
  return p;
  //  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_first_nz_adp_xtea_f_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE <= 8);
  // init A
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // init AA (A for adp_xor with one fixed input)
  gsl_matrix* AA[2][2][2];
  adp_xor_fixed_input_alloc_matrices(AA);
  adp_xor_fixed_input_sf(AA);
  adp_xor_fixed_input_normalize_matrices(AA);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  uint32_t n = WORD_SIZE;
  uint32_t delta = 0;//xrandom() & MASK;

  for(uint32_t l = 0; l < WORD_SIZE; l++) {
	 for(uint32_t r = 0; r < WORD_SIZE; r++) {
		if((l + r) > WORD_SIZE)
		  continue;
		if((l == 0) || (r == 0))
		  continue;
		if(l >= r)
		  continue;
		if(n < (2*r))
		  continue;
		uint32_t lsh_const = l;
		uint32_t rsh_const = r;
		for(uint32_t key = 0; key < WORD_SIZE; key++) {
		  for(uint32_t da = 0; da < WORD_SIZE; da++) {
			 uint32_t dd = 0;
			 double p = first_nz_adp_xtea_f(A, AA, key, delta, da, &dd, lsh_const, rsh_const);
			 printf("[%s:%d] %8X | %8X -> %8X %f (2^%f)\n", __FILE__, __LINE__, key, da, dd, p, log2(p));
		  }
		}
	 }
  }
  gsl_vector_free(C);
  adp_xor_free_matrices(A);
  adp_xor_fixed_input_free_matrices(AA);
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// test over random inputs
void test_first_nz_adp_xtea_f_random()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t N = (1U << 10);
  uint32_t cnt_zero = 0;
  for(uint32_t i = 0; i < N; i++) {
	 double p = test_first_nz_adp_xtea_f();
	 if(p == 0) {
		cnt_zero++;
	 }
  }
  double percent = ((double)cnt_zero / (double)N) * 100.0;
  printf("[%s:%d] Zero rate: %5d / %5d = %6.4f%%\n", __FILE__, __LINE__, cnt_zero, N, percent);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX ", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  printf("XTEA_LSH_CONST = %d, XTEA_RSH_CONST = %d\n", TEA_LSH_CONST, TEA_RSH_CONST);
  srandom(time(NULL));

  test_adp_xtea_f_lxr();
  test_adp_xtea_f_lxr_vs_exper_all();
  test_adp_xtea_f();
  test_adp_xtea_f_all();
  test_max_dy_adp_xtea_f();
  test_max_dx_adp_xtea_f();
  test_max_dy_adp_xtea_f_is_max();
  test_max_dx_adp_xtea_f_is_max();
  test_max_dy_adp_xtea_f_is_max_all();
  test_max_dx_adp_xtea_f_is_max_all();
  test_first_nz_adp_xtea_f();
  test_first_nz_adp_xtea_f_random();
#if 0
  test_adp_xtea_f_lxr_all();
  test_adp_xtea_f_approx();
  test_adp_xtea_f_approx_all();
  test_first_nz_adp_xtea_f_all();
#endif
  return 0;
}
