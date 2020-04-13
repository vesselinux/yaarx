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
 * \file  xdp-xtea-f-fk-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for xdp-xtea-f-fk.cc.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef XDP_XTEA_F_FK_H
#include "xdp-xtea-f-fk.hh"
#endif

void test_xdp_xtea_f_fk()
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

  double p_the = xdp_xtea_f_fk(n, dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = xdp_xtea_f_fk_exper(dx, dy, k, delta, lsh_const, rsh_const);
  assert(p_the == p_exp);

  uint32_t ninputs = (1U << 15);
  p_exp = xdp_xtea_f_fk_approx(ninputs, dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_XDP_XTEA_F_FK_TESTS
  printf("%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_xtea_f_fk_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

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

				  double p_the = xdp_xtea_f_fk(n, dx, dy, k, delta, lsh_const, rsh_const);
				  uint32_t dx_lxr = ((LSH(dx, lsh_const)) ^ RSH(dx, rsh_const));
				  double p_add = xdp_add(A, dx, dx_lxr, dy);
				  double p_exp = xdp_xtea_f_fk_exper(dx, dy, k, delta, lsh_const, rsh_const);
				  printf("\r[%s:%d] (%8X %8X | %8X -> %8X) = %f %f", __FILE__, __LINE__, delta, k, dx, dy, p_the, p_exp);
				  fflush(stdout);
#if DEBUG_XDP_XTEA_F_FK_TESTS
				  if(p_exp != p_add) {
					 printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
					 printf("[%s:%d] P_EXP(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_exp, log2(p_exp));
					 printf("[%s:%d] P_ADD(%8X %8X | %8X %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dx_lxr, dy, p_add, log2(p_add));
				  }
				  printf("\n[%s:%d] P_THE(%8X %8X | %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dx, dy, p_the, log2(p_the));
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
				  assert(p_the == p_exp);
				  assert(p_add == p_add); // to avoid compilation warnings
				}
			 }
		  }
		}
	 }
  }
  xdp_add_free_matrices(A);
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_xtea_f2_fk()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  const uint32_t n = WORD_SIZE;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  uint32_t dxx = xrandom() & MASK;
  uint32_t dx = xrandom() & MASK;
  uint32_t dy = xrandom() & MASK; 
  uint32_t k = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  double p_the = xdp_xtea_f2_fk(n, dxx, dx, dy, k, delta, lsh_const, rsh_const);
  double p_exp = xdp_xtea_f2_fk_exper(dxx, dx, dy, k, delta, lsh_const, rsh_const);
#if DEBUG_XDP_XTEA_F_FK_TESTS
  printf("[%s:%d] P_THE(%8X %8X | %8X %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dxx, dx, dy, p_the, log2(p_the));
  printf("[%s:%d] P_EXP(%8X %8X | %8X %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dxx, dx, dy, p_exp, log2(p_exp));
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
  assert(p_the == p_exp);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_xtea_f2_fk_all()
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
			 for(uint32_t dxx = 0; dxx < ALL_WORDS; dxx++) {
				for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
				  for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
					 double p_the = xdp_xtea_f2_fk(n, dxx, dx, dy, k, delta, lsh_const, rsh_const);

					 double p_exp = xdp_xtea_f2_fk_exper(dxx, dx, dy, k, delta, lsh_const, rsh_const);
					 printf("\r[%s:%d] (%8X %8X | %8X %8X -> %8X) = %f %f", __FILE__, __LINE__, delta, k, dxx, dx, dy, p_the, p_exp);
					 fflush(stdout);
#if DEBUG_XDP_XTEA_F_FK_TESTS
					 if(p_exp != p_the) {
						printf("\n[%s:%d] P_THE(%8X %8X | %8X %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dxx, dx, dy, p_the, log2(p_the));
						printf("[%s:%d] P_EXP(%8X %8X | %8X %8X -> %8X) = %f 2^%f\n", __FILE__, __LINE__, delta, k, dxx, dx, dy, p_exp, log2(p_exp));
					 }
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
					 assert(p_the == p_exp);
				  }
				}
			 }
		  }
		}
	 }
  }
  printf("\n[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_xdp_xtea_f2_fk_approx()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(TEA_LSH_CONST < TEA_RSH_CONST);

  for(uint32_t i = 0; i < (1U << 8); i++) {
	 uint32_t lsh_const = TEA_LSH_CONST;
	 uint32_t rsh_const = TEA_RSH_CONST;
	 uint32_t hong_diff = 0x80402010 & MASK;
	 uint32_t dxx = 0;//hong_diff;//xrandom() & MASK;
	 uint32_t dx = hong_diff;////xrandom() & MASK;
	 uint32_t dy = hong_diff;//dx;//xrandom() & MASK; 
	 uint32_t key = xrandom() & MASK;
	 uint32_t delta = xrandom() & MASK;

	 uint32_t ninputs = (1U << 15);
	 double p_approx = xdp_xtea_f2_fk_approx(ninputs, dxx, dx, dy, key, delta, lsh_const, rsh_const);
#if DEBUG_XDP_XTEA_F_FK_TESTS
	 printf("%4d: XDP_F2_APRX(%8X %8X | %8X %8X -> %8X)  = %f (2^%4.2f)\n", i++, key, delta, dxx, dx, dy, p_approx, log2(p_approx));
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
	 assert(p_approx == p_approx); // to avoid compilation warning
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_nz_xdp_xtea_f()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);
  uint32_t dx = gen_sparse(4, WORD_SIZE);//xrandom() & MASK;
  uint32_t dy = 0;
  uint32_t key = xrandom() & MASK;
  uint32_t delta = xrandom() & MASK;

  double p = nz_xdp_xtea_f(A, dx, &dy, lsh_const, rsh_const);
  uint32_t ninputs = (1U << 15);
  double p_exp = xdp_xtea_f_fk_approx(ninputs, dx, dy, key, delta, lsh_const, rsh_const);
#if DEBUG_XDP_XTEA_F_FK_TESTS
  printf("[%s:%d] NZ XDP_F_THE(%8X -> %8X) = %f (2%f)\n", __FILE__, __LINE__, dx, dy, p, log2(p));
  printf("[%s:%d] NZ XDP_F_EXP(%8X -> %8X) = %f (2%f) | key delta %8X %8X\n", __FILE__, __LINE__, dx, dy, p_exp, log2(p_exp), key, delta);
#endif  // #if DEBUG_XDP_XTEA_F_FK_TESTS
  assert(p == p); // to avoid compilation warning
  assert(p_exp == p_exp); // to avoid compilation warning
  xdp_add_free_matrices(A);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X ", __FILE__, __LINE__, WORD_SIZE, MASK);
  printf("XTEA_LSH_CONST = %d, XTEA_RSH_CONST = %d\n", TEA_LSH_CONST, TEA_RSH_CONST);
  srandom(time(NULL));

  test_xdp_xtea_f_fk();
  test_xdp_xtea_f2_fk();
  test_xdp_xtea_f2_fk_approx();
  test_nz_xdp_xtea_f();
  if(WORD_SIZE < 5) {
	 test_xdp_xtea_f_fk_all();
	 test_xdp_xtea_f2_fk_all();
  }
  return 0;
}
