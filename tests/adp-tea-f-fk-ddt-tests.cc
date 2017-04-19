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
 * \file  adp-tea-f-fk-ddt-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for adp-tea-f-fk-ddt.cc
 *
 * Note: Infeasible for large word sizes (> 10 bits). Used only for tests and verification.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_DDT_H
#include "adp-tea-f-fk-ddt.hh"
#endif

void test_ddt()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  differential_t* ST;
  ST = sddt_alloc();

  //  differential_t** T;
  uint32_t** T;
  T = ddt_alloc();
  ddt_f(T, k0, k1, delta, lsh_const, rsh_const);

#if 0									  // DEBUG
  ddt_print(T);
#endif

#if 0									  // DEBUG
  ddt_sort_rows(T);
#endif

  ddt_to_list(T, ST);
  ddt_sort(ST);

  for(uint32_t i = 0; i < (ALL_WORDS * ALL_WORDS); i++) {
	 uint32_t dx = ST[i].dx;
	 uint32_t dy = ST[i].dy;
	 uint32_t np = ST[i].npairs;
	 double p = (double)np / (double)(ALL_WORDS);
#if 0									  // DEBUG
	 printf("[%s:%d] %10d: %08x -> %08x %d %f\n", __FILE__, __LINE__, i, dx, dy, np, p);
#endif
	 assert(p == p);				  // to avoid compilation warning
	 uint32_t npairs = T[dx][dy];
	 if(np != npairs) {
		printf("[%s:%d] WARNING: %d != %d\n", __FILE__, __LINE__, np, npairs);
	 }
	 assert(np == npairs);
  }

  sddt_free(ST);
  ddt_free(T);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_ddt_vs_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT & MASK;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  uint32_t** T;
  T = ddt_alloc();
  ddt_f(T, k0, k1, delta, lsh_const, rsh_const);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {
	 for(uint32_t db = 0; db < ALL_WORDS; db++) {

		double p1 = adp_f_ddt(T, da, db);
		double p2 = adp_f_exper_fixed_key_all(da, db, k0, k1, delta, lsh_const, rsh_const);

		//		printf("%8X %8X | %f %f\n", da, db, p1, p2);
		printf("\r%2d %2d | %f %f", da, db, p1, p2);
		fflush(stdout);
		assert(p1 == p2);
	 }
  }
  printf("\n");
  ddt_free(T);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_f_ddt_exper()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = random() % WORD_SIZE; // TEA_LSH_CONST;
  uint32_t rsh_const = random() % WORD_SIZE; // TEA_RSH_CONST;

  uint32_t** T;
  T = ddt_alloc();
  ddt_f(T, k0, k1, delta, lsh_const, rsh_const);

  uint32_t da = random() & MASK;
  uint32_t db1 = 0;
  uint32_t db2 = 0;

  double p1 = max_adp_f_ddt(T, da, &db1);
  double p2 = max_adp_f_exper_fixed_key_all(da, &db2, k0, k1, delta, lsh_const, rsh_const);
  printf("%2d %2d %2d | %f %f\n", da, db1, db2, p1, p2);
  assert(p1 == p2);
  ddt_free(T);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_max_adp_f_ddt_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = random() % WORD_SIZE; // TEA_LSH_CONST;
  uint32_t rsh_const = random() % WORD_SIZE; // TEA_RSH_CONST;

  uint32_t** T;
  T = ddt_alloc();
  ddt_f(T, k0, k1, delta, lsh_const, rsh_const);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {

	 uint32_t db1 = 0;
	 uint32_t db2 = 0;

	 double p1 = max_adp_f_ddt(T, da, &db1);
	 double p2 = max_adp_f_exper_fixed_key_all(da, &db2, k0, k1, delta, lsh_const, rsh_const);

	 //	 printf("%2d %2d %2d | %f %f\n", da, db1, db2, p1, p2);
	 printf("\r %2d %2d %2d | %f %f", da, db1, db2, p1, p2);
	 fflush(stdout);
	 assert(p1 == p2);
  }
  printf("\n");
  ddt_free(T);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

// sorted rows
void test_max_adp_f_rsddt_vs_exper_all()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = random() % WORD_SIZE; // TEA_LSH_CONST;
  uint32_t rsh_const = random() % WORD_SIZE; // TEA_RSH_CONST;

  uint32_t** DDT;
  DDT = ddt_alloc();
  ddt_f(DDT, k0, k1, delta, lsh_const, rsh_const);

  differential_t** RSDDT;
  RSDDT = rsddt_alloc();
  ddt_to_diff_struct(DDT, RSDDT);
  ddt_sort_rows(RSDDT);

  for(uint32_t da = 0; da < ALL_WORDS; da++) {

	 uint32_t db1 = 0;
	 uint32_t db2 = 0;

	 double p1 = max_adp_f_rsddt(RSDDT, da, &db1);
	 double p2 = max_adp_f_exper_fixed_key_all(da, &db2, k0, k1, delta, lsh_const, rsh_const);

	 //	 printf("%2d %2d %2d | %f %f\n", da, db1, db2, p1, p2);
	 printf("\r %2d %2d %2d | %f %f", da, db1, db2, p1, p2);
	 fflush(stdout);
	 assert(p1 == p2);
  }
  printf("\n");
  ddt_free(DDT);
  rsddt_free(RSDDT);
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

/** 
 * The key-dependent probability for the TEA F-function
 * with the corresponding value of the round keys.
 */
typedef struct {
  uint32_t k0;
  uint32_t k1;
  double p;
} skey_t;

bool operator<(skey_t x, skey_t y)
{
  if(x.p > y.p)
	 return true;	
  return false;
}

// 
// Investigate the influence of the key on ADP-F
// 
void test_max_adp_f_ddt_wrt_keys()
{
  printf("[%s:%d] Running test %s() ...\n", __FILE__, __LINE__, __FUNCTION__);

  uint32_t da = random() & MASK;
  uint32_t db = random() & MASK;

  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  skey_t key[ALL_WORDS * ALL_WORDS];// = {{0, 0, 0.0}};

  for(uint32_t k1 = 0; k1 < ALL_WORDS; k1++) {
	 for(uint32_t k0 = 0; k0 < ALL_WORDS; k0++) {
		uint32_t i = (k1 * ALL_WORDS) + k0;

		uint32_t** T;
		T = ddt_alloc();
		ddt_f(T, k0, k1, delta, lsh_const, rsh_const);
		double p = adp_f_ddt(T, da, db);

		key[i].k0 = k0;
		key[i].k1 = k1;
		key[i].p = p;

		ddt_free(T);
	 }
  }

  std::sort(key, key + (ALL_WORDS * ALL_WORDS));

  for(uint64_t i = 0; i < (ALL_WORDS * ALL_WORDS); i++) {
	 uint32_t k0 = key[i].k0;
	 uint32_t k1 = key[i].k1;
	 double p = key[i].p;
	 printf("%d %d | %f %4d %4d | ", lsh_const, rsh_const, p, k0, k1);
	 print_binary(k0);
	 print_binary(k1);
	 printf("   |");
	 print_binary(da);
	 print_binary(db);
	 printf("\n");
  }
  printf("[%s:%d] WORD_SIZE = %d. Test %s() OK.\n", __FILE__, __LINE__, WORD_SIZE, __FUNCTION__);
}

void test_adp_f_ddt()
{
  uint32_t k0 = random() & MASK;
  uint32_t k1 = random() & MASK;
  uint32_t delta = DELTA_INIT & MASK;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  uint32_t** T;
  T = ddt_alloc();
  ddt_f(T, k0, k1, delta, lsh_const, rsh_const);

  uint32_t da = random() & MASK;
  uint32_t db = random() & MASK;

  double p1 = adp_f_ddt(T, da, db);
  double p2 = adp_f_exper_fixed_key_all(da, db, k0, k1, delta, lsh_const, rsh_const);

  printf("n = %d | %8X %8X | %8X -> %8X : %f %f\n", WORD_SIZE, k0, k1, da, db, p1, p2);
  assert(p1 == p2);

  ddt_free(T);
} 

int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  assert(WORD_SIZE <= 10);
  test_ddt();
  test_adp_f_ddt();
  test_adp_f_ddt_vs_exper();
  test_max_adp_f_ddt_exper();
  test_max_adp_f_ddt_vs_exper_all();
  test_max_adp_f_rsddt_vs_exper_all();
#if 0
  test_max_adp_f_ddt_wrt_keys();
#endif
  return 0;
}
