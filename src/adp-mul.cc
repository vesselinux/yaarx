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
 * \file  adp-mul.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of modular multiplication (MUL): \f$\mathrm{adp}^{\odot}\f$ 
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

uint32_t gcd(const uint32_t a_in, const uint32_t b_in)
{
  uint32_t a = a_in;
  uint32_t b = b_in;
  uint32_t c = 0;

  if((a == 0) && (b == 0))
	 return 0;
  if(a == 0)
	 return b;
  if(b == 0)
	 return a;

  while(a != 0) {
	 c = a;
	 a = (b % a);
	 b = c;
  }
  return b;
}

double adp_mul(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  // (db x) + (da y) = dc - (da db)
  double p = 0.0;
  uint32_t n = (1UL << WORD_SIZE); // 2^n

  // Compute GCD with the GNU MP library
  mpz_t z_da, z_db, z_n, z_g, z_d;
  mpz_init_set_ui(z_da, da);
  mpz_init_set_ui(z_db, db);
  mpz_init_set_ui(z_n, n);
  mpz_init(z_g);
  mpz_gcd(z_g, z_da, z_db);	  // gcd(da, db)
  mpz_init(z_d);
  mpz_gcd(z_d, z_g, z_n);	  // gcd(da, db, 2^n)
  uint32_t d = mpz_get_ui(z_d);
  int32_t e = dc - (da * db);  // gamma - (alpha * beta)
  int32_t r = (e % d);			  // remainder from e / d
#if 0									  // DEBUG
  printf("[%s:%d] g = gcd(%d, %d, %d) %d\n", __FILE__, __LINE__, da, db, n, d);
#endif
  if(r != 0) {						  // d does not divide e
	 return 0.0;
  }
  p = (double)(d * n) / (double)(n * n); // (d*2^n) / 2^2n

  mpz_clear(z_da);
  mpz_clear(z_db);
  mpz_clear(z_g);
  mpz_clear(z_n);

  return p;
}

double adp_mul_exper(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  assert(WORD_SIZE <= 10);
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 + da) % MOD;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 + db) % MOD;
		uint32_t c1 = MUL(a1, b1);
		uint32_t c2 = MUL(a2, b2);
		uint32_t dx = SUB(c2, c1);//(c2 - c1 + MOD) % MOD;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc) {
		  cnt++;
#if 1									  // DEBUG
		  //		  uint32_t t = (MUL(db, a1) + MUL(da, b1) + MUL(da, db)) & MASK;
		  uint32_t t = (MUL(db, a1) + MUL(da, b1)) & MASK;
		  //		  printf("%d %d\n", a1, b1);
		  assert(t == SUB(dc, MUL(da, db)));
#endif
		}
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}
