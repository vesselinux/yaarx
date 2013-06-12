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
 * \file  idea.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Analysis of block cipher IDEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

// Reference implementation of IDEA by Pate Williams (c) 1997
#include "idea-ref.cc"

// The d() operator of IDEA: F_{2^n + 1} -> F_{2^n}
uint32_t d(uint32_t x)
{
  if(x == MOD)
	 return 0;					  // 2^n
  return x;
}

// The d^{-1}() operator of IDEA: F_{2^n} -> F_{2^n + 1}
uint32_t inv_d(uint32_t x)
{
  if(x == 0)
	 return MOD;					  // 2^n
  return x;
}

uint32_t idea_mul(uint32_t x_in, uint32_t y_in)
{
  uint32_t x = inv_d(x_in);
  uint32_t y = inv_d(y_in);
  uint32_t z = (x * y) % (MOD + 1); // mod (2^n + 1)
  printf("(%d %d) -> (%d %d) %d | %d\n", x_in, y_in, x, y, z, d(z));
  z = d(z);
  assert(z < MOD);
  return z;
}

double adp_idea_mul(const uint32_t da_in, const uint32_t db_in, const uint32_t dc_in)
{
  uint32_t da = da_in;
  uint32_t db = db_in;
  uint32_t dc = dc_in;

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
  //  int32_t e = dc - idea_mul(da, db);  // gamma - (alpha * beta)
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

double adp_idea_mul_exper(const uint32_t da, const uint32_t db, const uint32_t dc)
{
  assert(WORD_SIZE <= 10);
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = (a1 + da) % MOD;
	 for(uint32_t b1 = 0; b1 < N; b1++) {
		uint32_t b2 = (b1 + db) % MOD;
		uint32_t c1 = idea_mul(a1, b1);
		uint32_t c2 = idea_mul(a2, b2);
		uint32_t dx = SUB(c2, c1);//(c2 - c1 + MOD) % MOD;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc) {
		  cnt++;
		}
	 }
  }
  double p = (double)cnt / (double)all;
  return p;
}

// --- TESTS ---

void test_adp_idea_mul()
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
  for(da = 1; da < N; da++) {
	 for(db = 1; db < N; db++) {
		for(dc = 1; dc < N; dc++) {
		  double p1 = adp_idea_mul(da, db, dc);
		  double p2 = adp_idea_mul_exper(da, db, dc);
		  printf("[%s:%d] ADP_IDEA_MUL_TH[(%d,%d)->%d] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p1, log2(p1));
		  printf("[%s:%d] ADP_IDEA_MUL_EX[(%d,%d)->%d] = %6.5f 2^%f\n", 
					__FILE__, __LINE__, da, db, dc, p2, log2(p2));
		  printf("\n");
		}
	 }
  }
}

void test_idea_mul()
{
  uint16_t a = 0;
  uint16_t b = (1 << (WORD_SIZE - 1));
  uint32_t c = idea_mul(a, b);

  printf("[%s:%d] (%8X * %8X) =  %8X\n", __FILE__, __LINE__, a, b, c);
}

// Is the following true: 
// d(x) - d(y) (mod 2^n) = d((x - y) (mod 2^n))
// Answer: Yes.
void test_d()
{
  uint32_t N = MOD + 1;
  for(uint32_t x = 0; x < N; x++) {
	 for(uint32_t y = 0; y < N; y++) {
		uint32_t z1 = SUB(d(x), d(y));
		uint32_t z2 = d(SUB(x, y));
		printf("[%s:%d] %d %d | %d %d\n", __FILE__, __LINE__, x, y, z1, z2);
		//		if(((x - y) % (MOD + 1)) != MOD)
		assert(z1 == z2);
	 }
  }
}

// Is the following true: 
// d^-1(x) + d^-1(y) (mod 2^n) = d((x + y) (mod 2^n))
void test_inv_d_add()
{
  uint32_t N = MOD + 1;
  for(uint32_t x = 1; x < N; x++) {
	 for(uint32_t y = 1; y < N; y++) {
		uint32_t z1 = ADD(inv_d(x), inv_d(y));
		uint32_t z2 = inv_d(ADD(x, y)) % MOD;
		printf("[%s:%d] %d %d | %d %d\n", __FILE__, __LINE__, x, y, z1, z2);
		//		if(((x - y) % (MOD + 1)) != MOD)
		assert(z1 == z2);
	 }
  }
}

// Is the following true: 
// d^-1(x) * d^-1(y) (mod 2^n + 1) = d^-1(xy (mod 2^n + 1))
// Answer: No.
void test_inv_d()
{
  uint32_t N = MOD;
  for(uint32_t x = 1; x < N; x++) { // skip the 0 !!
	 for(uint32_t y = 1; y < N; y++) { // skip the 0 !!
		uint32_t z1 = (inv_d(x) * inv_d(y)) % (MOD + 1);
		uint32_t z2 = inv_d((x * y) % (MOD + 1));
		printf("[%s:%d] %d %d | %d %d\n", __FILE__, __LINE__, x, y, z1, z2);
		assert(z1 == z2);
	 }
  }
}

// Test vectors for IDEA
void test_idea_tvec()
{
  long **K, **L;
  ushort i, j, key[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  ushort X[4] = {0, 1, 2, 3}, Y[4];

  K = (long **)calloc(9, sizeof(long *));
  L = (long **)calloc(9, sizeof(long *));
  for (i = 0; i < 9; i++) {
    K[i] = (long *)calloc(6, sizeof(long));
    L[i] = (long *)calloc(6, sizeof(long));
    for (j = 0; j < 6; j++) K[i][j] = L[i][j] = 0;
  }
  IDEA_encryption_key_schedule(key, K);
  IDEA_encryption(X, Y, K);
  IDEA_decryption_key_schedule(K, L);
  IDEA_encryption(Y, X, L);
  for (i = 0; i < 9; i++) {
    free(K[i]);
    free(L[i]);
  }
  free(K);
  free(L);
}

// add-linearized version of idea
void test_idea_lin()
{
  assert(WORD_SIZE == 16);

  uint32_t Y_cnt[16] = {0};

  long **K;
  // fix key to random
  ushort key[8] = {0xFD01, 0x3631, 0xFF19, 0x6C15, 0x8F26, 0x96BE, 0xCAE8, 0x15FE};
  //  ushort key[8] = {0xFD01, 0x3631, 0xFF19, 0x6C15, 0x8F26, 1, 0xCAE8, 0x15FE};

  printf("#--- [%s:%d] NROUNDS %d\n", __FILE__, __LINE__, NROUNDS);
  // generate random key
#if 1
  printf("# --- KEY ");
  for(uint32_t j = 0; j < 8; j++) {
	 //	 key[j] = random32() & 0xFFFF;
	 printf("0x%4X, ", key[j]);
  }
  printf("\n");
#endif

  // alloc K
  K = (long **)calloc(9, sizeof(long *));
  for(uint32_t i = 0; i < 9; i++) {
    K[i] = (long *)calloc(6, sizeof(long));
    for(uint32_t j = 0; j < 6; j++) {
		K[i][j] = 0;
	 }
  }
  IDEA_encryption_key_schedule(key, K);

  const uint32_t rand_const = 0x1963;//random32() & MASK;
  uint32_t all_one = 0xFFFF;
  printf("#--- rand_const = %8X\n", rand_const);
  for(uint32_t q = 0; q < 1; q++) { // index of active difference

	 ushort DX[4] = {0, 0, 0, 0};
	 for(uint32_t j = 0; j < 4; j++) {
		DX[j] = 0;//random32() & MASK;//0;
	 }
	 DX[q] = 1;//0x8000;//1;// random32() & MASK;//1;//0x8000;						  // D[0] = alpha

	 printf("#--- [%s:%d] DX = (%8X %8X %8X %8X)\n", __FILE__, __LINE__, DX[0], DX[1], DX[2], DX[3]);

	 uint32_t N = (1U << WORD_SIZE);
	 uint32_t coeff = 0;
	 for(uint32_t i = 0; i < N; i++) {

		ushort DY[4] = {0, 0, 0, 0};
		ushort DY_lin[4] = {0, 0, 0, 0};
		ushort X1[4] = {0, 0, 0, 0};
		ushort X2[4] = {0, 0, 0, 0};
		ushort Y1[4] = {0, 0, 0, 0};
		ushort Y2[4] = {0, 0, 0, 0};

		for(uint32_t j = 0; j < 4; j++) {
		  X1[j] = rand_const;//random32() & 0xFFFF;
		  X2[j] = ADD(DX[j], X1[j]);
#if 1
		  if(j != 0) {
			 assert(X1[j] == X2[j]);
		  }
#endif
		}
		X1[q] = i;
		X2[q] = ADD(DX[q], X1[q]);

		IDEA_LIN_encryption(X1, Y1, K);
		IDEA_LIN_encryption(X2, Y2, K);

		for(uint32_t j = 0; j < 4; j++) {
		  DY_lin[j] = SUB(Y2[j], Y1[j]);
		}
		if(i == 0) {
		  coeff = DY_lin[q];
		} else {
		  assert(coeff == DY_lin[q]);
		}

		for(uint32_t j = 0; j < 4; j++) {
		  Y1[j] = 0;
		  Y2[j] = 0;
		}

		if(1) {
		  uint32_t r = 0;

		  // execution 1
		  uint32_t x0 = multiply(X1[0], K[r][0]);
		  uint32_t x2 = add(X1[2], K[r][2]);
  		  uint32_t t0 = multiply(K[r][4], x0 ^ x2);

		  uint32_t x3 = multiply(X1[3], K[r][3]);
		  uint32_t x1 = add(X1[1], K[r][1]);
		  uint32_t t1 = multiply(K[r][5], add(t0, x1 ^ x3));
		  //	  uint32_t t2 = add(t0, t1);
#if 0
		  t1 = t1 ^ x0;
		  t1 = multiply(t1, K[r+1][0]);
#endif
		  //		  t1 = add(t1, x0);

		  // exectution 2
		  uint32_t xx0 = multiply(X2[0], K[r][0]);
		  uint32_t xx2 = add(X2[2], K[r][2]);
  		  uint32_t tt0 = multiply(K[r][4], xx0 ^ xx2);

		  uint32_t xx3 = multiply(X2[3], K[r][3]);
		  uint32_t xx1 = add(X2[1], K[r][1]);
		  uint32_t tt1 = multiply(K[r][5], add(tt0, xx1 ^ xx3));
		  //		  uint32_t tt2 = add(tt0, tt1);
#if 0
		  tt1 = tt1 ^ xx0;
		  tt1 = multiply(tt1, K[r+1][0]);
#endif
		  //		  tt1 = add(tt1, xx0);

		  // differences
		  //		  uint32_t dt2 = SUB(tt2, t2);
		  //		  uint32_t dt0 = SUB(tt0, t0);
		  //		  printf("%6d %6d\n", i, dt0);
		  uint32_t dt1 = SUB(tt1, t1);
#if 1
		  for(uint32_t k = 0; k < 16; k++) {
			 uint32_t t = (dt1 >> k) & 1;
			 if(t == 1) {
				Y_cnt[k]++;
			 }
		  }
#endif
		  uint32_t mid = (1U << 15);
		  printf("%6d %6d ", i, dt1);
		  printf("# %8X ", dt1);
		  print_binary(dt1);
		  printf(" | ");
		  for(uint32_t k = 0; k < 16; k++) {
			 //			 printf("%4d ", abs(mid - Y_cnt[k]));
			 printf("%4d ", Y_cnt[k]);
		  }
		  printf(" | %d ", mid);
		  printf("\n");
		  all_one &= dt1;
		  //		  uint32_t dx0 = SUB(xx0, x0);
		  //		  printf("%6d %6d\n", i, dx0);
		}

		IDEA_encryption(X1, Y1, K);
		IDEA_encryption(X2, Y2, K);
		for(uint32_t j = 0; j < 4; j++) {
		  DY[j] = SUB(Y2[j], Y1[j]);
		}
#if 0
		for(uint32_t k = 0; k < 16; k++) {
		  uint32_t t = (DY[0] >> k) & 1;
		  if(t == 1) {
			 Y_cnt[k]++;
		  }
		}
#endif
#if 0
		printf("%6d ", i);
		printf("%6d ", DY[q]);
		printf("\n");
#endif
		//		printf("| %8X %8X %8X %8X |", DY_lin[0], DY_lin[1], DY_lin[2], DY_lin[3]);
		//		printf("| %8X %8X %8X %8X |", DY[0], DY[1], DY[2], DY[3]);
#if 0
		printf("%8X %8X | ", Y1[0], Y2[0]);
		printf("%8X %8X | ", Y1[1], Y2[1]);
		printf("%8X %8X | ", Y1[2], Y2[2]);
		printf("%8X %8X | ", Y1[3], Y2[3]);
#endif
	 }

#if 0
	 printf("%6d ", N);
	 printf("%6d ", coeff);
	 printf("\n");
#endif
  }

  printf("# %8X ", all_one);
  print_binary(all_one);
  printf("\n");

#if 1
  printf("# [%s:%d] Bit-level biases Y0[k] == 0:\n", __FILE__, __LINE__);
  for(uint32_t k = 0; k < 16; k++) {
	 double p = (double)Y_cnt[k] / (double)(1U << 16);
	 double eps = fabs(0.5 - p);
	 printf("# %6d: %6d | %f (2^%f) | %f (2^%f)\n", k, Y_cnt[k], p, log2(p), eps, log2(eps));
  }
#endif

  // free K
  for(uint32_t i = 0; i < 9; i++) {
    free(K[i]);
  }
  free(K);
}

/**
 * Main function of ADP-XOR tests.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  //  test_adp_idea_mul();
  //  test_idea_mul();
  //  test_d();
  //  test_inv_d();
  //  test_inv_d_add();
  //  test_idea_tvec();
  test_idea_lin();
  return 0;
}
