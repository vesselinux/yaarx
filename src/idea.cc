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
#ifndef BSDR_H
#include "bsdr.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef ADP_XOR_COUNT_ODIFF_H
#include "adp-xor-count-odiff.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif
#ifndef ADP_XOR_FI_COUNT_ODIFF_H
#include "adp-xor-fi-count-odiff.hh"
#endif
#ifndef ADP_MUL_H
#include "adp-mul.hh"
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
#if 0											// DEBUG
  printf("(%d %d) -> (%d %d) %d | %d\n", x_in, y_in, x, y, z, d(z));
#endif
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

// IDEA multiplication with one fixed input
double adp_idea_mul_fi_exper(const uint32_t da, const uint32_t k, const uint32_t dc)
{
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;

  uint64_t all = N;				  // all input pairs

  for(uint32_t a1 = 0; a1 < N; a1++) {
	 uint32_t a2 = ADD(a1,da);
	 uint32_t c1 = idea_mul(a1, k);
	 uint32_t c2 = idea_mul(a2, k);
	 uint32_t dx = SUB(c2, c1);//(c2 - c1 + MOD) % MOD;
	 assert((dx >= 0) && (dx < MOD));
	 if(dx == dc) {
		cnt++;
	 }
#if 0									  // DEBUG
	 printf("[%s:%d] %8X %8X %8X %8X | %10d / %10lld\n", __FILE__, __LINE__, da, k, dc, dx, cnt, all);
#endif
  }
  double p = (double)cnt / (double)all;
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

void test_idea_mul_key()
{
  uint32_t da = 0xD18D;//0x4000;
  uint32_t dx = 0xD18D;
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 uint16_t a = da;
	 uint16_t b = i;
	 uint16_t c = idea_mul(a, b);
	 uint16_t cc = multiply(a, b);
	 printf("[%s:%d] (%8X * %8X) =  %8X %8X\n", __FILE__, __LINE__, a, b, c, cc);
	 assert(c == cc);
	 if(c == dx) {
		assert(1 == 0);
	 }
  }
}

void test_adp_idea_mul_fi_exper()
{
  uint32_t da = 0xD18D;//0x4000;//0xD18D;//0xD2C3;//0x19CF;//0x377B;//0xB77B;//random32() & MASK;
  uint32_t  k = random32() & MASK;//0x96BE;//0x8F26;//0xFD01;//random32() & MASK;
  uint32_t dc = 0x4000;//0xD18D;//random32() & MASK;//0xD18D;//0x4000;//MUL(da, k);//random32() & MASK;
  double p = 0.0;
  do {
	 p = adp_idea_mul_fi_exper(da, k, dc);
	 printf("[%s:%d] ADP_IDEA_MUL_EX[(%8X,[%8X])->%8X] = %6.5f 2^%f\n", 
			  __FILE__, __LINE__, da, k, dc, p, log2(p));
	 //	 dc = random32() & MASK;
	 k = random32() & MASK;
  } while(p == 0.0);
}

void test_idea_adp_xor_fi()
{
  //  uint32_t a = random32() & MASK;
  uint32_t da = 1;//0x377B; 
  uint32_t dc = 0x8885;
  double p_max = 0.0;
  uint32_t a_max = MOD;
  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);
  for(uint32_t a = 0; a < ALL_WORDS; a++) {
	 double p = adp_xor_fixed_input(A, a, da, dc);
	 if(p > p_max) {
		p_max = p;
		a_max = a;
		//		assert(1 == 0);
		printf("[%s:%d] ADP_XOR_FI[(%8X,[%8X])->%8X] = %6.5f 2^%f\n", 
				 __FILE__, __LINE__, da, a, dc, p, log2(p));
	 }
  }
  adp_xor_fixed_input_free_matrices(A);
}

void test_idea_adp_xor()
{
  //  uint32_t a = random32() & MASK;
  uint32_t da = 0xC000; 
  uint32_t dc = 0x8885;
  double p_max = 0.0;
  uint32_t a_max = MOD;
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);
  for(uint32_t a = 0; a < ALL_WORDS; a++) {
	 double p = adp_xor(A, a, da, dc);
	 if(p > p_max) {
		p_max = p;
		a_max = a;
		//		assert(1 == 0);
		printf("[%s:%d] ADP_XOR[(%8X,[%8X])->%8X] = %6.5f 2^%f\n", 
				 __FILE__, __LINE__, da, a, dc, p, log2(p));
	 }
  }
  adp_xor_free_matrices(A);
}

void test_adp_idea_mul_rand()
{
  assert(WORD_SIZE <= 10);

  uint64_t N = (1ULL << 10);
  for(uint32_t i = 0; i < N; i++) {
	 uint32_t da = random32() & MASK;
	 uint32_t db = random32() & MASK;
	 uint32_t dc = random32() & MASK;

	 double p1 = adp_idea_mul(da, db, dc);
	 double p2 = adp_idea_mul_exper(da, db, dc);
	 printf("[%s:%d] ADP_IDEA_MUL_TH[(%d,%d)->%d] = %6.5f 2^%f\n", 
			  __FILE__, __LINE__, da, db, dc, p1, log2(p1));
	 printf("[%s:%d] ADP_IDEA_MUL_EX[(%d,%d)->%d] = %6.5f 2^%f\n", 
			  __FILE__, __LINE__, da, db, dc, p2, log2(p2));
	 printf("\n");
  }
}

void test_adp_idea_mul_all()
{
  assert(WORD_SIZE <= 10);

  uint64_t N = (1ULL << WORD_SIZE);
  for(uint32_t da = 0; da < N; da++) {
	 for(uint32_t db = 0; db < N; db++) {
		for(uint32_t dc = 0; dc < N; dc++) {
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

void test_temp()
{
  uint32_t N = MOD;

  for(uint32_t x = 0; x < N; x++) {
	 uint32_t y1 = idea_mul(0, x);
	 uint32_t y2 = SUB(1, x);
	 printf("[%s:%d] %d | %d %d\n", __FILE__, __LINE__, x, y1, y2);
	 assert(y1 == y2);
  }
}

void test_idea_mul_all()
{
  for(uint16_t a = 0; a < ALL_WORDS; a++) {
	 for(uint16_t b = 0; b < ALL_WORDS; b++) {
		uint16_t c = idea_mul(a, b);
		uint16_t cc = multiply(a, b);
		printf("[%s:%d] (%8X * %8X) =  %8X %8X\n", __FILE__, __LINE__, a, b, c, cc);
		assert(c == cc);
	 }
  }
}

void test_idea_mul_rand()
{
  uint32_t N = (1U << 16);
  for(uint32_t i = 0; i < N; i++) {
	 uint16_t a = random32() & MASK;
	 uint16_t b = random32() & MASK;
	 uint16_t c = idea_mul(a, b);
	 uint16_t cc = multiply(a, b);
	 printf("[%s:%d] (%8X * %8X) =  %8X %8X\n", __FILE__, __LINE__, a, b, c, cc);
	 assert(c == cc);
  }
}

// test MUL with fixed key
void idea_mul_fk_fdx(uint16_t key, uint16_t dx)
{
  uint32_t mid = (1U << 15);
  uint32_t cnt[16] = {0};
  printf("#--- [%s:%d] key %8X, dx %8X\n", __FILE__, __LINE__, key, dx);
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 uint16_t x1 = i;
	 uint16_t x2 = ADD(x1, dx);
	 uint16_t y1 = multiply(x1, key);
	 uint16_t y2 = multiply(x2, key);
	 uint16_t dy = SUB(y2, y1);
#if 1
	 for(uint32_t k = 0; k < 16; k++) {
		uint32_t t = (dy >> k) & 1;
		if(t == 1) {
		  cnt[k]++;
		}
	 }
#endif
	 printf("%6d %6d ", x1, dy);
	 printf("# ");
	 print_binary(dy);
	 printf("| ");
	 for(uint32_t k = 0; k < 16; k++) {
		printf("%6d ", cnt[k]);
	 }
	 printf(" | %6d", mid);
	 printf("\n");
  }
  printf("#--- [%s:%d] key %8X, dx %8X\n", __FILE__, __LINE__, key, dx);
}

bool comp_diff(difference_t a, difference_t b) 
{ 
  return (a.dx > b.dx);
}

// test XOR with fixed constant
void idea_xor_fc(uint16_t c, uint16_t dx)
{
#define BIAS 0
#define COUNT_ODIFF 1

  gsl_matrix* A[2][2][2];
  adp_xor_fixed_input_alloc_matrices(A);
  adp_xor_fixed_input_sf(A);
  adp_xor_fixed_input_normalize_matrices(A);

#if BIAS
  uint32_t mid = (1U << 15);
  uint32_t cnt[16] = {0};
#endif

#if COUNT_ODIFF
  difference_t DY[ALL_WORDS] = {{0, 0.0}};
  std::vector<difference_t> dy_vec;
#endif

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 uint16_t x1 = i;
	 uint16_t x2 = ADD(x1, dx);
	 uint16_t y1 = XOR(x1, c);
	 uint16_t y2 = XOR(x2, c);
	 uint16_t dy = SUB(y2, y1);

#if COUNT_ODIFF
	 DY[dy].dx = dy;
    DY[dy].p += 1;;
#endif

#if BIAS
	 for(uint32_t k = 0; k < 16; k++) {
		uint32_t t = (dy >> k) & 1;
		if(t == 1) {
		  cnt[k]++;
		}
	 }
#endif

#if BIAS
	 printf("%6d %6d ", x1, dy);
	 printf("# ");
	 print_binary(dy);
	 printf("| ");
	 for(uint32_t k = 0; k < 16; k++) {
		printf("%6d ", cnt[k]);
		//		  printf("%6d ", abs(mid - cnt[k]));
	 }
	 printf(" | %6d", mid);
	 printf("\n");
#endif
  }

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 if(DY[i].p != 0.0) {
		dy_vec.push_back(DY[i]);
	 }
  }

#if COUNT_ODIFF
  printf("const      %4X     ", c);
  print_binary(c);
  printf("\n");
  printf("   dx      %4X     ", dx);
  print_binary(dx);
  printf("\n\n");
  std::sort(dy_vec.begin(), dy_vec.end());
  //  std::sort(dy_vec.begin(), dy_vec.end(), comp_diff);
  double h = 0;					  // entropy
  uint32_t i = 0;
  uint32_t s = 0;
  std::vector<difference_t>::iterator vec_iter = dy_vec.begin();
  for(vec_iter = dy_vec.begin(); vec_iter != dy_vec.end(); vec_iter++) {
	 difference_t diff = *vec_iter;
	 double p = diff.p / (double)ALL_WORDS;
	 h += p * log2(p);
	 double p_the = adp_xor_fixed_input(A, c, dx, diff.dx);
	 printf("%6d %8X  |  ", i, diff.dx);
	 print_binary(diff.dx);
	 //	 uint32_t unaf = naf(diff.dx).val;
	 //	 printf("  |  ");
	 //	 print_binary(unaf);
	 //	 printf("%8X ", unaf);
	 printf("  | %f  2^%f ", p, log2(p));
	 printf("2^%f ", log2(p_the));
	 printf("\n");
	 s += (uint32_t)diff.p;
	 i++;
	 assert(p == p_the);
  }
  h *= -1;
  printf("all %d %lld\n", s, ALL_WORDS);
  assert(s == ALL_WORDS);
  printf("[%s:%d] Entropy: %f 2^%f\n", __FILE__, __LINE__, h, log2(h));
#endif

#if BIAS									  // count biases
  printf("# [%s:%d] Biases:\n", __FILE__, __LINE__);
  for(uint32_t k = 0; k < 16; k++) {
	 double p = (double)cnt[k] / (double)(1U << 16);
	 double eps = fabs(0.5 - p);
	 uint32_t c_i = (c >> k) & 1;
	 uint32_t dx_i = (dx >> k) & 1;
	 //	 printf("%f (2^%f) ", eps, log2(eps));
	 //	 printf("%3.2f ", eps);
	 printf("%3.2f (%d,%d) ", eps, c_i, dx_i);
  }
  printf("\n");
#endif

  printf("#--- [%s:%d] const %8X %6d , dx %8X %6d\n", __FILE__, __LINE__, c, c, dx, dx);
  printf("const ");
  print_binary(c);
  printf("\n");
  printf("   dx ");
  print_binary(dx);
  printf("\n");
  //  printf("#--- [%s:%d] const %8X, dx %8X\n", __FILE__, __LINE__, c, dx);
  adp_xor_fixed_input_free_matrices(A);
}

void test_idea_mul_fk_fdx()
{
  uint32_t key = random32() & MASK;
  uint32_t dx = random32() & MASK;
  idea_mul_fk_fdx(key, dx);
}

void test_idea_xor_fc()
{
  //  uint32_t c  = 0x9702;
  //  uint32_t dx = 0x6891;
  //  uint32_t c  = 0xF68;
  //  uint32_t dx = 0xCACA;
  //  uint32_t c  = 0x1D01;
  //  uint32_t dx = 0xEE17;
  //  uint32_t c = 0xF055;
  //  uint32_t dx = 0x89FF;
  //  uint32_t c = 0xE91A;
  //  uint32_t dx = 0x9A06;
  //  uint32_t c = random32() & MASK;
  //  uint32_t dx = random32() & MASK;
  uint32_t  c = 0x7FC0;//0x8000;//random32() & MASK;
  uint32_t dx = 0x2780;//0xA000;//random32() & MASK;
  idea_xor_fc(c, dx);
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
  //  ushort key[8] = {0xFD01, 0x3631, 0xFF19, 0x6C15, 0x8F26, 0x96BE, 0xCAE8, 0x15FE};
      ushort key[8] = {0xFD01, 0x3631, 0xFF19, 0x6C15, 0xB9CC, 0x96BE, 0xCAE8, 0x15FE};

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

  const uint32_t rand_const = SUB(0x4000, 0xFF19);//random32() & MASK;//0xFFC1;//SUB(0x4000, 0xFF19);//0x4000;//random32() & MASK;
  uint32_t all_one = 0xFFFF;
  printf("#--- rand_const = %8X\n", rand_const);

  //  for(uint32_t q = 0; q < 1; q++) 
  uint32_t q = 0; // index of active difference
  { 
	 ushort DX[4] = {0, 0, 0, 0};
	 //	 DX[q] = 1;//0xFFC0;//0x556B;//0xC000;//1;//0x8000;//1;// random32() & MASK;//1;//0x8000;						  // D[0] = alpha

	 DX[q] = 0x556B;
	 //	 DX[2] = 0x377B;

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
#if 0
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
		  t1 = t1 ^ x0;
#if 1
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
		  tt1 = tt1 ^ xx0;
#if 1
		  tt1 = multiply(tt1, K[r+1][0]);
#endif
		  //		  tt1 = add(tt1, xx0);

		  // differences
		  //		  uint32_t dt2 = SUB(tt2, t2);
		  //		  uint32_t dt0 = SUB(tt0, t0);
		  //		  printf("%6d %6d\n", i, dt0);
#if 1
		  uint32_t dt1 = SUB(tt1, t1);
#endif
		  //		  dt1 = SUB(add(tt0, xx1 ^ xx3), add(t0, x1 ^ x3));
		  //		  dt1 = SUB(multiply(0x96BE, add(tt0, xx1 ^ xx3)), multiply(0x96BE, add(t0, x1 ^ x3)));
		  //		  dt1 = SUB(multiply(K[r][5], add(tt0, xx1 ^ xx3)), multiply(K[r][5], add(t0, x1 ^ x3)));
		  //		  dt1 = SUB(tt0, t0);
		  //		  dt1 = SUB(xx0, x0);
		  //		  dt1 = x2;//SUB(xx2, x2);
		  //		  dt1 = SUB((xx0 ^ xx2), (x0 ^ x2));
		  //		  uint32_t dt1 = SUB(xx0, x0);

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
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));

  //  test_idea_mul_key();
  //  test_idea_adp_xor();
  //  test_idea_adp_xor_fi();
  //  test_adp_idea_mul_fi_exper();

  //  test_adp_idea_mul_rand();
  //  test_adp_idea_mul_all();

  test_idea_lin();

  //  test_idea_mul();
  //  test_d();
  //  test_inv_d();
  //  test_inv_d_add();
  //  test_idea_tvec();

  //  test_idea_mul_all();
  //  test_idea_mul_rand();

  //  test_idea_mul_fk_fdx();
  //  test_idea_xor_fc();
  return 0;
}
