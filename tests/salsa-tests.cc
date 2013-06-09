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
 * \file  salsa-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for salsa.cc .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_DIFF_SET_H
#include "xdp-add-diff-set.hh"
#endif
#ifndef SALSA_H
#include "salsa.hh"
#endif

/**
 * Test vector for Salsa20. Ref. http://cr.yp.to/snuffle/spec.pdf
 */
uint8_t g_test_vector_0[2][64] = {
  // input to Salsa20
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
  // output from Salsa20
  {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
};

/**
 * Test vector for Salsa20. Ref. http://cr.yp.to/snuffle/spec.pdf
 */
uint8_t g_test_vector_1[2][64] = {
  // input to Salsa20
  {211,159, 13,115, 76, 55, 82,183, 3,117,222, 37,191,187,234,136,
	49,237,179, 48, 1,106,178,219,175,199,166, 48, 86, 16,179,207,
	31,240, 32, 63, 15, 83, 93,161,116,147, 48,113,238, 55,204, 36,
	79,201,235, 79, 3, 81,156, 47,203, 26,244,243, 88,118,104, 54},
  // output from Salsa20
  {109,  42, 178, 168, 156, 240, 248, 238, 168, 196, 190, 203,  26, 110, 170, 154,
	29,  29, 150,  26, 150,  30, 235, 249, 190, 163, 251,  48,  69, 144,  51,  57,
	118,  40, 152, 157, 180,  57,  27,  94, 107,  42, 236,  35,  27, 111, 114, 114,
	219, 236, 232, 135, 111, 155, 110,  18,  24, 232,  95, 158, 179,  19,  48, 202}
};

void test_vector_salsa20()
{
  assert(WORD_SIZE == 32);
  assert(SALSA_FEED_FORWARD == 1);

  uint32_t X[SALSA_STATE] = {0};
  uint32_t Y[SALSA_STATE] = {0};
  uint8_t X8[4 * SALSA_STATE] = {0};
  uint8_t Y8[4 * SALSA_STATE] = {0};
  uint32_t r_start = 0;
  uint32_t r_end = 20;

  assert(r_end == 20);

  for(uint32_t i = 0; i < (4 * SALSA_STATE); i++) {
	 //	 X8[i] = g_test_vector_0[0][i];
	 X8[i] = g_test_vector_1[0][i];
  }

  printf("[%s:%d] X8\n", __FILE__, __LINE__);
  salsa_print_state_uint8(X8);
  salsa_state_uint8_to_uint32(X8, X);
  salsa20(E, r_start, r_end, X, Y);
  salsa_state_uint32_to_uint8(Y8, Y);
  printf("[%s:%d] Y8\n", __FILE__, __LINE__);
  salsa_print_state_uint8(Y8);

  for(uint32_t i = 0; i < (4 * SALSA_STATE); i++) {
	 //	 assert(Y8[i] == g_test_vector_0[1][i]);
	 assert(Y8[i] == g_test_vector_1[1][i]);
  }
}


void test_salsa()
{
  uint32_t X[SALSA_STATE] = {0};
  uint32_t Y[SALSA_STATE] = {0};
  uint32_t r_start = 0;
  uint32_t r_end = 3;
  salsa_gen_rand_input_state(X);
  printf("[%s:%d] X\n", __FILE__, __LINE__);
  salsa_print_state_uint32(X);
  salsa20(E, r_start, r_end, X, Y);
  printf("[%s:%d] Y\n", __FILE__, __LINE__);
  salsa_print_state_uint32(Y);
}

void test_xdp_add_dset_salsa20_all()
{
  const uint32_t r_start = 0;
  const uint32_t r_end = 4;//5;
  uint32_t nrounds = r_end - r_start;
  uint32_t npairs = (1U << 15);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* A[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(A);
  xdp_add_dset_gen_matrices_all(A, AA);


  //  uint32_t arr_w[4] = {6, 7, 8, 9};
#if 0
  for(uint32_t i_w = 6; i_w < 10; i_w++) {
	 for(uint32_t i_pos = 0; i_pos < WORD_SIZE; i_pos++) {
#else
  for(uint32_t s6 = 0; s6 < ALL_WORDS; s6++) {
	 for(uint32_t s7 = 0; s7 < ALL_WORDS; s7++) {
		for(uint32_t s8 = 0x73; s8 < ALL_WORDS; s8++) {
		  for(uint32_t s9 = 0x20; s9 < ALL_WORDS; s9++) {
			 if((s6 == 0) && (s7 == 0) && (s8 == 0) && (s9 == 0))
				continue;
#endif
			 diff_set_t DX[SALSA_STATE] = {{0, 0}};
			 diff_set_t DY[SALSA_STATE] = {{0, 0}};
			 diff_set_t DT[MAX_NROUNDS][SALSA_STATE] = {{{0,0}}};
			 double PT[MAX_NROUNDS][SALSA_STATE] = {{0.0}};
			 double PW_the[SALSA_STATE] = {0.0};
			 double PW_exp[SALSA_STATE] = {0.0};
			 double PW_rand[SALSA_STATE] = {0.0};
			 uint32_t D[MAX_NROUNDS][SALSA_STATE] = {{0}};

#if 0
			 uint32_t S[SALSA_STATE] = 
				{0, 0, 0, 0,
				 0, 0, 0, 0,
				 0x80000000, 0, 0, 0,
				 0, 0, 0, 0};
#endif
#if 0	// Crowley differential
			 uint32_t S[SALSA_STATE] = 
				{0, 0, 0, 0,
				 0, 0, 0, 0,
				 0, 0x80000000, 0, 0,
				 0, 0, 0, 0};
#endif
			 uint32_t S[SALSA_STATE] = {0};

			 //  S[9] = random32() & MASK;//1U << (WORD_SIZE);
#if 1
			 S[6] = s6;
			 S[7] = s7;
			 S[8] = s8;
			 S[9] = s9;
#else
			 //  uint32_t i_w = random32() % 4; // random index
			 //  i_w = 9;						  // Crowley
			 //  i_w = 7;							  // Aumasson et al.
			 //  S[i_w] = 1U << (WORD_SIZE - 1);
			 S[i_w] = 1U << i_pos;
			 printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, i_w, S[i_w]);

#endif
			 // copy input state
			 for(uint32_t i = 0; i < SALSA_STATE; i++) {
				DT[0][i].diff = S[i];
				PT[0][i] = 1.0;

				DX[i].diff = S[i];
				DX[i].fixed = 0;//0xffffffff & MASK;//0;
			 }
			 //  DX[i_w].fixed = 0xffffffff & MASK;//0;;//gen_sparse(8, WORD_SIZE);

			 double p = xdp_add_dset_salsa20(E, r_start, r_end, A, DX, DY, DT, PT);
			 double p_exp = xdp_add_dset_salsa20_exper(E, r_start, r_end, npairs, DX, DY, PW_exp);

			 salsa_gen_word_deps(nrounds, E, D);
			 //  salsa_word_probs(nrounds, E, PT, D, PW_the);
			 salsa_word_probs_v2(r_start, r_end, E, PT, PW_the);

			 salsa_compute_prob_rand(DY, PW_rand);
#if 0
			 salsa_print_trail(r_end, DT, PT);
#endif
#if 0
			 printf("[%s:%d] PW_the:\n", __FILE__, __LINE__);
			 salsa_print_prob(PW_the);
#endif
			 printf("[%s:%d] PW_exp:\n", __FILE__, __LINE__);
			 salsa_print_prob(PW_exp);
			 printf("[%s:%d] PW_exp vs. P_rand:\n", __FILE__, __LINE__);
			 salsa_print_prob_vs_rand(PW_exp, PW_rand);
			 printf("[%s:%d] p = %f (2^%f), p = %f (2^%f)\n", __FILE__, __LINE__, p, log2(p), p_exp, log2(p_exp));
			 //  printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, i_w, S[i_w]);
			 printf("[%s:%d] S: %8X %8X %8X %8X\n", __FILE__, __LINE__, S[6], S[7], S[8], S[9]);
			 //		printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, 6, S[6]);
			 //		printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, 7, S[7]);
			 //		printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, 8, S[8]);
			 //		printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, 9, S[9]);
#if 1
		  }
		}
	 }
  }
#else
	 }
  }
#endif
  xdp_add_dset_free_matrices_all(A);
  xdp_add_dset_free_matrices(AA);
}

void test_xdp_add_dset_salsa20()
{
  const uint32_t r_start = 0;
  const uint32_t r_end = 4;//5;
  uint32_t nrounds = r_end - r_start;
  uint32_t npairs = (1U << 12);

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* A[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(A);
  xdp_add_dset_gen_matrices_all(A, AA);

  //  uint32_t arr_w[4] = {6, 7, 8, 9};
  diff_set_t DX[SALSA_STATE] = {{0, 0}};
  diff_set_t DY[SALSA_STATE] = {{0, 0}};
  diff_set_t DT[MAX_NROUNDS][SALSA_STATE] = {{{0,0}}};
  double PT[MAX_NROUNDS][SALSA_STATE] = {{0.0}};
  double PW_the[SALSA_STATE] = {0.0};
  double PW_exp[SALSA_STATE] = {0.0};
  double PW_rand[SALSA_STATE] = {0.0};
  uint32_t D[MAX_NROUNDS][SALSA_STATE] = {{0}};

  uint32_t S[SALSA_STATE] = {0};
  S[8] = 0x73;
  S[9] = 0x28;
  //  printf("[%s:%d] S[%2d] %8X\n", __FILE__, __LINE__, i_w, S[i_w]);

  // copy input state
  for(uint32_t i = 0; i < SALSA_STATE; i++) {
	 DT[0][i].diff = S[i];
	 PT[0][i] = 1.0;
	 DX[i].diff = S[i];
	 DX[i].fixed = 0;//0xffffffff & MASK;//0;
  }
  //  DX[i_w].fixed = 0xffffffff & MASK;//0;;//gen_sparse(8, WORD_SIZE);

  double p = xdp_add_dset_salsa20(E, r_start, r_end, A, DX, DY, DT, PT);
  double p_exp = xdp_add_dset_salsa20_exper(E, r_start, r_end, npairs, DX, DY, PW_exp);

  salsa_gen_word_deps(nrounds, E, D);
  //  salsa_word_probs(nrounds, E, PT, D, PW_the);
  salsa_word_probs_v2(r_start, r_end, E, PT, PW_the);

  salsa_compute_prob_rand(DY, PW_rand);
#if 0
  salsa_print_trail(r_end, DT, PT);
#endif
#if 0
  printf("[%s:%d] PW_the:\n", __FILE__, __LINE__);
  salsa_print_prob(PW_the);
#endif
  printf("[%s:%d] PW_exp:\n", __FILE__, __LINE__);
  salsa_print_prob(PW_exp);
  printf("[%s:%d] PW_exp vs. P_rand:\n", __FILE__, __LINE__);
  salsa_print_prob_vs_rand(PW_exp, PW_rand);
  printf("[%s:%d] p = %f (2^%f), p = %f (2^%f)\n", __FILE__, __LINE__, p, log2(p), p_exp, log2(p_exp));
  printf("[%s:%d] S: %8X %8X %8X %8X\n", __FILE__, __LINE__, S[6], S[7], S[8], S[9]);

  xdp_add_dset_free_matrices_all(A);
  xdp_add_dset_free_matrices(AA);
}

void test_salsa_bias()
{
  uint32_t DX[SALSA_STATE] = {0};
  const uint32_t r_start = 0;
  uint32_t npairs = (1U << 23);
#if 0									  // Aumasson
  const uint32_t r_end = 7;
  uint32_t i_w = 7; // Aumasson et al.
  uint32_t o_w = random() % WORD_SIZE;//9; // output word
  uint32_t o_bit_val = 0; // value of output bit
  uint32_t o_bit_idx = 1; // index of output bit
#endif
#if 1									  // Crowley
  const uint32_t r_end = 5;
  uint32_t i_w = 9; // Crowley
  uint32_t o_w = random() % WORD_SIZE;//9; // output word
  uint32_t o_bit_val = 0; // value of output bit
  uint32_t o_bit_idx = 1; // index of output bit
#endif
  DX[i_w] = 1U << (WORD_SIZE - 1);
  printf("[%s:%d] DX[%2d] %8X\n", __FILE__, __LINE__, i_w, DX[i_w]);

  assert((r_end + 1) < MAX_NROUNDS);

  uint32_t cnt = 0;
  for(uint32_t i = 0; i < npairs; i++) {
	 uint32_t X1[SALSA_STATE] = {0};
	 uint32_t X2[SALSA_STATE] = {0};
	 uint32_t Y1[SALSA_STATE] = {0};
	 uint32_t Y2[SALSA_STATE] = {0};
	 for(uint32_t j = 0; j < SALSA_STATE; j++) {
		X1[j] = random32() & MASK;
		X2[j] = XOR(X1[j], DX[j]);
	 }
	 salsa20(E, r_start, r_end, X1, Y1);
	 salsa20(E, r_start, r_end, X2, Y2);
	 uint32_t DY[SALSA_STATE] = {0};
	 for(uint32_t j = 0; j < SALSA_STATE; j++) {
		DY[j] = XOR(Y1[j], Y2[j]);
	 }
	 uint32_t test_bit_val = (DY[o_w] >> o_bit_idx) & 1;
	 uint32_t test_bit_val_2 = (DY[o_w] >> (o_bit_idx + 1)) & 1;
	 bool b_is_equal = ((test_bit_val == o_bit_val) && (test_bit_val_2 == o_bit_val));
	 //	 bool b_is_equal = (test_bit_val == o_bit_val);
	 if(b_is_equal) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)npairs;
  //  double eps = abs(0.5 - p);
  double eps = 0.25 - p;
  if(p > 0.25) {
	 eps = p - 0.25;
  }
  printf("[%s:%d] DY[%2d][%2d] p = %f (2^%f), eps = %f (2^%f)\n", __FILE__, __LINE__, r_end, o_w, p, log2(p), eps, log2(eps));
}

void test_salsa_gen_word_deps()
{
  uint32_t nrounds = 2;
  uint32_t D[MAX_NROUNDS][SALSA_STATE] = {{0}};
  salsa_gen_word_deps(nrounds, E, D);

  for(uint32_t  i = 0; i < SALSA_STATE; ++i) {
	 printf("word %d after round %d Dends on:\n", i, nrounds - 1);
	 for(uint32_t  s = 0; s < nrounds; ++s) {
		//		printf("D[%d][%d]=%8X\n", i, s, D[s][i]);
		for(uint32_t  j = 0; j < SALSA_STATE; ++j) {
		  if((D[s][i] >> j) & 1) {
			 printf("  addition %d of round %d\n", j, s);
		  }
		}
	 }
  }
}

//[./src/salsa.cc:153]  4: w[ 4]: 
// (k = 2) 01*****1 (41,3E) | 001110** (38, 3) | ******** ( 0,FF) | ******** ( 0,FF) | 0.058594 2^-4.093109
void test_xdp_add_dset_salsa_arx()
{
  diff_set_t dx = {0x41, 0x3E};
  diff_set_t dy = {0x38, 0x3};
  diff_set_t dz = {0x0, 0xFF};
  diff_set_t dt = {0, 0};//{0x0, 0xFF};
  uint32_t k = 0;
  bool b_single_diff = false;

  gsl_matrix* AA[2][2][2];		  // xdp-add-dset
  xdp_add_dset_alloc_matrices(AA);
  xdp_add_dset_gen_matrices(AA);

  gsl_matrix* A[3][3][3];		  // xdp-add-dset-full
  xdp_add_dset_alloc_matrices_all(A);
  xdp_add_dset_gen_matrices_all(A, AA);

  double p = xdp_add_dset_salsa_arx(A, dx, dy, dz, &dt, k, b_single_diff);

#if 1
  printf("[%s:%d] (k = %d) ", __FILE__, __LINE__, k);
  xdp_add_dset_print_set(dx);
  printf(" (%2X,%2X) | ", dx.diff, dx.fixed);
  xdp_add_dset_print_set(dy);
  printf(" (%2X,%2X) | ", dy.diff, dy.fixed);
  xdp_add_dset_print_set(dz);
  printf(" (%2X,%2X) | ", dz.diff, dz.fixed);
  xdp_add_dset_print_set(dt);
  printf(" (%2X,%2X) | ", dt.diff, dt.fixed);
  printf("%f 2^%f\n", p, log2(p));
#endif

  xdp_add_dset_free_matrices_all(A);
  xdp_add_dset_free_matrices(AA);
}

/**
 * Main function of the tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  if(WORD_SIZE < 32) {
	 salsa_gen_rand_shift_const(E);
  }
  //  test_xdp_add_dset_salsa_arx();
  //  test_salsa_bias();
  test_xdp_add_dset_salsa20_all();
  //  test_xdp_add_dset_salsa20();
  //  test_salsa_gen_word_deps();
  //  test_salsa();
  //  test_vector_salsa20();
  return 0;
}
