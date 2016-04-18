/*
 *    Copyright (c) 2012-2015 Luxembourg University,
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
 * \file  xlp-add-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Tests for \f$\mathrm{xlp}^{+}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XLP_ADD_H
#include "xlp-add.hh"
#endif

// --- TESTS ---

void test_parity()
{
  for(WORD_T i = 0; i < ALL_WORDS; i++) {
	 WORD_T x = i;
	 WORD_T par = parity(x);
	 printf("[%s:%d] parity of x %X ", __FILE__, __LINE__, x);
	 print_binary(x);
	 printf(" is %2d\n", par);
  }
}

void test_xlp_add_vs_exper()
{
  WORD_T word_size = WORD_SIZE;
  const WORD_T ma = 0x61;//0x5;
  const WORD_T mb = 0x41;//0x5;
  const WORD_T mc = 0x41;//0x7;

  double prob_exper = xlp_add_exper(ma, mb, mc, word_size);
  double bias_exper = (prob_exper - 0.5);
  double corr_exper = ((2.0 * prob_exper) - 1.0);
  assert(corr_exper == (2.0 * bias_exper));

  double prob = xlp_add(ma, mb, mc, word_size);
  double bias = xlb_add(ma, mb, mc, word_size);
  double corr = xlc_add(ma, mb, mc, word_size) * xlc_add_sign(ma, mb, mc, word_size);
  //  printf("[%s:%d] top corr %4.2f\n", __FILE__, __LINE__, corr);
  //  prob = 0.5 * (corr + 1.0);
  //  bias = 0.5 * corr;

  printf("[%s:%d] xlp_ex(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
			ma, mb, mc, prob_exper, log2(prob_exper), bias_exper, log2(bias_exper), corr_exper, log2(corr_exper));
  printf("[%s:%d] xlp_th(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
			ma, mb, mc, prob, log2(prob), bias, log2(bias), corr, log2(corr));

  assert(prob_exper == prob);
  assert(bias_exper == bias);
  assert(corr_exper == corr);
}

void test_xlp_add_vs_exper_all()
{
#if(WORD_SIZE <= 8)
  WORD_T word_size = WORD_SIZE;
  WORD_T all_words = (1U << word_size);
  for(WORD_T ma = 0; ma < all_words; ma++) {
	 for(WORD_T mb = 0; mb < all_words; mb++) {
		for(WORD_T mc = 0; mc < all_words; mc++) {

		  double prob_exper = xlp_add_exper(ma, mb, mc, word_size);
		  double bias_exper = (prob_exper - 0.5);
		  double corr_exper = ((2.0 * prob_exper) - 1.0);

		  double prob = xlp_add(ma, mb, mc, word_size);
		  double bias = xlb_add(ma, mb, mc, word_size);
		  double corr = xlc_add(ma, mb, mc, word_size) * xlc_add_sign(ma, mb, mc, word_size);

		  if(bias_exper != 0.0) {
			 printf("[%s:%d] xlp_ex(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
					  ma, mb, mc, prob_exper, log2(prob_exper), bias_exper, log2(bias_exper), corr_exper, log2(corr_exper));
			 printf("[%s:%d] xlp_th(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
					  ma, mb, mc, prob, log2(prob), bias, log2(bias), corr, log2(corr));
		  }

		  assert(prob_exper == prob);
		  assert(bias_exper == bias);
		  assert(corr_exper == corr);
		}
	 }
  }
  printf("[%s:%d] Test OK!\n", __FILE__, __LINE__);
#endif // #if(WORD_SIZE <= 8)
}

void test_xlp_add_vs_exper_all_word_sizes()
{
  WORD_T max_word_size = 7;
  for(WORD_T word_size = 0; word_size < max_word_size; word_size++) {
	 WORD_T all_words = (1U << word_size);
	 printf("\n[%s:%d] === WORD_SIZE %d ===\n", __FILE__, __LINE__, word_size);
	 for(WORD_T ma = 0; ma < all_words; ma++) {
		for(WORD_T mb = 0; mb < all_words; mb++) {
		  for(WORD_T mc = 0; mc < all_words; mc++) {

			 double prob_exper = xlp_add_exper(ma, mb, mc, word_size);
			 double bias_exper = (prob_exper - 0.5);
			 double corr_exper = ((2.0 * prob_exper) - 1.0);

			 double prob = xlp_add(ma, mb, mc, word_size);
			 double bias = xlb_add(ma, mb, mc, word_size);
			 double corr = xlc_add(ma, mb, mc, word_size) * xlc_add_sign(ma, mb, mc, word_size);

			 if(bias_exper != 0.0) {
				printf("[%s:%d] xlp_ex(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
						 ma, mb, mc, prob_exper, log2(prob_exper), bias_exper, log2(bias_exper), corr_exper, log2(corr_exper));
				printf("[%s:%d] xlp_th(%X %X -> %X) = %f 2^%4.2f | bias %f 2^%4.2f | corr %f 2^%4.2f\n", __FILE__, __LINE__, 
						 ma, mb, mc, prob, log2(prob), bias, log2(bias), corr, log2(corr));
			 }

			 assert(prob_exper == prob);
			 assert(bias_exper == bias);
			 assert(corr_exper == corr);
		  }
		}
	 }
  }
  printf("[%s:%d] Test OK!\n", __FILE__, __LINE__);
}

/**
 * Test if the correlation function is montonously decreasing in the
 * word size.
 */
void test_xlc_add_monotonous_decrease_all()
{
  WORD_T word_size = 6;//WORD_SIZE;
  WORD_T all_words = (1U << word_size);
  for(WORD_T i = 0; i < all_words; i++) {
	 for(WORD_T j = 0; j < all_words; j++) {
		for(WORD_T k = 0; k < all_words; k++) {

		  WORD_T w = 1;
		  WORD_MAX_T mask = (~0ULL >> (64 - w)); // full mask (word_size bits)
		  WORD_T ma = (i >> (word_size - w)) & 1;
		  WORD_T mb = (j >> (word_size - w)) & 1;
		  WORD_T mc = (k >> (word_size - w)) & 1;
		  double corr_prev = xlc_add(ma, mb, mc, w);// * xlc_add_sign(ma, mb, mc, w);
#if 0
		  printf("[%s:%d] xlc(%2d: %X %X -> %X) = corr %f 2^%4.2f\n", __FILE__, __LINE__, 
					w, ma, mb, mc, corr_prev, log2(corr_prev));
		  printf("[%s:%d] --- %X %X %X ---\n", __FILE__, __LINE__, i, j, k);
#endif

		  for(w = 2; w <= word_size; w++) {

			 mask = (~0ULL >> (64 - w)); // full mask (word_size bits)

			 // Extract the w MS bits of i, j, k
			 // We have to parse the words MSB to LSB (see xlp_add)
			 ma = (i >> (word_size - w)) & mask;
			 mb = (j >> (word_size - w)) & mask;
			 mc = (k >> (word_size - w)) & mask;

			 double corr = xlc_add(ma, mb, mc, w);// * xlc_add_sign(ma, mb, mc, w);
			 double corr_exper = std::abs((2.0 * xlp_add_exper(ma, mb, mc, w)) - 1.0);// * xlc_add_sign(ma, mb, mc, w);
#if 0
			 printf("[%s:%d] xlc_th(%2d: %X %X -> %X) = corr %f 2^%4.2f corr_prev %f 2^%4.2f\n", __FILE__, __LINE__, 
					  w, ma, mb, mc, corr, log2(corr), corr_prev, log2(corr_prev));
#endif
			 if(!(corr == corr_exper)) {
				printf("[%s:%d] xlc_ex(%2d: %X %X -> %X) = corr_exper %f 2^%4.2f\n", __FILE__, __LINE__, 
						 w, ma, mb, mc, corr_exper, log2(corr_exper));
			 }
			 assert(corr == corr_exper);
			 assert(corr <= corr_prev);
			 corr_prev = corr;
		  }
		}
	 }
  }
  printf("[%s:%d] Test OK!\n", __FILE__, __LINE__);
}

/**
 * Test if the correlation function is montonously decreasing in the
 * word size.
 *
 * WARNINIG! Parse the bits MSB to LSB
 */
void test_xlc_add_monotonous_decrease()
{
  WORD_T word_size = WORD_SIZE;
  double corr_final = 0.0;

  while(corr_final == 0.0) {

	 // fse16 slides example
#if 1
	 WORD_T i = 0xFB;
	 WORD_T j = 0xBB;
	 WORD_T k = 0xA6;
#else
	 WORD_T i = xrandom() & MASK;
	 WORD_T j = xrandom() & MASK;
	 WORD_T k = xrandom() & MASK;
#endif

	 printf("[%s:%d] --- %X %X %X ---\n", __FILE__, __LINE__, i, j, k);
	 print_binary(i);
	 printf(" ");
	 print_binary(j);
	 printf(" ");
	 print_binary(k);
	 printf("\n");

	 WORD_T w = 1;
	 WORD_MAX_T mask = (~0ULL >> (64 - w)); // full mask (word_size bits)
	 WORD_T ma = (i >> (word_size - w)) & 1;
	 WORD_T mb = (j >> (word_size - w)) & 1;
	 WORD_T mc = (k >> (word_size - w)) & 1;
	 double corr_prev = xlc_add(ma, mb, mc, w);// * xlc_add_sign(ma, mb, mc, w);
#if 1
	 printf("[%s:%d] xlc(%2d: %X %X -> %X) = corr %f 2^%4.2f\n", __FILE__, __LINE__, 
			  w, ma, mb, mc, corr_prev, log2(corr_prev));
	 printf("[%s:%d] --- %X %X %X ---\n", __FILE__, __LINE__, i, j, k);
	 print_binary(ma, w);
	 printf(" ");
	 print_binary(mb, w);
	 printf(" ");
	 print_binary(mc, w);
	 printf("\n");
#endif

	 for(w = 2; w <= word_size; w++) {

		mask = (~0ULL >> (64 - w)); // full mask (word_size bits)

		// Extract the w MS bits of i, j, k
		// We have to parse the words MSB to LSB (see xlp_add)
		ma = (i >> (word_size - w)) & mask;
		mb = (j >> (word_size - w)) & mask;
		mc = (k >> (word_size - w)) & mask;

		double corr = xlc_add(ma, mb, mc, w);// * xlc_add_sign(ma, mb, mc, w);
		double corr_exper = std::abs((2.0 * xlp_add_exper(ma, mb, mc, w)) - 1.0);// * xlc_add_sign(ma, mb, mc, w);
#if 1
		printf("[%s:%d] xlc_th(%2d: %X %X -> %X) = corr %f 2^%4.2f corr_prev %f 2^%4.2f\n", __FILE__, __LINE__, 
				 w, ma, mb, mc, corr, log2(corr), corr_prev, log2(corr_prev));
		print_binary(ma, w);
		printf(" ");
		print_binary(mb, w);
		printf(" ");
		print_binary(mc, w);
		printf("\n");
#endif
		if(!(corr == corr_exper)) {
		  printf("[%s:%d] xlc_ex(%2d: %X %X -> %X) = corr_exper %f 2^%4.2f\n", __FILE__, __LINE__, 
					w, ma, mb, mc, corr_exper, log2(corr_exper));
		}
		assert(corr == corr_exper);
		assert(corr <= corr_prev);
		corr_prev = corr;
	 }

	 corr_final = corr_prev;
  }

  printf("[%s:%d] Test OK!\n", __FILE__, __LINE__);
}

/*
 * Test multiple executions of xlc_add
 */
void test_xlc_add_multi()
{
  WORD_T word_size = WORD_SIZE;
  const WORD_T ma = 0x5;
  const WORD_T mb = 0x5;
  const WORD_T mc = 0x7;
  uint32_t N = (1U << 10);

  double corr_prev = xlc_add(ma, mb, mc, word_size);
  for(uint32_t i = 0; i < N; i++) {

	 //  double corr = xlc_add(ma, mb, mc, word_size) * xlc_add_sign(ma, mb, mc, word_size);
	 double corr = xlc_add(ma, mb, mc, word_size);
#if 1 // DEBUG
	 if(!(corr_prev == corr)) {
		printf("[%s:%d] %5d: %X %X %X %d %f %f\n", __FILE__, __LINE__,
				 i, ma, mb, mc, word_size, corr, corr_prev);
	 }
#endif // #if 1 // DEBUG
	 assert(corr_prev == corr);
	 //	 corr_prev = corr;
  }
}

/**
 * Main function of XLP-ADD tests.
 */
int main()
{
  printf("[%s:%d] Tests, WORD_SIZE  = %d, MASK = %llX\n", __FILE__, __LINE__, WORD_SIZE, (WORD_MAX_T)MASK);
  srandom(time(NULL));
  //  test_parity();
  //  test_xlp_add_vs_exper_all();
  //  test_xlp_add_vs_exper_all_word_sizes();
  test_xlc_add_monotonous_decrease();
  //  test_xlc_add_monotonous_decrease_all();
  //  test_xlp_add_vs_exper();
  //  test_xlc_add_multi();
  return 0;
}

