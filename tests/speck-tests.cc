/*
 *    Copyright (c) 2012-2016 Luxembourg University,
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
 * \file  speck-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2016
 * \brief Tests if Speck is a Markov cipher and other tests.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif

#define LEFT 0
#define RIGHT 1

#define SAME_KEY 1

/**
 * One round of Speck (equivalent representation)
 */
void speck_round_equiv(const WORD_T key[2], const WORD_T plaintext[2], WORD_T ciphertext[2])
{
  WORD_T x_L = plaintext[LEFT];
  WORD_T x_R = plaintext[RIGHT];
  x_L ^= key[LEFT];
  x_R ^= key[RIGHT];
  WORD_T y_L = ADD(x_L, x_R);
  WORD_T y_R = x_R;
  ciphertext[LEFT] = y_L;
  ciphertext[RIGHT] = y_R;
}

/**
 * Probability of one round of Speck computed over the round keys and
 * the plaintexts.
 */
double speck_round_xdp_keys_plaintexts(const WORD_T dx[2], const WORD_T dy[2])
{
  uint32_t cnt_all = 0;
  uint32_t cnt = 0;
  for(WORD_T key_L = 0; key_L < ALL_WORDS; key_L++) {
#if SAME_KEY 
	 cnt_all = ALL_WORDS * ALL_WORDS * ALL_WORDS;
	 WORD_T key[2] = {key_L, key_L};
#else
	 cnt_all = ALL_WORDS * ALL_WORDS * ALL_WORDS * ALL_WORDS;
	 for(WORD_T key_R = 0; key_R < ALL_WORDS; key_R++) {
		WORD_T key[2] = {key_L, key_R};
#endif

		for(WORD_T x_L = 0; x_L < ALL_WORDS; x_L++) {
		  for(WORD_T x_R = 0; x_R < ALL_WORDS; x_R++) {

			 // first plaintext-ciphertext pair (x, y)
			 WORD_T x[2] = {x_L, x_R};
			 WORD_T y[2] = {0, 0};
			 speck_round_equiv(key, x, y);

			 // second plaintext-ciphertext pair (xx, yy)
			 WORD_T xx[2] = {(x_L ^ dx[LEFT]), (x_R ^ dx[RIGHT])};
			 WORD_T yy[2] = {0, 0};
			 speck_round_equiv(key, xx, yy);

			 WORD_T dy_tmp[2] = {(y[LEFT] ^ yy[LEFT]), (y[RIGHT] ^ yy[RIGHT])};

			 if((dy[LEFT] == dy_tmp[LEFT]) && (dy[RIGHT] == dy_tmp[RIGHT])) {
				cnt++;
			 }
		  }
		}
#if !SAME_KEY 
	 }
#endif 
  }
  double prob = (double)cnt / (double)cnt_all;
  return prob;
}

/**
 * Probability of one round of Speck computed over the round keys.
 */
double speck_round_xdp_keys(const WORD_T x_fixed[2], const WORD_T dx[2], const WORD_T dy[2])
{
  uint32_t cnt = 0;
  uint32_t cnt_all = 0;
  for(WORD_T key_L = 0; key_L < ALL_WORDS; key_L++) {
#if SAME_KEY 
	 cnt_all = ALL_WORDS;
	 WORD_T key[2] = {key_L, key_L};
#else
	 cnt_all = ALL_WORDS * ALL_WORDS;
	 for(WORD_T key_R = 0; key_R < ALL_WORDS; key_R++) {
		WORD_T key[2] = {key_L, key_R};
#endif

		// first plaintext-ciphertext pair (x, y)
		WORD_T x[2] = {x_fixed[LEFT], x_fixed[RIGHT]};
		WORD_T y[2] = {0, 0};
		speck_round_equiv(key, x, y);

		// second plaintext-ciphertext pair (xx, yy)
		WORD_T xx[2] = {(x_fixed[LEFT] ^ dx[LEFT]), (x_fixed[RIGHT] ^ dx[RIGHT])};
		WORD_T yy[2] = {0, 0};
		speck_round_equiv(key, xx, yy);

		WORD_T dy_tmp[2] = {(y[LEFT] ^ yy[LEFT]), (y[RIGHT] ^ yy[RIGHT])};

		if((dy[LEFT] == dy_tmp[LEFT]) && (dy[RIGHT] == dy_tmp[RIGHT])) {
		  cnt++;
		}
#if !SAME_KEY 
	 }
#endif 
  }

  double prob = (double)cnt / (double)cnt_all;
  return prob;
}

void test_speck_markov_property()
{
  WORD_T dx[2] = {0, 0};
  WORD_T dy[2] = {0, 0};

  dx[LEFT] = xrandom() & MASK;
  dx[RIGHT] = xrandom() & MASK;
  dy[LEFT] = xrandom() & MASK;
  dy[RIGHT] = xrandom() & MASK;

  for(dx[LEFT] = 0; dx[LEFT] < ALL_WORDS; dx[LEFT]++) {
	 for(dx[RIGHT] = 0; dx[RIGHT] < ALL_WORDS; dx[RIGHT]++) {
		for(dy[LEFT] = 0; dy[LEFT] < ALL_WORDS; dy[LEFT]++) {
		  for(dy[RIGHT] = 0; dy[RIGHT] < ALL_WORDS; dy[RIGHT]++) {
			 //			 printf("[%s:%d] dx (%X %X) -> dy (%X %X)\n", __FILE__, __LINE__,
			 //					  dx[LEFT], dx[RIGHT], dy[LEFT], dy[RIGHT]);
			 for(WORD_T x_L = 0; x_L < ALL_WORDS; x_L++) {
				for(WORD_T x_R = 0; x_R < ALL_WORDS; x_R++) {
				  WORD_T x_fixed[2] = {x_L, x_R};
				  double prob_keys_ptexts = speck_round_xdp_keys_plaintexts(dx, dy);
				  double prob_keys = speck_round_xdp_keys(x_fixed, dx, dy);
				  if(!(prob_keys_ptexts == prob_keys)) {
					 printf("[%s:%d] dx (%X %X) -> dy (%X %X)\n", __FILE__, __LINE__,
							  dx[LEFT], dx[RIGHT], dy[LEFT], dy[RIGHT]);
					 printf("[%s:%d] x_L x_R (%X %X) | 2^%f 2^%f\n", __FILE__, __LINE__, 
							  x_L, x_R, log2(prob_keys_ptexts), log2(prob_keys));
				  }
				  assert(prob_keys_ptexts == prob_keys);
				}
			 }
		  }
		}
	 }
  }
}

/**
 * Main function.
 */
int main (int argc, char *argv[])
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  %d NROUNDS %d\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS);
  srandom(time(NULL));
  test_speck_markov_property();
  return 0;
}
