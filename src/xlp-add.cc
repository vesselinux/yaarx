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
 * \file  xlp-add.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief The XOR linear probability of ADD \f$\mathrm{xlp}^{+}(ma,mb \rightarrow mb)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xlp-add.hh"
#endif

/**
 * The XOR linear probability of ADD (\f$\mathrm{xlp}^{+}\f$)
 * computed experimentally over all inputs. \b Complexity: \f$O(2^{2n})\f$.
 * 
 * XLP is the probability over the inputs a and b that the following
 * equation holds:
 *
 * (a . ma) ^ (b . mb) = (c . mc)
 *
 * where (x . ma) denotes the dot product between the word x and the
 * mask mx.
 *
 * \param ma first input mask.
 * \param mb second input mask.
 * \param mc output mask.
 * \param word_size word size in bits
 * \return \f$p = \mathrm{xlp}^{+}(ma, mb \rightarrow mc)\f$
 *
 * \see xlp_add
 */
double xlp_add_exper(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  assert(word_size <= WORD_SIZE);
  double p = 0.0;
#if(WORD_SIZE <= 16)
  WORD_MAX_T mask = (~0ULL >> (64 - word_size)); // full mask (word_size bits)
  uint64_t N = (1ULL << word_size);
  uint32_t cnt = 0;

  uint32_t all = N * N;				  // all input pairs

  for(WORD_T a = 0; a < N; a++) {
	 for(WORD_T b = 0; b < N; b++) {
		WORD_T c = ADD(a, b);

		WORD_T parity_a = parity(a & ma); // dot product (a . ma)
		WORD_T parity_b = parity(b & mb); // dot product (b . mb)
		WORD_T parity_c = parity(c & mc); // dot product (c . mc)

		// linear approximation: (a . ma) ^ (b . mb) = (c . mc)
		WORD_T leq = (parity_a ^ parity_b ^ parity_c) & mask;

		if(leq == 0)
		  cnt++;
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 16)
  return p;
}

/**
 * The absolute XOR linear correlation of ADD (\f$\mathrm{xlp}^{+}\f$)
 * \b Complexity: \f$O(n)\f$.
 * 
 * XCP is the correlation of the following linear approximation of
 * modular addition, computed over the inputs a and b 
 *
 * (a . ma) ^ (b . mb) = (c . mc)
 *
 * where (x . ma) denotes the dot product between the word x and the
 * mask mx.
 *
 * \param ma first input mask.
 * \param mb second input mask.
 * \param mc output mask.
 * \param word_size word size in bits
 * \return \f$p = \mathrm{xlp}^{+}(ma, mb \rightarrow mc)\f$
 *
 * \note Relations between linear probability, bias and correlation:
 *
 * bias = prob - 1/2
 * corr = (2 * bias) = (2 * prob) - 1
 *
 * \ref xlc_add is an optimized version
 *
 * \see xlc_add, xlp_add, xlp_add_exper
 *
 * Non-optimized version
 */
double xlc_add_nopt(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  assert(word_size <= WORD_SIZE);
  assert(word_size > 0);

#if 0 // DEBUG
  printf("[%s:%d] Enter %s() %X %X %X %d\n", __FILE__, __LINE__, __FUNCTION__, 
			ma, mb, mc, word_size);
#endif // #if 1 // DEBUG

#if 0 // DEBUG
  printf("ma = ");
  print_binary(ma);
  printf("\nmb = ");
  print_binary(mb);
  printf("\nmc = ");
  print_binary(mc);
  printf("\n");
#endif // #if 1 // DEBUG

  WORD_T w = 1; // absolute value in the exponent of the correlation
  WORD_T S[WORD_SIZE] = {0}; // max size
  for(uint32_t i = 0; i < word_size; i++) {

	 WORD_T ma_i = (ma >> i) & 1;
	 WORD_T mb_i = (mb >> i) & 1;
	 WORD_T mc_i = (mc >> i) & 1;

	 WORD_T word = (mc_i << 2) | (mb_i << 1) | (ma_i << 0);
	 assert((word >= 0) && (word <= 7));

	 // store the LSB at index S[word_size - 1] and the MSB at S[0]
	 S[word_size - i - 1] = word; 
	 //	 S[i] = word; 
	 //	 printf("%2d S[%2d] %d\n", i, (word_size - i - 1), S[word_size - i - 1]);
  }

#if 0 // DEBUG
  printf(" S = ");
  for(uint32_t i = 0; i < word_size; i++) {
	 printf("%d", S[i]);
  }
  printf("\n");
#endif // #if 1 // DEBUG

  uint32_t ibit = 0; // bit iterator
  uint32_t state = 0; // state: can be 0 or 1

  // { -----------

  while(ibit < word_size) {

	 const WORD_T index = ibit; // index of S
	 WORD_T cnt_b7 = 0; // counting 7-states

	 if(S[index] == 7) {

		assert(ibit == index);
		while(S[ibit] == 7) {
		  cnt_b7++; // count 7-block
		  ibit++; // move to next bit
		}
		w = w + (cnt_b7 / 2); // increase exponent by the number of 7-block tuples
		if(!is_even(cnt_b7)) { // if odd number of 7-blocks - change state from 0/1 tp 1/0
		  if(state == 1) {
			 w++;
		  }
		  state = 1 - state; // switch state
		  assert((state == 0) || (state == 1));
		}

		//		printf("[%s:%d] cnt_b7 = %d (cnt_b7 / 2) = %d state %d w %d\n", __FILE__, __LINE__, cnt_b7, cnt_b7 / 2, state, w);
	 }

	 if(S[index] == 0) {
		ibit++; // move to next bit
		if(state == 1) { // if at state 1 increase exponent
		  w = w + 1; // increase exponent
		}
	 }

	 if((S[index] == 1) || (S[index] == 2) || (S[index] == 4)) {
		if(state == 0) { /// if at state 0 halt (probability = 1/2, bias = 0)
		  // correlation 0
		  return 0.0;
		}
		state = 1 - state; // switch state
		assert((state == 0) || (state == 1));
		w = w + 1; // increase exponent
		ibit++; // move to next bit
	 }

	 if((S[index] == 3) || (S[index] == 5) || (S[index] == 6)) {
		if(state == 0) { /// if at state 0 halt (probability = 1/2, bias = 0)
		  // correlation 0
		  return 0.0;
		}
  		w = w + 1; // increase exponent
		ibit++; // move to next bit
	 }

  } // while

  // ----------- }

  //  printf("[%s:%d] w %d\n", __FILE__, __LINE__, w);

  w--; // corr = 2 * bias

  double corr_abs = 0.0;
  if (w == 64) {
	 corr_abs = pow(2, -64);
  } else {
	 corr_abs = (double) 1.0 / (double)(1ULL << w); // efficient pow(2, w)
  }

#if 0 // DEBUG
  printf("[%s:%d]  Exit %s() %X %X %X %d %4.2f\n", __FILE__, __LINE__, __FUNCTION__, 
			ma, mb, mc, word_size, corr_abs);
#endif // #if 1 // DEBUG
  //  printf("Exit corr_abs %4.2f w %d\n", corr_abs, w);
  return corr_abs;
}

/**
 * Compute the sign of the XOR linear correlation of ADD
 * (\f$\mathrm{xlp}^{+}\f$)
 * 
 * \param ma first input mask.
 * \param mb second input mask.
 * \param mc output mask.
 * \param word_size word size in bits
 * \return sign +1 or -1
 * \see xlc_add
 */
int xlc_add_sign(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  int sign = 1;
  WORD_MAX_T mask = (~0ULL >> (64 - word_size)); // full mask (word_size bits)
  WORD_T word = ((ma ^ mc) & (mb ^ mc)) & mask;
  if(!is_even(hamming_weight(word))) {
	 sign = -1;
  }
  return sign;
}

/**
 * The XOR linear probability of ADD (\f$\mathrm{xlp}^{+}\f$)
 * \b Complexity: \f$O(n)\f$.
 * 
 * XLP is the probability over the inputs a and b that the following
 * equation holds:
 *
 * (a . ma) ^ (b . mb) = (c . mc)
 *
 * where (x . ma) denotes the dot product between the word x and the
 * mask mx.
 *
 * xlp is computed from xlc using the relation:
 *
 * xlc = (2 * xlp) - 1
 *
 * together with the fact that the sign of xlc is -1 iff 
 * HW((ma ^ mc) & (mb ^ mc)) is odd.
 *
 * \param ma first input mask.
 * \param mb second input mask.
 * \param mc output mask.
 * \param word_size word size in bits
 * \return \f$p = \mathrm{xlp}^{+}(ma, mb \rightarrow mc)\f$
 *
 * \see xlc_add, xlc_add_sign
 */
double xlp_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  double corr_abs = xlc_add(ma, mb, mc, word_size);
  int sign = xlc_add_sign(ma, mb, mc, word_size);
  double corr = sign * corr_abs;
  //  double p = (corr + 1.0) / 2.0; <--- BUG!!
  //  printf("[%s:%d] corr %4.2f\n", __FILE__, __LINE__, corr);
  double p = 0.5 * (corr + 1.0);
  return p;
}

/**
 * Compute the bias of the following linear approximation of modular
 * addition:
 *
 * (a . ma) ^ (b . mb) = (c . mc)
 *
 * where (x . ma) denotes the dot product between the word x and the
 * mask mx.
 *
 * xlb is computed from xlp using the relation:
 *
 * xlb = xlp - 1/2
 *
 * \param ma first input mask.
 * \param mb second input mask.
 * \param mc output mask.
 * \param word_size word size in bits
 * \return \f$p = \mathrm{xlb}^{+}(ma, mb \rightarrow mc)\f$
 *
 * \see xlp_add, xlc_add, xlc_add_sign
 */
double xlb_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  double prob = xlp_add(ma, mb, mc, word_size);
  double bias = prob - 0.5;
  return bias;
}


