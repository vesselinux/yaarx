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
 * \file  xlp-add.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Header file for xlp-add.cc: \copybrief xlp-add.cc.
 */ 
#ifndef XLP_ADD_H
#define XLP_ADD_H

double xlp_add_exper(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size);
double xlc_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size);
int xlc_add_sign(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size);
double xlp_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size);
double xlb_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size);

/**
 * Return the reverse of the ibit-th bit i.e. the bit at position
 * (word_size - ibit - 1)-th of masks ma, mb and mc as an octal word:
 * WORD_T word = (mc_i << 2) | (mb_i << 1) | (ma_i << 0);
 */
inline WORD_T get_masks_rev_ibit(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size, const WORD_T ibit)
{
  WORD_T i = (word_size - ibit - 1);
  //  WORD_T word = (((mc >> i) & 1) << 2) | (((mb >> i) & 1) << 1) | (((ma >> i) & 1) << 0);
  //  assert((word >= 0) && (word <= 7));
  //  return word;
  return (((mc >> i) & 1) << 2) | (((mb >> i) & 1) << 1) | (((ma >> i) & 1) << 0);
}

/**
 * Optimized version of xlc_add_nopt
 * \see xlc_add_nopt
 */
inline double xlc_add(const WORD_T ma, const WORD_T mb, const WORD_T mc, const WORD_T word_size)
{
  assert(word_size <= WORD_SIZE);
  assert(word_size > 0);

#if 1 // DEBUG
  printf("[%s:%d] Enter %s() %X %X %X %d\n", __FILE__, __LINE__, __FUNCTION__, 
			ma, mb, mc, word_size);
#endif // #if 1 // DEBUG

#if 1 // DEBUG
  printf("ma = ");
  print_binary(ma, word_size);
  printf("\nmb = ");
  print_binary(mb, word_size);
  printf("\nmc = ");
  print_binary(mc, word_size);
  printf("\n");
#endif // #if 1 // DEBUG

  WORD_T w = 1; // absolute value in the exponent of the correlation
  uint32_t ibit = 0; // bit iterator
  uint32_t state = 0; // state: can be 0 or 1

  // { -----------

  while(ibit < word_size) {

	 const WORD_T index = ibit; // index of S
	 WORD_T cnt_b7 = 0; // counting 7-states

	 WORD_T S_index = get_masks_rev_ibit(ma, mb, mc, word_size, index);

#if 1 // DEBUG
	 printf("[%s:%d] %2d S_index %2d\n", __FILE__, __LINE__, ibit, S_index);
	 if(!(get_masks_rev_ibit(ma, mb, mc, word_size, index) == S_index)) {
		WORD_T word = get_masks_rev_ibit(ma, mb, mc, word_size, index);
		printf("[%s:%d] ibit %d masks %X %X %X | word %X S %X\n", __FILE__, __LINE__, index, ma, mb, mc, word, S_index);
	 }
	 assert(get_masks_rev_ibit(ma, mb, mc, word_size, index) == S_index);
#endif // #if 0 // DEBUG

	 if(S_index == 7) {

		assert(ibit == index);

		while(get_masks_rev_ibit(ma, mb, mc, word_size, ibit) == 7) {
		  cnt_b7++; // count 7-block
		  ibit++; // move to next bit
		}
		//		w = w + (cnt_b7 / 2); // increase exponent by the number of 7-blocks divided by 2 (floor i.e. 1/2 = 1)
		w = w + (cnt_b7 >> 1); // increase exponent by the number of 7-blocks divided by 2 (floor i.e. 1/2 = 1)
		if(cnt_b7 & 1) { // if odd number of 7-blocks - change state from 0/1 tp 1/0
		  if(state == 1) {
			 w++;
		  }
		  state = 1 - state; // switch state
		  assert((state == 0) || (state == 1));
		}
		printf("[%s:%d] cnt_b7 = %d (cnt_b7 / 2) = %d state %d w %d\n", __FILE__, __LINE__, cnt_b7, cnt_b7 / 2, state, w);
	 }

	 if(S_index == 0) {
		ibit++; // move to next bit
		if(state == 1) { // if at state 1 increase exponent
		  w = w + 1; // increase exponent
		}
	 }

	 if((S_index == 1) || (S_index == 2) || (S_index == 4)) {
		if(state == 0) { /// if at state 0 halt (probability = 1/2, bias = 0)
		  // correlation 0
		  return 0.0;
		}
		state = 1 - state; // switch state
		assert((state == 0) || (state == 1));
		w = w + 1; // increase exponent
		ibit++; // move to next bit
	 }

	 if((S_index == 3) || (S_index == 5) || (S_index == 6)) {
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

#if 1 // DEBUG
  printf("[%s:%d]  Exit %s() %X %X %X %d %4.2f w %2d\n", __FILE__, __LINE__, __FUNCTION__, 
			ma, mb, mc, word_size, corr_abs, w);
#endif // #if 1 // DEBUG

  //  printf("Exit corr_abs %4.2f w %d\n", corr_abs, w);
  return corr_abs;
}

/**
 * The absolute XOR linear correlation of ADD (\f$\mathrm{xlp}^{+}\f$)
 * \b Complexity: \f$O(n)\f$.
 * 
 * XLC is the correlation of the following linear approximation of
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
 * Optimized version
 */
inline int xlc_add_log2(const uint32_t ma, const uint32_t mb, const uint32_t mc, const uint32_t word_size)
{
	assert(word_size <= WORD_SIZE);
	assert(word_size > 0);

	int w = -1; /* absolute value in the exponent of the correlation */
	uint32_t ibit = 0; /* bit iterator */
	uint32_t state = 0; /* state: can be 0 or 1 */

	while (ibit < word_size)
	{
		const uint32_t index = ibit;
		uint32_t cnt_b7 = 0; /* counting 7-states */
		uint32_t S_index = get_masks_rev_ibit(ma, mb, mc, word_size, index);

		switch (S_index)
		{
			case 0:
				ibit++; /* move to next bit */
				if (state == 1)
				{
					/* if at state 1 increase exponent */
					w = w - 1; /* increase exponent */
				}
				break;
			case 1:
			case 2:
			case 4:
				if(state == 0)
				{
					/* if at state 0 halt (probability = 1/2, bias = 0) */
					return LOG0;
				}
				state = 1 - state;
				assert((state == 0) || (state == 1));
				w = w - 1; /* increase exponent */
				ibit++; /* move to next bit */
				break;
			case 3:
			case 5:
			case 6:
				if (state == 0)
				{ /* if at state 0 halt (probability = 1/2, bias = 0) */
					return LOG0;
				}
				w = w - 1; /* increase exponent */
				ibit++; /* move to next bit */
				break;
			case 7:
				while (get_masks_rev_ibit(ma, mb, mc, word_size, ibit) == 7)
				{
					cnt_b7++;
					ibit++; /* move to next bit */
				}
				w = w - (cnt_b7 >> 1); /* increase exponent by the number of 7-block tuples */
				if (cnt_b7 & 1)
				{
					/* if odd number of 7-blocks - change state from 0/1 to 1/0 */
					if (state == 1)
					{
						w = w - 1;
					}
					state = 1 - state; /* switch state */
					assert((state == 0) || (state == 1));
				}
				break;
			default:
				fprintf(stderr, "-- S_index should never be %u. Exiting...\n", S_index);
				exit(-1);
				break;
		}
	}
	w++; /* corr = 2 * bias */
	return w;
}

#endif  // #ifndef XLP_ADD_H
