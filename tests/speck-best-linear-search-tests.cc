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
 * \file  speck-best-linear-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Tests for automatic search for the best XOR linear
 *        trail in block cipher Speck .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif
#ifndef ADP_XOR_H
#include "xlp-add.hh"
#endif

#if (WORD_SIZE <= 16)
const uint32_t g_r1 = SPECK_RIGHT_ROT_CONST_16BITS % WORD_SIZE; // rotation const. 1
const uint32_t g_r2 = SPECK_LEFT_ROT_CONST_16BITS % WORD_SIZE; // rotation const. 2
#else // (WORD_SIZE > 16)
const uint32_t g_r1 = SPECK_RIGHT_ROT_CONST; // rotation const. 1
const uint32_t g_r2 = SPECK_LEFT_ROT_CONST; // rotation const. 2
#endif // #if (WORD_SIZE <= 16)

const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  0)), // 2
  (1.0 / (double)(1ULL <<  1)), // 3
  (1.0 / (double)(1ULL <<  3)), // 4
  (1.0 / (double)(1ULL <<  5)), // 5
  (1.0 / (double)(1ULL <<  7)), // 6
  (0.0 / (double)(1ULL <<  9)), // 7
  (0.0 / (double)(1ULL << 12)), // 8
  (0.0 / (double)(1ULL << 14)), // 9
  (0.0 / (double)(1ULL << 17)), // 10
};
/**
 * If UPDATE_BOUND is false then the algorithm will find ALL trails
 * with probability (g_Bn * EPS) or higher.
 */
#define UPDATE_BOUND false
#define EPS (1.0 / (double)(1ULL <<  1))
double g_Bn = g_best_B[NROUNDS - 1] * EPS; // underestimated bound for round n
differential_t g_T[NROUNDS + 1] = {{0, 0, 0, 0.0}}; // trail
differential_t g_best_T[NROUNDS + 1] = {{0, 0, 0, 0.0}}; // best trail

/**
 * From the input and output masks of one round, extract the input and
 * output masks of the linear addtion, using the following relations:
 *
 * \param ml_prev left input mask to one round
 * \param mr_prev right input mask to one round
 * \param ml left output mask from one round
 * \param mr right output mask from one round
 * \param alpha first input mask to the modular adition of one round
 * \param beta second input mask to the modular adition of one round
 * \param gamma output mask from the modular adition of one round
 *
 * alpha_i = ml_{i-1} >>> r1
 * beta_i = mr_{i-1} ^ (mr_i >>> r2)
 * gamma_i = ml_i ^ mr_i
 *
 */
void speck_round_masks_to_add_masks(const WORD_T ml_prev, const WORD_T mr_prev, // input masks
												const WORD_T ml, const WORD_T mr, // output masks
												WORD_T* alpha, WORD_T* beta, WORD_T* gamma)
{
  //  printf("\n[%s:%d] %s() M_LR (%X %X) -> (%X %X) r1 %d r2 %d\n", __FILE__, __LINE__, __FUNCTION__, 
  //			ml_prev, mr_prev, ml, mr, g_r1, g_r2);
  *alpha = (RROT(ml_prev, g_r1)) & MASK;
  *beta = (mr_prev ^ RROT(mr, g_r2)) & MASK;
  *gamma = (ml ^ mr) & MASK;
  //  printf("[%s:%d] alpha beta gamma %X %X %X\n", __FILE__, __LINE__, *alpha, *beta, *gamma);
}

void speck_print_linear_trail(differential_t T[NROUNDS + 1])
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  double p = 1.0;
  for(uint32_t i = 0; i <= NROUNDS; i++) {
	 printf("%2d: M_LR %8X %8X %4.2f 2^%4.2f ", i, T[i].dx, T[i].dy, T[i].p, log2(T[i].p));

#if 1 // DEBUG
	 // check for consistency
	 if(i > 0) {
		const WORD_T ml_prev = T[i-1].dx;
		const WORD_T mr_prev = T[i-1].dy;
		const WORD_T ml = T[i].dx;
		const WORD_T mr = T[i].dy;
		const double corr = T[i].p;
		WORD_T alpha = 0;
		WORD_T beta = 0;
		WORD_T gamma = 0;
		speck_round_masks_to_add_masks(ml_prev, mr_prev, ml, mr, &alpha, &beta, &gamma);
		const double corr_tmp = xlc_add(alpha, beta, gamma, WORD_SIZE);
		printf(" | m_abc %X %X -> %X %4.2f\n", alpha, beta, gamma, corr_tmp);
		assert(corr == corr_tmp);
	 } else {
		printf("\n");
	 }
#else
	 printf("\n");
#endif // #if 1 // DEBUG


	 p *= T[i].p;
  }
  printf("corr_trail %f %4.2f\n", p, log2(p));
}

/*
 * Print just the input and outpt masks
 */
void speck_print_linear_hull(differential_t T[NROUNDS + 1])
{
  double p = 1.0;
  for(uint32_t i = 0; i <= NROUNDS; i++) {
	 if((i == 0) || (i == NROUNDS)) {
		printf("%8X %8X ", T[i].dx, T[i].dy);
	 }
#if 1 // DEBUG
	 // check for consistency
	 if(i > 0) {
		const WORD_T ml_prev = T[i-1].dx;
		const WORD_T mr_prev = T[i-1].dy;
		const WORD_T ml = T[i].dx;
		const WORD_T mr = T[i].dy;
		const double corr = T[i].p;
		WORD_T alpha = 0;
		WORD_T beta = 0;
		WORD_T gamma = 0;
		speck_round_masks_to_add_masks(ml_prev, mr_prev, ml, mr, &alpha, &beta, &gamma);
		const double corr_tmp = xlc_add(alpha, beta, gamma, WORD_SIZE);
		assert(corr == corr_tmp);
	 } 
#endif // #if 1 // DEBUG

	 p *= T[i].p;
  }
  printf("%4.0f\n", log2(p));
}

void speck_print_linear_trail(differential_t T[NROUNDS + 1], uint32_t nrounds)
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  double p = 1.0;
  for(uint32_t i = 0; i <= nrounds; i++) {
	 printf("%2d: M_LR %8X %8X %4.2f 2^%4.2f ", i, T[i].dx, T[i].dy, T[i].p, log2(T[i].p));

#if 1 // DEBUG
	 // check for consistency
	 if(i > 0) {
		const WORD_T ml_prev = T[i-1].dx;
		const WORD_T mr_prev = T[i-1].dy;
		const WORD_T ml = T[i].dx;
		const WORD_T mr = T[i].dy;
		const double corr = T[i].p;
		WORD_T alpha = 0;
		WORD_T beta = 0;
		WORD_T gamma = 0;
		speck_round_masks_to_add_masks(ml_prev, mr_prev, ml, mr, &alpha, &beta, &gamma);
		const double corr_tmp = xlc_add(alpha, beta, gamma, WORD_SIZE);
		printf(" | m_abc %X %X -> %X %4.2f\n", alpha, beta, gamma, corr_tmp);
		assert(corr == corr_tmp);
	 } else {
		printf("\n");
	 }
#else
	 printf("\n");
#endif // #if 1 // DEBUG


	 p *= T[i].p;
  }
  printf("corr_trail %f %4.2f\n", p, log2(p));
}

/**
 * Add new element at position i in the trail T
 */
void speck_add_mask_to_trail(differential_t T[NROUNDS + 1], const uint32_t i, const differential_t new_mask)
{
#if 0
  printf("[%s:%d] %s() iround %2d / %2d add (%X %X)\n", __FILE__, __LINE__, __FUNCTION__, 
			i, NROUNDS, new_mask.dx, new_mask.dy);
#endif

  assert(i < (NROUNDS + 1));
  assert(T[i].dx == 0);
  assert(T[i].dy == 0);
  assert(T[i].npairs == 0);
  assert(T[i].p == 0.0);

  T[i].dx = new_mask.dx;
  T[i].dy = new_mask.dy;
  T[i].npairs = new_mask.npairs;
  T[i].p = new_mask.p;

  //  speck_print_linear_trail(g_T, i);

#if 0 // DEBUG
  // check for consistency
  if(i > 0) {
	 const WORD_T ml_prev = T[i-1].dx;
	 const WORD_T mr_prev = T[i-1].dy;
	 const WORD_T ml = T[i].dx;
	 const WORD_T mr = T[i].dy;
	 const double corr = T[i].p;
	 WORD_T alpha = 0;
	 WORD_T beta = 0;
	 WORD_T gamma = 0;
	 speck_round_masks_to_add_masks(ml_prev, mr_prev, ml, mr, &alpha, &beta, &gamma);
	 const double corr_tmp = xlc_add(alpha, beta, gamma, WORD_SIZE);
	 if(!(corr == corr_tmp)) {
		printf("%2d: M_LR %8X %8X %4.2f 2^%4.2f ", i, T[i].dx, T[i].dy, T[i].p, log2(T[i].p));
		printf(" | m_abc %X %X -> %X %4.2f\n", alpha, beta, gamma, corr_tmp);
	 }
	 assert(corr == corr_tmp);
  } 
#endif // #if 1 // DEBUG

}

/**
 * Remove element from position i in the trail T (sets differences and
 * prob. to zero)
 */
void speck_remove_mask_from_trail(differential_t T[NROUNDS + 1], const uint32_t i)
{
  assert(i < (NROUNDS + 1));

  T[i].dx = 0; 
  T[i].dy = 0;
  T[i].npairs = 0;
  T[i].p = 0.0;
}

/**
 * Copy trail from_T to to_T
 */
void speck_copy_linear_trail(const differential_t from_T[NROUNDS + 1], differential_t to_T[NROUNDS + 1])
{
  for(uint32_t i = 0; i < (NROUNDS + 1); i++) {
	 to_T[i].dx = from_T[i].dx; 
	 to_T[i].dy = from_T[i].dy;
	 to_T[i].npairs = from_T[i].npairs;
	 to_T[i].p = from_T[i].p;
  }
}

/**
 * Print the trail in C-style
 * \see speck_print_linear_trail
 */
void speck_print_linear_trail_cstyle(differential_t T[NROUNDS + 1])
{
  printf("differential_t g_T[NROUNDS + 1] = {\n");
  for(uint32_t i = 0; i <= NROUNDS; i++) {
	 printf("{%8X, %8X, %d, (1.0 / (double)(1ULL <<  %d))},\n", T[i].dx, T[i].dy, T[i].npairs, (uint32_t)log2(T[i].p));
  }
  printf("};");
}

/**
 * Full search for the best linear trail of block cipher SPECK
 * (non-recursive).
 *
 * \note Feasible for up to 4 bit words and up to 3 rounds.
 * \note The complexity is 2^{(n+1) (2*w)}, where n is the total number of
 *       rounds and w is the word size. Therefore this function is
 *       exponential in the word size and in the number of rounds.
 *
 * The structure \p differential_t contains left and right linear
 * masks ml_i and ml_i, input to round i,  organized as follow:
 *
 * T[0] = ml_0, mr_1, 1.0
 * T[1] = ml_1, mr_1, corr_1
 * ...
 * T[i] = ml_i, mr_i, corr_i
 * ...
 * T[r] = ml_r, mr_r, corr_r
 *
 * such that corr_i = corr(ml_{i-1}, mr_{i-1} -> ml_i, mr_i) is the
 * correlation that inout mask propagates to output mask. 
 *
 * The input/output masks alpha_i, beta_i, gamma_i to the modular
 * addition at round i are related to the input/output masks ml_{i-1},
 * mr_{i-1}, ml_i, mr_i of round i as follow:
 *
 * alpha_i = ml_{i-1} >>> r1
 * beta_i = mr_{i-1} ^ (mr_i >>> r2)
 * gamma_i = ml_i ^ mr_i
 *
 * \see speck_best_trail_search_full
 */
void speck_best_linear_search_full(differential_t T_best[NROUNDS + 1], // best trail for n rounds
											  double* corr_best) // best correlation for n rounds
{
#if (WORD_SIZE <= 4) && (NROUNDS <= 3)

  double corr_max = 0.0;
  WORD_T npairs = 0; // dummy
  uint64_t nmasks = (1ULL << ((NROUNDS + 1) * (2 * WORD_SIZE)));
  printf("[%s:%d] nmasks 2^%2.0f\n", __FILE__, __LINE__, log2(nmasks));

  for(uint64_t masks_i = 1; masks_i < nmasks; masks_i++) {

	 differential_t T[NROUNDS + 1] ={0, 0, 0, 0.0};
	 uint32_t r = 0;
	 const WORD_T mr_0 = (masks_i >> (r * WORD_SIZE)) & MASK;
	 const WORD_T ml_0 = (masks_i >> ((r+1) * WORD_SIZE)) & MASK;
	 r += 2;
	 const double corr_0 = 1.0;

	 T[0] = {ml_0, mr_0, npairs, corr_0};

	 for(uint32_t j = 1; j <= NROUNDS; j++, r += 2) {

		const WORD_T ml_prev = T[j-1].dx;
		const WORD_T mr_prev = T[j-1].dy;

		const WORD_T mr = (masks_i >> (r * WORD_SIZE)) & MASK;
		const WORD_T ml = (masks_i >> ((r+1) * WORD_SIZE)) & MASK;

		WORD_T alpha_r = 0;
		WORD_T beta_r = 0;
		WORD_T gamma_r = 0;

		speck_round_masks_to_add_masks(ml_prev, mr_prev, ml, mr, &alpha_r, &beta_r, &gamma_r);

		const double corr_r = xlc_add(alpha_r, beta_r, gamma_r, WORD_SIZE);

		T[j] = {ml, mr, npairs, corr_r};

	 }

	 double corr_tot = 1.0;
	 for(uint32_t j = 0; j <= NROUNDS; j++) {
		corr_tot *= T[j].p;
	 }

	 if(corr_tot >= corr_max) {
		if(corr_max) {
		  printf("[%s:%d] Update corr %4.2f -> %4.2f\n", __FILE__, __LINE__, log2(corr_max), log2(corr_tot));
		  speck_print_linear_trail(T);
		}
		corr_max = corr_tot;
		for(uint32_t j = 0; j <= NROUNDS; j++) {
		  T_best[j].dx = T[j].dx;
		  T_best[j].dy = T[j].dy;
		  T_best[j].p = T[j].p;
		}
	 }

  }
  *corr_best = corr_max;
#endif // #if #if (WORD_SIZE <= 4) && (NROUNDS <= 3)
}

/**
 * Search for the best linear trail of block cipher SPECK.
 *
 * \param iround current round: \f$ 0 \ge r < NROUNDS\f$
 * \param ibit current bit position (from w-1 to -1)
 * \param alpha first input mask to the addition of round iround
 * \param beta second input mask to the addition of round iround
 * \param gamma output mask from the addition of round iround
 * \param imask_R_in right input mask to the iround-th round
 *
 * \see speck_best_diff_search_i
 */
void speck_best_linear_search_i(const uint32_t iround, // current round
										  const int32_t ibit, // current bit position
										  const WORD_T alpha_in, // input mask to the addition of round iround
										  const WORD_T beta_in, // input mask to the addition of round iround
										  const WORD_T gamma_in, // output mask from the addition of round iround
										  const WORD_T imask_R_in) // right input mask to the iround-th round
{
#if 0 // DEBUG
  printf("[%s:%d] Enter iround %d ibit %d diffs %X %X %X %X\n", __FILE__, __LINE__, 
			iround, ibit, alpha_in, beta_in, gamma_in, imask_R_in);
#endif // #if 1 // DEBUG

  if((iround == 1) && (iround != NROUNDS)) {

	 if(ibit == -1) {

		const double corr = xlc_add(alpha_in, beta_in, gamma_in, WORD_SIZE);

		for(WORD_T imask_R = 0; imask_R < ALL_WORDS; imask_R++) {
		// WARNINIG!! no loop
		//		{
		  //		  WORD_T imask_R = (RROT(gamma_in, g_r2) ^ beta_in) & MASK;
		  const WORD_T imask_L = LROT(alpha_in, g_r1) & MASK;

		  //		  printf("[%s:%d] imask_L %X imask_R %X g_Bn %4.2f\n", __FILE__, __LINE__, imask_L, imask_R, g_Bn);
		  if((imask_L == 0) && (imask_R == 0)) // skip the zero input masks
			 continue;
			 //			 return;

		  const WORD_T omask_R = LROT((beta_in ^ imask_R), g_r2) & MASK;
		  const WORD_T omask_L = (gamma_in ^ omask_R) & MASK;

		  const differential_t new_mask_zero = {imask_L, imask_R, 0, 1.0};
		  const differential_t new_mask_one = {omask_L, omask_R, 0, corr};

		  speck_add_mask_to_trail(g_T, iround - 1, new_mask_zero);
		  speck_add_mask_to_trail(g_T, iround, new_mask_one);

		  const WORD_T alpha_next = RROT(omask_L, g_r1);
		  const WORD_T beta_next = 0;
		  const WORD_T gamma_next = 0;

		  speck_best_linear_search_i(iround + 1, WORD_SIZE - 1, alpha_next, beta_next, gamma_next, omask_R);

		  speck_remove_mask_from_trail(g_T, iround - 1);
		  speck_remove_mask_from_trail(g_T, iround);

		}

	 } else {

		const WORD_T word_size = (WORD_SIZE - ibit); // word size of the
																	// partial masks: ibit = (WORD_SIZE - 1) down to 0
		const WORD_MAX_T mask_part = (~0ULL >> (64 - word_size)); // partial mask (word_size bits)
		assert(hamming_weight(mask_part) == word_size);

		for(WORD_T w = 0; w < 8; w++) {

		  const WORD_T alpha_i = (w >> 0) & 1;
		  const WORD_T beta_i = (w >> 1) & 1;
		  const WORD_T gamma_i = (w >> 2) & 1;

		  const WORD_T alpha_part = alpha_in | (alpha_i << ibit);
		  const WORD_T beta_part = beta_in | (beta_i << ibit);
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);

		  // Extract the word_size MS bits of alpha_part, beta_part,
		  // gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
		  const WORD_T alpha_part_msb = (alpha_part >> ibit) & mask_part;
		  const WORD_T beta_part_msb = (beta_part >> ibit) & mask_part;
		  const WORD_T gamma_part_msb = (gamma_part >> ibit) & mask_part;

		  double corr_part = xlc_add(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); // partial prob.
		  double corr_est = corr_part * g_best_B[NROUNDS - 2];

#if 0 // DEBUG
		  printf("[%s:%d] word_size %2d %8X %8X -> %8X %4.2f\n", __FILE__, __LINE__, word_size, 
					alpha_part_msb, beta_part_msb, gamma_part_msb, corr_part);
#endif // #if 0 // DEBUG

		  if(corr_est >= g_Bn) {
			 speck_best_linear_search_i(iround, ibit - 1, alpha_part, beta_part, gamma_part, imask_R_in);
		  }

		}

	 }

  } // ((iround == 1) && (iround != NROUNDS))

  if((iround > 1) && (iround != NROUNDS)) {

	 if(ibit == -1) {

		const double corr = xlc_add(alpha_in, beta_in, gamma_in, WORD_SIZE);
		//		const WORD_T imask_L = LROT(alpha_in, g_r1) & MASK;
		const WORD_T imask_R = imask_R_in;
		const WORD_T omask_R = LROT((beta_in ^ imask_R), g_r2) & MASK;
		const WORD_T omask_L = (gamma_in ^ omask_R) & MASK;
		const differential_t new_mask = {omask_L, omask_R, 0, corr};

#if 0
		printf("\n[%s:%d] alpha_in beta_in gamma_in %X %X -> %X %4.2f 2^%4.2f\n", __FILE__, __LINE__,
				 alpha_in, beta_in, gamma_in, corr, log2(corr));
		printf("\n%2d: M_LR (%8X %8X) -> (%8X %8X) %4.2f 2^%4.2f\n", iround, 
				 imask_L, imask_R, omask_L, omask_R, corr, log2(corr));

		printf("[%s:%d] imask_L %X g_T[%d].dx %X\n", __FILE__, __LINE__, imask_L, iround - 1, g_T[iround - 1].dx);
		printf("[%s:%d] imask_R %X g_T[%d].dy %X\n", __FILE__, __LINE__, imask_R, iround - 1, g_T[iround - 1].dy);

		assert(imask_L == g_T[iround - 1].dx);
		assert(imask_R == g_T[iround - 1].dy);
#endif 

		speck_add_mask_to_trail(g_T, iround, new_mask);

		const WORD_T alpha_next = RROT(omask_L, g_r1) & MASK;
		const WORD_T beta_next = 0;
		const WORD_T gamma_next = 0;

		speck_best_linear_search_i(iround + 1, WORD_SIZE - 1, alpha_next, beta_next, gamma_next, omask_R);

		speck_remove_mask_from_trail(g_T, iround);

	 } else {

		const WORD_T word_size = (WORD_SIZE - ibit); // word size of the partial masks
		const WORD_MAX_T mask_part = (~0ULL >> (64 - word_size)); // partial mask of word_size MS bits = 0000000FFF
		const WORD_MAX_T mask_msb = (~0ULL << ibit) & MASK; // masks word_size MS bits = FFF000000

		for(WORD_T w = 0; w < 4; w++) {

		  const WORD_T beta_i = (w >> 0) & 1;
		  const WORD_T gamma_i = (w >> 1) & 1;

		  const WORD_T alpha_part = (alpha_in & mask_msb);
		  const WORD_T beta_part = beta_in | (beta_i << ibit);
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);

		  // Extract the word_size MS bits of alpha_part, beta_part,
		  // gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
		  const WORD_T alpha_part_msb = (alpha_part >> ibit) & mask_part;
		  const WORD_T beta_part_msb = (beta_part >> ibit) & mask_part;
		  const WORD_T gamma_part_msb = (gamma_part >> ibit) & mask_part;

		  double corr_part = xlc_add(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); // partial prob.

		  double corr_est = 1.0;
		  // c[1] c[2] ... c[iround - 1] => first (iround - 1) rounds: c[0] = 1.0 is the input mask corr
		  for(uint32_t i = 1; i < iround; i++) {
			 double corr_i = g_T[i].p;
			 corr_est *= corr_i;
		  }
		  // c[1] c[2] ... c[iround - 1] (c_part = c[iround]) => first iround rounds
		  corr_est = corr_est * corr_part * g_best_B[NROUNDS - iround - 1];

#if 0 // DEBUG
		  printf("[%s:%d] ibit %2d mask_msb %llX alpha_in %X alpha_part %X\n", __FILE__, __LINE__,
					ibit, mask_msb, alpha_in, alpha_part);
#endif // #if 1 // DEBUG

		  if(corr_est >= g_Bn) {
			 speck_best_linear_search_i(iround, ibit - 1, alpha_in, beta_part, gamma_part, imask_R_in); // <-- BUG alpha_part
		  }
		}

	 }

  } // ((iround > 1) && (iround != NROUNDS))

  if(iround == NROUNDS) {

	 if(ibit == -1) {

		const double corr = xlc_add(alpha_in, beta_in, gamma_in, WORD_SIZE);
		const WORD_T imask_R = imask_R_in;
		const WORD_T omask_R = LROT((beta_in ^ imask_R), g_r2) & MASK;
		const WORD_T omask_L = (gamma_in ^ omask_R) & MASK;
		const differential_t new_mask = {omask_L, omask_R, 0, corr};

		speck_add_mask_to_trail(g_T, iround, new_mask);

		// c[1] c[2] ... c[iround] => first iround rounds
		double corr_trail = 1.0;
		for(uint32_t i = 1; i <= iround; i++) {
		  double corr_i = g_T[i].p;
		  corr_trail *= corr_i;
		}

		if(corr_trail >= g_Bn) {
		  /**
			* If UPDATE_BOUND is false then the algorithm will find ALL trails
			* with probability (g_Bn * EPS) or higher.
			*/
#if (UPDATE_BOUND == true)
		  printf("[%s:%d] Update bound: %4.2f -> %4.2f\n", __FILE__, __LINE__, log2(g_Bn), log2(corr_trail));
		  g_Bn = corr_trail;
#endif // #if UPDATE_BOUND
#if 0
		  speck_print_linear_trail(g_T);
#endif
#if 1
		  speck_print_linear_hull(g_T);
#endif
		  speck_copy_linear_trail(g_T, g_best_T);
		}

		speck_remove_mask_from_trail(g_T, iround);

	 } else {

		const WORD_T word_size = (WORD_SIZE - ibit); // word size of the partial masks
		const WORD_MAX_T mask_part = (~0ULL >> (64 - word_size)); // partial mask of word_size MS bits = 0000000FFF
		const WORD_MAX_T mask_msb = (~0ULL << ibit) & MASK; // masks word_size MS bits = FFF000000

		for(WORD_T w = 0; w < 4; w++) {

		  const WORD_T beta_i = (w >> 0) & 1;
		  const WORD_T gamma_i = (w >> 1) & 1;

		  const WORD_T alpha_part = (alpha_in & mask_msb);
		  const WORD_T beta_part = beta_in | (beta_i << ibit);
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);

		  // Extract the word_size MS bits of alpha_part, beta_part,
		  // gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
		  const WORD_T alpha_part_msb = (alpha_part >> ibit) & mask_part;
		  const WORD_T beta_part_msb = (beta_part >> ibit) & mask_part;
		  const WORD_T gamma_part_msb = (gamma_part >> ibit) & mask_part;

		  double corr_part = xlc_add(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); // partial prob.

		  double corr_est = 1.0;
		  // c[1] c[2] ... c[iround - 1] => first (iround - 1) rounds: c[0] = 1.0 is the input mask corr
		  for(uint32_t i = 1; i < iround; i++) {
			 double corr_i = g_T[i].p;
			 corr_est *= corr_i;
		  }
		  // c[1] c[2] ... c[iround - 1] (c_part = c[iround]) => first iround rounds
		  corr_est = corr_est * corr_part;

#if 0 // DEBUG
		  printf("[%s:%d] ibit %2d mask_msb %llX alpha_in %X alpha_part %X\n", __FILE__, __LINE__,
					ibit, mask_msb, alpha_in, alpha_part);
#endif // #if 1 // DEBUG

		  if(corr_est >= g_Bn) {
			 speck_best_linear_search_i(iround, ibit - 1, alpha_in, beta_part, gamma_part, imask_R_in); // <- BUG! alpha_part
		  }
		}

	 }

  } // (iround == NROUNDS)

}

void speck_best_linear_search()
{
#if (NROUNDS > 1)
  uint32_t r = 1;
  int32_t i = (WORD_SIZE - 1); // initialize at the MSB
  WORD_T alpha = 0;
  WORD_T beta = 0;
  WORD_T gamma = 0;
  WORD_T mask_R = 0;

  speck_best_linear_search_i(r, i, alpha, beta, gamma, mask_R);

  printf("[%s:%d] Best linear trail on %d rounds (WORD_SIZE %d bits):\n", __FILE__, __LINE__, NROUNDS, WORD_SIZE);
  speck_print_linear_trail(g_best_T);
  speck_print_linear_trail_cstyle(g_best_T);
#endif // #if (NROUNDS == 4)
}

/** 
  * Given an XOR linear trail for \f$N\f$ rounds, experimentally
  * verify the probabilities of the corresponding \f$N\f$ one-round
  * linear approximations:
  *
  *       - Approximation for 1 round: round 0. 
  *       - Approximation for 2 rounds: rounds \f$0,1\f$. 
  *       - Approximation for 3 rounds: rounds \f$0,1,2\f$. 
  *       - \f$\ldots\f$
  *       - Approximation for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
  *
  * bias = prob - 1/2
  * corr = (2 * bias) = (2 * prob) - 1
  *
  * \see speck_verify_xor_trail
  */
void speck_verify_linear_trail(const uint32_t nrounds, const uint32_t npairs, 
										 const WORD_T master_key[SPECK_MAX_NROUNDS], 
										 const differential_t T[NROUNDS + 1])
{
#if (WORD_SIZE >= 16)
  uint32_t key_size = speck_get_keysize(WORD_SIZE);
  uint32_t nkey_words = speck_compute_nkeywords(WORD_SIZE, key_size);
  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < SPECK_MAX_NROUNDS; i++) {
	 key[i] = master_key[i];
  }
  speck_key_expansion(key, nrounds, nkey_words, g_r1, g_r2);

  //  printf("Input masks: %16llX %16llX\n\n", (WORD_MAX_T)ML_in, (WORD_MAX_T)MR_in);
  //  double corr_the = 1.0;
  for(uint32_t i = 1; i <= nrounds; i++) {

	 //	 uint32_t enc_nrounds = i;
	 uint32_t enc_nrounds = 1; // always encrypt for 1 round as we are
										// checking a trail (as opposed to a
										// differential)
	 uint32_t cnt = 0;

	 WORD_T ML_in = T[i-1].dx;		  // left paintext mask
	 WORD_T MR_in = T[i-1].dy;		  // right plaintext mask
	 WORD_T ML_out = T[i].dx;	  // left ciphertext mask
	 WORD_T MR_out = T[i].dy;	  // right ciphertext mask
	 double corr_the = T[i].p; // "theoretical" correlation

	 WORD_T alpha = 0;
	 WORD_T beta = 0;
	 WORD_T gamma = 0;
	 speck_round_masks_to_add_masks(ML_in, MR_in, ML_out, MR_out, &alpha, &beta, &gamma);
	 const double corr_xlc = xlc_add(alpha, beta, gamma, WORD_SIZE);
#if 0 // DEBUG
	 printf("%2d: M_LR %8X %8X -> %8X %8X | m_abc %8X %8X -> %8X %4.2f 2^%4.2f\n", i, ML_in, MR_in, ML_out, MR_out, 
			  alpha, beta, gamma, corr_xlc, log2(corr_xlc));
#endif // #if 1 // DEBUG

	 for(uint64_t j = 0; j < npairs; j++) {
		WORD_T x_L = xrandom() & MASK; // plaintext left
		WORD_T x_R = xrandom() & MASK; // plaintext right
		WORD_T y_L = x_L; // ciphertext left
		WORD_T y_R = x_R;	// ciphertext right

		speck_encrypt(key, enc_nrounds, g_r1, g_r2, &y_L, &y_R);

		WORD_T parity_x_L = parity(x_L & ML_in); // dot product (x_L . ML_in)
		WORD_T parity_x_R = parity(x_R & MR_in); // dot product (x_R . MR_in)

		WORD_T parity_y_L = parity(y_L & ML_out); // dot product (y_L . ML_out)
		WORD_T parity_y_R = parity(y_R & MR_out); // dot product (y_R . MR_out)

		// linear approximation: (a . ma) ^ (b . mb) = (c . mc) ^ (d . md)
		WORD_T leq = (parity_x_L ^ parity_x_R ^ parity_y_L ^ parity_y_R);

		assert((leq == 0) || (leq == 1));

		if(leq == 0) {
		  cnt++;
		}
	 }
	 double prob = (double)cnt / (double)npairs; // experimental correlation
	 double bias = std::abs(prob - 0.5);
	 double corr_exp = (2.0 * bias);
#if 1 // DEBUG
	 printf("R#%2d %8X %8X -> %8X %8X 2^%4.2f 2^%4.2f 2^%4.2f\n", i, ML_in, MR_in, ML_out, MR_out, log2(corr_the), log2(corr_xlc), log2(corr_exp));
#endif // #if 1 // DEBUG
	 assert(corr_xlc == corr_the);
  }
#endif // #if (WORD_SIZE >= 16)
}

// --- TESTS ---

differential_t g_meiqin_T32[NROUNDS_MAX + 1] = {
  {    0xA0,   0x629, 0, (1.0 / (double)(1ULL <<  0))},
  {  0x78A0,  0x18A1, 0, (1.0 / (double)(1ULL <<  1))},
  {    0x90,  0x6021, 0, (1.0 / (double)(1ULL <<  4))},
  {  0x6080,  0x4081, 0, (1.0 / (double)(1ULL <<  1))},
  {    0x80,     0x1, 0, (1.0 / (double)(1ULL <<  1))},
  {     0x1,       0, 0, (1.0 / (double)(1ULL <<  0))},
  {   0xE00,   0xC00, 0, (1.0 / (double)(1ULL <<  1))},
  {  0x3040,  0x3058, 0, (1.0 / (double)(1ULL <<  3))},
  {    0x82,  0xC0E2, 0, (1.0 / (double)(1ULL <<  2))},
  {  0x1F8E,  0x1B8F, 0, (1.0 / (double)(1ULL <<  1))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
};

differential_t g_vpv_T32[NROUNDS_MAX + 1] = {
  {    0xA0,  0x3021, 0, (1.0 / (double)(1ULL <<  0))},
  {    0x80,  0x4081, 0, (1.0 / (double)(1ULL <<  1))},
  {   0x200,   0x201, 0, (1.0 / (double)(1ULL <<  0))},
  {   0x818,   0x81C, 0, (1.0 / (double)(1ULL <<  1))},
  {  0x8000,  0xA010, 0, (1.0 / (double)(1ULL <<  2))},
  {  0x85C2,  0x8442, 0, (1.0 / (double)(1ULL <<  1))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
  {       0,       0, 0, (1.0 / (double)(1ULL <<  0))},
};

void test_speck_verify_linear_trail()
{
#if (WORD_SIZE == 16)
  assert(WORD_SIZE == 16);
  uint32_t npairs = (1ULL << 23);
  WORD_T key[SPECK_MAX_NROUNDS] = {0};
  key[0] = xrandom() & MASK;
  key[1] = xrandom() & MASK;
  key[2] = xrandom() & MASK;
  key[3] = xrandom() & MASK;
#if (WORD_SIZE == 16)
  //  speck_verify_linear_trail(NROUNDS, npairs, key, g_meiqin_T32);
  speck_verify_linear_trail(NROUNDS, npairs, key, g_vpv_T32);
#endif // #if (WORD_SIZE == 16)
#endif // #if (WORD_SIZE == 16)
}

void test_speck_best_linear_search_full()
{
  differential_t T[NROUNDS + 1] = {{0, 0, 0, 0.0}};
  double corr_best = 0.0;
  speck_best_linear_search_full(T, &corr_best);
  printf("[%s:%d] Best trail for %d rounds (word size %d bits) p 2^%4.2f\n", __FILE__, __LINE__, NROUNDS, WORD_SIZE, log2(corr_best));
  speck_print_linear_trail(T);
  speck_print_linear_trail_cstyle(T);
}

/**
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  %d NROUNDS %d UPDATE_BOUND %d r1 %d r2 %d g_Bn 2^%4.2f\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS, UPDATE_BOUND, g_r1, g_r2, log2(g_Bn));
  srandom(time(NULL));

  //  test_speck_best_linear_search_full();
  //  test_speck_verify_linear_trail();
  speck_best_linear_search();
  return 0;
}
