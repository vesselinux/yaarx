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
5B *    YAARX is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with YAARX.  If not, see <http://www.gnu.org/licenses/>.
 */
/**
 * \file  marx-best-linear-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu, Yann Le Corre, yann.lecorre@uni.lu
 * \date 2012-2016
 * \brief Automatic search for the best XOR differential trail in
 *        block cipher MARX -- optimized version by Yann Le Corre..
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xlp-add.hh"
#endif

#if (WORD_SIZE != 8)
#error("WORD_SIZE must be 8")
#endif
#ifndef MARX_LEFT_ROT_CONST
#define MARX_LEFT_ROT_CONST 3
#endif
#ifndef MARX_RIGHT_ROT_CONST
#define MARX_RIGHT_ROT_CONST 6
#endif
#ifndef MARX_LEFT_ROT_CONST_V2
#define MARX_LEFT_ROT_CONST_V2 6
#endif
#ifndef MARX_RIGHT_ROT_CONST_V2
#define MARX_RIGHT_ROT_CONST_V2 1
#endif

const uint32_t g_r1 = MARX_LEFT_ROT_CONST % WORD_SIZE; // rotation const. 2
const uint32_t g_r2 = MARX_RIGHT_ROT_CONST % WORD_SIZE; // rotation const. 1
const uint32_t g_r3 = MARX_LEFT_ROT_CONST_V2 % WORD_SIZE;
const uint32_t g_r4 = MARX_RIGHT_ROT_CONST_V2 % WORD_SIZE;

const std::array<int, 15> g_best_B_ref =
{{
	  0, // 1
	  0, // 2
	  0, // 3
	  0, // 4
	  0, // 5
	  0, // 6
	  0, // 7
	  0, // 8
	  0, // 9
	  0, // 10
	  0, // 11
	  0, // 12
	  0, // 13
	  0, // 14
	  0, // 15
}};

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)

/**
  * Correlation structure
  */
typedef struct {
	uint32_t oMaskL; /* left output mask */
	uint32_t oMaskR; /* right output mask */
	int c;	/* correlation */
} Correlation;

enum Side {LEFT = 0, RIGHT = 1};
typedef std::array<Correlation, g_best_B_ref.size() + 1> SideTrail;
typedef std::array<SideTrail, 2> FullTrail;

/* Globals */
std::array<int, g_best_B_ref.size()> g_best_B;
int g_Bn;
FullTrail g_T;
uint64_t nNodes;
unsigned int g_nRounds;


/**
 * Print number of visited nodes and computation speed
 */
void finalize(std::chrono::seconds startTime)
{
    std::chrono::seconds stopTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
    unsigned long int duration = stopTime.count() - startTime.count();
    double speed;
    if (duration != 0)
    {
        speed = double(nNodes)/double(duration);
    }
    else
    {
        speed = nan("");
    }
    fprintf(stdout, "[%lu s] {%lu nodes -> %g nodes/s}\n", duration, nNodes, speed);
}

/**
 * Add new element at position i in the trail fullTrail
 * \se speck_add_mask_to_trail
 */
static inline void marx_add_mask_to_trail(FullTrail &fullTrail, const uint32_t iround, const Correlation new_mask[2])
{
	for (unsigned int i = 0; i < 2; i++)
	{
		/* left, right */
		assert(iround < (g_nRounds + 1));
		/* YLC */
		if (fullTrail[i][iround].oMaskL != 0)
		{
			printf("i = %u, iround = %u", i, iround);
		}
		assert(fullTrail[i][iround].oMaskL == 0);
		assert(fullTrail[i][iround].oMaskR == 0);
		assert(fullTrail[i][iround].c == LOG0);

		fullTrail[i][iround].oMaskL = new_mask[i].oMaskL;
		fullTrail[i][iround].oMaskR = new_mask[i].oMaskR;
		fullTrail[i][iround].c = new_mask[i].c;
	}
}

/**
 * Remove element from position i in the trail fullTrail (sets differences and
 * prob. to zero)
 * \see speck_remove_mask_from_trail
 */
static inline void marx_remove_mask_from_trail(FullTrail &fullTrail, const uint32_t iround)
{
	assert(iround < (g_nRounds + 1));

	for (unsigned int i = 0; i < 2; i++)
	{
		/* left,right */
		fullTrail[i][iround].oMaskL = 0; 
		fullTrail[i][iround].oMaskR = 0;
		fullTrail[i][iround].c = LOG0;
	}
}

/**
 * Clear trail fullTrail
 */
static inline void marx_clear_trail(FullTrail &fullTrail)
{
	for (unsigned int i = 0; i < fullTrail[0].size(); i++)
	{
		fullTrail[LEFT][i] = {0, 0, LOG0};
		fullTrail[RIGHT][i] = {0, 0, LOG0};
	}
}

/**
 * Print trail T up to- and including round nrounds
 * \see speck_print_linear_trail
 */
void marx_print_linear_trail(FullTrail &T)
{
	int corr_trail = 0;
	for (unsigned int i = 0; i <= g_nRounds; i++)
	{
		fprintf(stdout, "%2d: M_LR %8X %8X %+4d %8X %8X %+4d\n", i, 
			  T[LEFT][i].oMaskL, T[LEFT][i].oMaskR, T[LEFT][i].c,
			  T[RIGHT][i].oMaskL, T[RIGHT][i].oMaskR, T[RIGHT][i].c
		);
#if(MARX_VERSION == 2) // MARX
		corr_trail += (T[LEFT][i].c + T[RIGHT][i].c);
#elif(MARX_VERSION == 1) // Speckey
		corr_trail += T[LEFT][i].c;
#endif // #if(MARX_VERSION == 2)
	}
	fprintf(stdout, "corr_trail %+d\n", corr_trail);
}

/**
 * From the input and output masks of one round, extract the input and
 * output masks of the addtion, using the following relations:
 *
 * alpha_i = ml_{i-1}
 * beta_i = mr_{i-1} ^ (mr_i >>> rot_const)
 * gamma_i = ml_i ^ mr_i
 *
 * \param ml_prev left input mask to one round
 * \param mr_prev right input mask to one round
 * \param ml left output mask from one round
 * \param mr right output mask from one round
 * \param alpha first input mask to the modular adition of one round
 * \param beta second input mask to the modular adition of one round
 * \param gamma output mask from the modular adition of one round
 *
 * \see speck_round_masks_to_add_masks
 */
void marx_round_masks_to_add_masks(
	/* input masks */
	const uint32_t ml_prev,
	const uint32_t mr_prev,
	/* output masks */
	const uint32_t ml,
	const uint32_t mr,
	const uint32_t rot_const,
	uint32_t *alpha,
	uint32_t *beta,
	uint32_t *gamma
)
{
  assert(0 == 1);
  *alpha = ml_prev;
  *beta = (mr_prev ^ RROT(mr, rot_const));
  *gamma = (ml ^ mr);
}

/**
 * Search for the best linear trail of MARX (Threefish-256/MIX + ARX)
 *
 * \param iround current round: \f$ 0 \ge r < g_nRounds\f$
 * \param ibit current bit position (from w-1 to -1)
 * \param alpha first input mask to the 1st addition of round iround
 * \param beta second input mask to the 1st addition of round iround
 * \param gamma output mask from the1st addition of round iround
 * \param delta first input mask to the 2nd  addition of round iround
 * \param lambda second input mask to the 2nd addition of round iround
 * \param eta output mask from the 2nd addition of round iround
 * \param iGamma_R_in first right input mask to the iround-th round
 *                    (the left part is iGamma_L_in and the output
 *                    masks are oGamma_L and oGamma_R)
 * \param iLambda_R_in second right input mask to the iround-th round
 *                     (the left part is iLambda_L_in and the output
 *                     masks are oLambda_L and oLambda_R)
 *
 * \see speck_best_linear_search_i
 */
bool marx_best_linear_search_i(
	const uint32_t iround,
	const int32_t ibit,
	const uint32_t alpha_in,
	const uint32_t beta_in,
	const uint32_t gamma_in,
	const uint32_t delta_in,
	const uint32_t lambda_in,
	const uint32_t eta_in,
	const uint32_t iGamma_R_in,
	const uint32_t iLambda_R_in
)
{
	nNodes++;
	if (iround == 1)
	{
		if (ibit == -1)
		{
			const int c = xlc_add_log2(alpha_in, beta_in, gamma_in, WORD_SIZE);
			const int d = xlc_add_log2(delta_in, lambda_in, eta_in, WORD_SIZE);

			for (uint32_t iGamma_R = 0; iGamma_R < ALL_WORDS; iGamma_R++)
			{
				for (uint32_t iLambda_R = 0; iLambda_R < ALL_WORDS; iLambda_R++)
				{
					const uint32_t iGamma_L = RROT(alpha_in, g_r3); // input mask to the round
					const uint32_t iLambda_L = RROT(delta_in, g_r4);

					const uint32_t oGamma_R = LROT((lambda_in ^ iLambda_R), g_r2);
					uint32_t oLambda_L = (eta_in ^ oGamma_R) & MASK;
					const uint32_t oLambda_R = LROT((beta_in ^ iGamma_R), g_r1);
					uint32_t oGamma_L = (gamma_in ^ oLambda_R) & MASK;

					if ((iGamma_L == 0) && (iGamma_R == 0) && (iLambda_L == 0) && (iLambda_R == 0))
					{
						/* skip the zero input masks */
						continue;
					}

					const Correlation T_zero[2] = {{iGamma_L, iGamma_R, 0}, {iLambda_L, iLambda_R, 0}};
					marx_add_mask_to_trail(g_T, iround - 1, T_zero);

					const Correlation T_one[2] = {{oGamma_L, oGamma_R, c}, {oLambda_L, oLambda_R, d}};
					marx_add_mask_to_trail(g_T, iround, T_one);

					oGamma_L = RROT(oGamma_L, g_r3);
					oLambda_L = RROT(oLambda_L, g_r4);

					bool ret = marx_best_linear_search_i(
						2,
						WORD_SIZE - 1, 
					   oGamma_L,
						0,
						0, 
						oLambda_L,
						0,
						0,
						oGamma_R,
						oLambda_R
					);
					if (ret == true)
					{
						return true;
					}

					marx_remove_mask_from_trail(g_T, iround - 1);
					marx_remove_mask_from_trail(g_T, iround);
				}
			}
		} else {
			const uint32_t word_size = (WORD_SIZE - ibit); /* word size of the partial masks: ibit = (WORD_SIZE - 1) down to 0 */
			const uint32_t mask_part = (~((uint32_t)0) >> (32 - word_size)); /* partial mask (word_size bits) */

			for (uint32_t w = 0; w < 8; w++)
			{
				const uint32_t alpha_i = (w >> 0) & 1;
				const uint32_t beta_i = (w >> 1) & 1;
				const uint32_t gamma_i = (w >> 2) & 1;

				const uint32_t alpha_part = alpha_in | (alpha_i << ibit);
				const uint32_t beta_part = beta_in | (beta_i << ibit);
				const uint32_t gamma_part = gamma_in | (gamma_i << ibit);

				/* Extract the word_size MS bits of alpha_part, beta_part,
				   gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
				*/
				const uint32_t alpha_part_msb = (alpha_part >> ibit) & mask_part;
				const uint32_t beta_part_msb = (beta_part >> ibit) & mask_part;
				const uint32_t gamma_part_msb = (gamma_part >> ibit) & mask_part;

				const int c_part = xlc_add_log2(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); /* partial prob. */
				const int c_est = c_part + g_best_B[g_nRounds - 2];

				if (c_est >= g_Bn)
				{
					for (uint32_t v = 0; v < 8; v++)
					{
						const uint32_t delta_i = (v >> 0) & 1;
						const uint32_t lambda_i = (v >> 1) & 1;
						const uint32_t eta_i = (v >> 2) & 1;

						const uint32_t delta_part = delta_in | (delta_i << ibit);
						const uint32_t lambda_part = lambda_in | (lambda_i << ibit);
						const uint32_t eta_part = eta_in | (eta_i << ibit);

						/* Extract the word_size MS bits of delta_part, lambda_part,
						   eta_part:(MSB delta_in | ibit | 000000..000 LSB)
						*/
						const uint32_t delta_part_msb = (delta_part >> ibit) & mask_part;
						const uint32_t lambda_part_msb = (lambda_part >> ibit) & mask_part;
						const uint32_t eta_part_msb = (eta_part >> ibit) & mask_part;

						const int d_part = xlc_add_log2(delta_part_msb, lambda_part_msb, eta_part_msb, word_size); /* partial prob. */
						const int cd_est = c_est + d_part;

						if (cd_est >= g_Bn)
						{
							bool ret = marx_best_linear_search_i(
								iround,
								ibit - 1,
								alpha_part,
								beta_part,
								gamma_part,
								delta_part,
								lambda_part,
								eta_part,
								iGamma_R_in,
								iLambda_R_in
							);
							if (ret == true)
							{
								return true;
							}
						}
					}
				}
			}
		}
	}

	if ((iround > 1) && (iround != g_nRounds))
	{
		if (ibit == -1)
		{
			const int c = xlc_add_log2(alpha_in, beta_in, gamma_in, WORD_SIZE);
			const int d = xlc_add_log2(delta_in, lambda_in, eta_in, WORD_SIZE);

			const uint32_t oGamma_R = LROT((lambda_in ^ iLambda_R_in), g_r2);
			uint32_t oLambda_L = (eta_in ^ oGamma_R) & MASK;
			const uint32_t oLambda_R = LROT((beta_in ^ iGamma_R_in), g_r1);
			uint32_t oGamma_L = (gamma_in ^ oLambda_R) & MASK;

			const Correlation T_iround[2] = {{oGamma_L, oGamma_R, c}, {oLambda_L, oLambda_R, d}};
			marx_add_mask_to_trail(g_T, iround, T_iround);

			oGamma_L = RROT(oGamma_L, g_r3);
			oLambda_L = RROT(oLambda_L, g_r4);

			bool ret = marx_best_linear_search_i(
				iround + 1,
				WORD_SIZE - 1, 
				oGamma_L,
				0,
				0, 
				oLambda_L,
				0,
				0,
				oGamma_R,
				oLambda_R
			);
			if (ret == true)
			{
				return true;
			}
			marx_remove_mask_from_trail(g_T, iround);
		} else {
			const uint32_t word_size = (WORD_SIZE - ibit); /* word size of the partial masks */
			const uint32_t mask_part = (~((uint32_t)0) >> (32 - word_size)); /* partial mask of word_size MS bits = 0000000FFF */
			const uint32_t mask_msb = (~((uint32_t)0) << ibit) & MASK; /* masks word_size MS bits = FFF000000 */

			int corr_trail = 0;
			/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] => first
			   (iround - 1) rounds: c[0] = d[0] = 0 is the input mask corr.
			*/
			for (uint32_t i = 1; i < iround; i++)
			{
				int c_i = g_T[LEFT][i].c;
				int d_i = g_T[RIGHT][i].c;
				corr_trail += (c_i + d_i);
			}

			for (uint32_t w = 0; w < 4; w++)
			{
				const uint32_t beta_i = (w >> 0) & 1;
				const uint32_t gamma_i = (w >> 1) & 1;

				const uint32_t alpha_part = (alpha_in & mask_msb);
				const uint32_t beta_part = beta_in | (beta_i << ibit);
				const uint32_t gamma_part = gamma_in | (gamma_i << ibit);

				/* Extract the word_size MS bits of alpha_part, beta_part,
				   gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
				*/
				const uint32_t alpha_part_msb = (alpha_part >> ibit) & mask_part;
				const uint32_t beta_part_msb = (beta_part >> ibit) & mask_part;
				const uint32_t gamma_part_msb = (gamma_part >> ibit) & mask_part;

				const int c_part = xlc_add_log2(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); /* partial prob. */

				/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] (c_part = c[iround]) => first iround rounds */
				const int c_est = corr_trail + c_part + g_best_B[g_nRounds - iround - 1];

				if (c_est >= g_Bn)
				{
					for (uint32_t v = 0; v < 4; v++)
					{
						const uint32_t lambda_i = (v >> 0) & 1;
						const uint32_t eta_i = (v >> 1) & 1;

						const uint32_t delta_part = (delta_in & mask_msb);
						const uint32_t lambda_part = lambda_in | (lambda_i << ibit);
						const uint32_t eta_part = eta_in | (eta_i << ibit);

						/* Extract the word_size MS bits of delta_part, lambda_part,
						   eta_part:(MSB delta_in | ibit | 000000..000 LSB)
						*/
						const uint32_t delta_part_msb = (delta_part >> ibit) & mask_part;
						const uint32_t lambda_part_msb = (lambda_part >> ibit) & mask_part;
						const uint32_t eta_part_msb = (eta_part >> ibit) & mask_part;

						const int d_part = xlc_add_log2(delta_part_msb, lambda_part_msb, eta_part_msb, word_size); /* partial prob. */

						/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] (c_part = c[iround]) => first iround rounds */
						const int cd_est = c_est + d_part;

						if (cd_est >= g_Bn)
						{
							bool ret = marx_best_linear_search_i(
								iround,
								ibit - 1, 
								alpha_in,
								beta_part,
								gamma_part,
								delta_in,
								lambda_part,
								eta_part,
								iGamma_R_in,
								iLambda_R_in
							);
							if (ret == true)
							{
								return true;
							}
						}
					}
				}
			}
		}
	}

	if (iround == g_nRounds)
	{
		if (ibit == -1)
		{
			const int c = xlc_add_log2(alpha_in, beta_in, gamma_in, WORD_SIZE);
			const int d = xlc_add_log2(delta_in, lambda_in, eta_in, WORD_SIZE);

			const uint32_t oGamma_R = LROT((lambda_in ^ iLambda_R_in), g_r2);
			const uint32_t oLambda_R = LROT((beta_in ^ iGamma_R_in), g_r1);
			const uint32_t oGamma_L = (gamma_in ^ oLambda_R) & MASK;
			const uint32_t oLambda_L = (eta_in ^ oGamma_R) & MASK;

			const Correlation T_iround[2] = {{oGamma_L, oGamma_R, c}, {oLambda_L, oLambda_R, d}};

			marx_add_mask_to_trail(g_T, iround, T_iround);

			/* c[1]d[1] c[2]d[2] ... c[iround]d[iround] => first iround rounds */
			int corr_trail = 0;
			for (uint32_t i = 1; i <= iround; i++)
			{
				int c_i = g_T[LEFT][i].c;
				int d_i = g_T[RIGHT][i].c;
				corr_trail += (c_i + d_i);
			}

			if (corr_trail >= g_Bn)
			{
				/* We have a winner ! */
				return true;
			}

			marx_remove_mask_from_trail(g_T, iround);
		} else {
			const uint32_t word_size = (WORD_SIZE - ibit); /* word size of the partial masks */
			const uint32_t mask_part = (~((uint32_t)0) >> (32 - word_size)); /* partial mask of word_size MS bits = 0000000FFF */
			const uint32_t mask_msb = (~((uint32_t)0) << ibit) & MASK; /* masks word_size MS bits = FFF000000 */

			int corr_trail = 0;
			/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] => first
			   (iround - 1) rounds: c[0] = d[0] = 1.0 is the input mask corr
			*/
			for (uint32_t i = 1; i < iround; i++)
			{
				int c_i = g_T[LEFT][i].c;
				int d_i = g_T[RIGHT][i].c;
				corr_trail += (c_i + d_i);
			}

			for (uint32_t w = 0; w < 4; w++)
			{
				const uint32_t beta_i = (w >> 0) & 1;
				const uint32_t gamma_i = (w >> 1) & 1;

				const uint32_t alpha_part = (alpha_in & mask_msb);
				const uint32_t beta_part = beta_in | (beta_i << ibit);
				const uint32_t gamma_part = gamma_in | (gamma_i << ibit);

				/* Extract the word_size MS bits of alpha_part, beta_part,
				   gamma_part:(MSB alpha_in | ibit | 000000..000 LSB)
				*/
				const uint32_t alpha_part_msb = (alpha_part >> ibit) & mask_part;
				const uint32_t beta_part_msb = (beta_part >> ibit) & mask_part;
				const uint32_t gamma_part_msb = (gamma_part >> ibit) & mask_part;

				const int c_part = xlc_add_log2(alpha_part_msb, beta_part_msb, gamma_part_msb, word_size); /* partial prob. */

				/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] (c_part = c[iround]) => first iround rounds */
				const int c_est = corr_trail + c_part;

				if (c_est >= g_Bn)
				{
					for (uint32_t v = 0; v < 4; v++)
					{
						const uint32_t lambda_i = (v >> 0) & 1;
						const uint32_t eta_i = (v >> 1) & 1;

						const uint32_t delta_part = (delta_in & mask_msb);
						const uint32_t lambda_part = lambda_in | (lambda_i << ibit);
						const uint32_t eta_part = eta_in | (eta_i << ibit);

						/* Extract the word_size MS bits of delta_part, lambda_part,
						   eta_part:(MSB delta_in | ibit | 000000..000 LSB)
						*/
						const uint32_t delta_part_msb = (delta_part >> ibit) & mask_part;
						const uint32_t lambda_part_msb = (lambda_part >> ibit) & mask_part;
						const uint32_t eta_part_msb = (eta_part >> ibit) & mask_part;

						const int d_part = xlc_add_log2(delta_part_msb, lambda_part_msb, eta_part_msb, word_size); /* partial prob. */

						/* c[1]d[1] c[2]d[2] ... c[iround - 1]d[iround - 1] (c_part = c[iround]) => first iround rounds */
						const int cd_est = c_est + d_part;

						if (cd_est >= g_Bn)
						{
							bool ret = marx_best_linear_search_i(
								iround,
								ibit - 1, 
								alpha_in,
								beta_part,
								gamma_part,
								delta_in,
								lambda_part,
								eta_part,
								iGamma_R_in,
								iLambda_R_in
							);
							if (ret == true)
							{
								return true;
							}
						}
					}
				}
			}
		}
	}
	return false;
}

bool marx_best_linear_search()
{
	nNodes = 0;
	marx_clear_trail(g_T);
	return marx_best_linear_search_i(1, WORD_SIZE - 1, 0, 0, 0, 0, 0, 0, 0, 0);
}

void marx_find_bound(void)
{
	while (1)
	{
		fprintf(stdout, "-- g_Bn = %+3d ... ", g_Bn);
		fflush(stdout);
		std::chrono::seconds startTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
		bool found = marx_best_linear_search();
		if (found == false)
		{
			fprintf(stdout, "no trail found! ");
			finalize(startTime);
		}
		else
		{
			fprintf(stdout, "trail found! ");
			finalize(startTime);
			marx_print_linear_trail(g_T);
			break;
		}
		g_Bn--;
	}
}


/**
 * Main function.
 */
int main(int argc, char *argv[])
{
	fprintf(stdout, "########################################################################################\n");
	fprintf(stdout, "# V%s: Searching for best linear trail for MARX with WORD_SIZE = %u, r1 = %u, r2 = %u, r3 = %u, r4 = %u\n", STRINGIFY(MARX_VERSION), WORD_SIZE, g_r1, g_r2, g_r3, g_r4);
	fprintf(stdout, "########################################################################################\n");

	FILE *summaryFileHandle = stdout;
	int opt;
	while ((opt = getopt(argc, argv, "s:")) != -1)
	{
		switch (opt)
		{
			case 's':
				summaryFileHandle = fopen(optarg, "w");
				fprintf(stdout, "-- Generating summary file \"%s\"\n", optarg);
				break;
			case '?':
				fprintf(stderr, "Usage: %s <-s summaryFileName>\n", argv[0]);
				exit(-1);
				break;
		}
	}

	//	g_best_B = g_best_B_ref;
	g_best_B.fill(0);
	for (g_nRounds = 2; g_nRounds < g_best_B.size() + 1; g_nRounds++)
	{
		fprintf(stdout, "-- g_nRounds = %u\n", g_nRounds);
		g_Bn = g_best_B[g_nRounds - 2];
		marx_find_bound();
		g_best_B[g_nRounds - 1] = g_Bn;
		if (summaryFileHandle != stdout)
		{
			fprintf(summaryFileHandle, "%u,%+d\n", g_nRounds, g_Bn);
			fflush(summaryFileHandle);
		}
		if (g_Bn <= -17)
		{
			break;
		}
	}

	if (summaryFileHandle != stdout)
	{
		fclose(summaryFileHandle);
	}

	return 0;
}
