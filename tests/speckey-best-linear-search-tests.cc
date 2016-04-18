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
 * \file  speckey-best-linear-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu, Yann Le Corre, yann.lecorre@uni.lu
 * \date 2012-2016
 * \brief Automatic search for the best XOR differential trail in
 *        block cipher Speckey -- optimized version by Yann Le Corre..
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xlp-add.hh"
#endif

#if (WORD_SIZE != 16)
#error("WORD_SIZE must be 16")
#endif
#ifndef SPECKEY_LEFT_ROT_CONST
#define SPECKEY_LEFT_ROT_CONST 7
#endif
#ifndef SPECKEY_RIGHT_ROT_CONST
#define SPECKEY_RIGHT_ROT_CONST 2
#endif

const uint32_t g_r1 = SPECKEY_LEFT_ROT_CONST % WORD_SIZE; // rotation const. 2
const uint32_t g_r2 = SPECKEY_RIGHT_ROT_CONST % WORD_SIZE; // rotation const. 1

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
static inline void speckey_add_mask_to_trail(FullTrail &fullTrail, const uint32_t iround, const Correlation new_mask[2])
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
static inline void speckey_remove_mask_from_trail(FullTrail &fullTrail, const uint32_t iround)
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
static inline void speckey_clear_trail(FullTrail &fullTrail)
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
void speckey_print_linear_trail(FullTrail &T)
{
	int corr_trail = 0;
	for (unsigned int i = 0; i <= g_nRounds; i++)
	{
		fprintf(stdout, "%2d: M_LR %8X %8X %+4d %8X %8X %+4d\n", i, 
			  T[LEFT][i].oMaskL, T[LEFT][i].oMaskR, T[LEFT][i].c,
			  T[RIGHT][i].oMaskL, T[RIGHT][i].oMaskR, T[RIGHT][i].c
		);
#if(SPECKEY_VERSION == 2) // SPECKEY
		corr_trail += (T[LEFT][i].c + T[RIGHT][i].c);
#elif(SPECKEY_VERSION == 1) // Speckey
		corr_trail += T[LEFT][i].c;
#endif // #if(SPECKEY_VERSION == 2)
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
void speckey_round_masks_to_add_masks(
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
 * Search for the best linear trail of SPECK32/Speckey.
 *
 * \param iround current round: \f$ 0 \ge r < g_nRounds\f$
 * \param ibit current bit position (from w-1 to -1)
 * \param alpha first input mask to the 1st addition of round iround
 * \param beta second input mask to the 1st addition of round iround
 * \param gamma output mask from the1st addition of round iround
 * \param iGamma_R_in first right input mask to the iround-th round
 *                    (the left part is iGamma_L_in and the output
 *                    masks are oGamma_L and oGamma_R)
 * \see speckey_best_linear_search_i
 */
bool speckey_best_linear_search_i(
	const uint32_t iround,
	const int32_t ibit,
	const uint32_t alpha_in,
	const uint32_t beta_in,
	const uint32_t gamma_in,
	const uint32_t iGamma_R_in
)
{
	nNodes++;
	if (iround == 1)
	{
		if (ibit == -1)
		{
			const int c = xlc_add_log2(alpha_in, beta_in, gamma_in, WORD_SIZE);

			for (uint32_t iGamma_R = 0; iGamma_R < ALL_WORDS; iGamma_R++)
			{
				{
					uint32_t iGamma_L = alpha_in;
					const uint32_t oGamma_R = LROT((beta_in ^ iGamma_R), g_r2) & MASK;
					uint32_t oGamma_L = (gamma_in ^ oGamma_R) & MASK;

					if ((iGamma_L == 0) && (iGamma_R == 0))
					{
						/* skip the zero input masks */
						continue;
					}

					iGamma_L = LROT(alpha_in, g_r1) & MASK; // additional rot in the left input => rot left in order to store the mask to the addition (and not the mask to the round!)

					const Correlation T_zero[2] = {{iGamma_L, iGamma_R, 0}, {0, 0, 0}};
					speckey_add_mask_to_trail(g_T, iround - 1, T_zero);

					const Correlation T_one[2] = {{oGamma_L, oGamma_R, c}, {0, 0, 0}};
					speckey_add_mask_to_trail(g_T, iround, T_one);

					oGamma_L = RROT(oGamma_L, g_r1) & MASK;

					bool ret = speckey_best_linear_search_i(
						2,
						WORD_SIZE - 1, 
					   oGamma_L,
						0,
						0, 
						oGamma_R
					);
					if (ret == true)
					{
						return true;
					}

					speckey_remove_mask_from_trail(g_T, iround - 1);
					speckey_remove_mask_from_trail(g_T, iround);
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
					 bool ret = speckey_best_linear_search_i(
																		  iround,
																		  ibit - 1,
																		  alpha_part,
																		  beta_part,
																		  gamma_part,
																		  iGamma_R_in
																		  );
					 if (ret == true)
					 {
						  return true;
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

			const uint32_t oGamma_R = LROT((beta_in ^ iGamma_R_in), g_r2) & MASK;
		   uint32_t oGamma_L = (gamma_in ^ oGamma_R) & MASK;

			const Correlation T_iround[2] = {{oGamma_L, oGamma_R, c}, {0, 0, 0}};
			speckey_add_mask_to_trail(g_T, iround, T_iround);

			oGamma_L = RROT(oGamma_L, g_r1) & MASK;

			bool ret = speckey_best_linear_search_i(
				iround + 1,
				WORD_SIZE - 1, 
				oGamma_L,
				0,
				0, 
				oGamma_R
			);
			if (ret == true)
			{
				return true;
			}
			speckey_remove_mask_from_trail(g_T, iround);

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
				assert(d_i == 0);
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
					 bool ret = speckey_best_linear_search_i(
																		  iround,
																		  ibit - 1, 
																		  alpha_in,
																		  beta_part,
																		  gamma_part,
																		  iGamma_R_in
																		  );
					 if (ret == true)
					 {
						  return true;
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

			const uint32_t oGamma_R = LROT((beta_in ^ iGamma_R_in), g_r2) & MASK;
			const uint32_t oGamma_L = (gamma_in ^ oGamma_R) & MASK;

			const Correlation T_iround[2] = {{oGamma_L, oGamma_R, c}, {0, 0, 0}};

			speckey_add_mask_to_trail(g_T, iround, T_iround);

			/* c[1]d[1] c[2]d[2] ... c[iround]d[iround] => first iround rounds */
			int corr_trail = 0;
			for (uint32_t i = 1; i <= iround; i++)
			{
				int c_i = g_T[LEFT][i].c;
				int d_i = g_T[RIGHT][i].c;
				assert(d_i == 0);
				corr_trail += (c_i + d_i);
			}

			if (corr_trail >= g_Bn)
			{
				/* We have a winner ! */
				return true;
			}

			speckey_remove_mask_from_trail(g_T, iround);
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
				assert(d_i == 0);
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
					 bool ret = speckey_best_linear_search_i(
																		  iround,
																		  ibit - 1, 
																		  alpha_in,
																		  beta_part,
																		  gamma_part,
																		  iGamma_R_in
																		  );
					 if (ret == true)
					 {
						  return true;
					 }
				}
			}
		}
	}
	return false;
}

bool speckey_best_linear_search()
{
	nNodes = 0;
	speckey_clear_trail(g_T);
	return speckey_best_linear_search_i(1, WORD_SIZE - 1, 0, 0, 0, 0);
}

void speckey_find_bound(void)
{
	while (1)
	{
		fprintf(stdout, "-- g_Bn = %+3d ... ", g_Bn);
		fflush(stdout);
		std::chrono::seconds startTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
		bool found = speckey_best_linear_search();
		if (found == false)
		{
			fprintf(stdout, "no trail found! ");
			finalize(startTime);
		}
		else
		{
			fprintf(stdout, "trail found! ");
			finalize(startTime);
			speckey_print_linear_trail(g_T);
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
	fprintf(stdout, "# V%s: Searching for best linear trail for SPECK32/Speckey with WORD_SIZE = %u, r1 = %u, r2 = %u\n", STRINGIFY(SPECKEY_VERSION), WORD_SIZE, g_r1, g_r2);
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
		speckey_find_bound();
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
