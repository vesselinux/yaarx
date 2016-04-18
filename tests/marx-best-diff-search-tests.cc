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
 * \file  marx-best-diff-search-opt-tests.cc 
 * \author V. Velichkov, Y. Le Corre
 * \date 2012-2016
 * \brief Automatic search for the best XOR differential trail in
 *        block cipher MARX .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
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
 * A differential composed of three differences.
 * For example, da and db can be input differences to XOR
 * and dc can be the corresponding output difference.
 * The differential holds with probability p.
 */
typedef struct
{
	WORD_T dx;  /**< Input difference. */
	WORD_T dy;  /**< Input difference. */
	WORD_T dz;  /**< Output difference. */
	int p;      /**< Log base 2 of the probability */
	int cp;     /**< Cumulated log base 2 of the trail probability */
} Differential;

enum Side {LEFT = 0, RIGHT = 1};
typedef std::array<Differential, g_best_B_ref.size()> SideTrail;
typedef std::array<SideTrail, 2> FullTrail;

/* Globals */
std::array<int, 15> g_best_B = {{0}};
int g_Bn;
FullTrail g_T;
uint64_t g_nNodes;
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
		speed = double(g_nNodes)/double(duration);
	}
	else
	{
		speed = nan("");
	}
	fprintf(stdout, "[%lu s] {%lu nodes -> %g nodes/s}\n", duration, g_nNodes, speed);
}

/**
 * Add new element at position i in the trail sideTrail
 */
static inline void marx_add_diff_to_trail(SideTrail &sideTrail, const uint32_t i, const Differential new_diff)
{
	assert(i < g_nRounds);
	assert(sideTrail[i].p == LOG0);
	std::memcpy(&(sideTrail[i]), &new_diff, sizeof(Differential));
}

/**
 * Remove element from position i in the trail sideTrail (sets differences and
 * prob. to zero)
 */
static inline void marx_remove_diff_from_trail(SideTrail &sideTrail, const uint32_t i)
{
	sideTrail[i].p = LOG0;;
}

/**
 * Clear trail fullTrail
 */
static inline void marx_init_diff_trail(FullTrail &fullTrail)
{
	for (uint32_t i = 0; i < 2; i++)
	{
		fullTrail[i].fill({0, 0, 0, LOG0, LOG0});
	}
}

/**
 * Print the trail fullTrail
 */
void marx_print_diff_trail(FullTrail fullTrail)
{
	int p = 0;
	for (uint32_t i = 0; i < g_nRounds; i++)
	{
		fprintf(stdout, "%2d: %8X %8X -> %8X %+4d [%+4d] | ", i, fullTrail[LEFT][i].dx, fullTrail[LEFT][i].dy, fullTrail[LEFT][i].dz, fullTrail[LEFT][i].p, fullTrail[LEFT][i].cp);
		fprintf(stdout, "%8X %8X -> %8X %+4d [%+4d]\n", fullTrail[RIGHT][i].dx, fullTrail[RIGHT][i].dy, fullTrail[RIGHT][i].dz, fullTrail[RIGHT][i].p, fullTrail[RIGHT][i].cp);
#if(MARX_VERSION == 2) // MARX
		p += (fullTrail[LEFT][i].p + fullTrail[RIGHT][i].p);
#elif(MARX_VERSION == 1) // Speckey
		p += fullTrail[LEFT][i].p;
#endif // #if(MARX_VERSION == 2)
	}
	fprintf(stdout, "p_trail = %+d\n", p);
}

void fprintTrailLatex(FILE *fh, FullTrail g_T)
{
	fprintf(fh, "\n%%------------------------trail start----------------------------------------\n");
	fprintf(fh, "\\begin{table}[ht]\n");
	fprintf(fh, "\\caption{Best differential trail for word size %d rounds %d}\n", WORD_SIZE, g_nRounds);
	fprintf(fh, "\\begin{center}\n");
	fprintf(fh, "\\begin{tabular}{c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}}\n");
	fprintf(fh, "\\toprule\n");
	fprintf(fh, "$r$ & $\\alpha$ & $\\beta$ & $\\gamma$ & $\\mathrm{log}_2 p$ & $\\delta$ & $\\lambda$ & $\\eta$ & $\\mathrm{log}_2 p$\\\\\n");
	fprintf(fh, "\\midrule\n");
	for (uint32_t i = 0; i < g_nRounds; i++)
	{
		fprintf(fh, "$%2d$ & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} & $%+4d$", i, g_T[LEFT][i].dx, g_T[LEFT][i].dy, g_T[LEFT][i].dz, g_T[LEFT][i].p);
		fprintf(fh, " & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} & $%+4d$ \\\\\n", g_T[RIGHT][i].dx, g_T[RIGHT][i].dy, g_T[RIGHT][i].dz, g_T[RIGHT][i].p);
    }
	fprintf(fh, "\\bottomrule\n");
	fprintf(fh, "\\end{tabular}\n");
	fprintf(fh, "\\end{center}\n");
	fprintf(fh, "\\end{table}\n");
	fprintf(fh, "%%------------------------trail end----------------------------------------\n");
}

/**
 * Search for the best differential trail of MARX (MIX-ARX)
 *
 * \param iround current round: \f$ 0 \ge r < g_nRounds\f$
 * \param ibit current bit position
 * \param alpha first input difference to the addition of round iround
 * \param beta second input difference to the addition of round iround
 * \param gamma output difference from the addition of round iround
 *
 * \see speck_best_diff_search_i
 */
bool marx_best_diff_search_i(
	const uint32_t iround,
	const uint32_t ibit,
	const WORD_T alpha_in,
	const WORD_T beta_in,
	const WORD_T gamma_in,
	const WORD_T delta_in,
	const WORD_T lambda_in,
	const WORD_T eta_in
)
{
	g_nNodes++;
	if (iround == 1)
	{
		if (ibit == WORD_SIZE)
		{
			if (!((alpha_in == 0) && (beta_in == 0) && (delta_in == 0) && (lambda_in == 0)))
			{
				/* discard zero input diff */
				const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
				const Differential new_diff_left = {alpha_in, beta_in, gamma_in, p, p};
				marx_add_diff_to_trail(g_T[LEFT], iround - 1, new_diff_left);

				const int q = xdp_add_lm_log2(delta_in, lambda_in, eta_in);
				const Differential new_diff_right = {delta_in, lambda_in, eta_in, q, q};
				marx_add_diff_to_trail(g_T[RIGHT], iround - 1, new_diff_right);

				/* input differences for next round: LEFT */
				const WORD_T alpha_next = LROT(gamma_in, g_r3);
				const WORD_T beta_next = XOR(eta_in, LROT(lambda_in, g_r2));
				const WORD_T gamma_next = 0;

				/* input differences for next round: RIGHT */
				const WORD_T delta_next = LROT(eta_in, g_r4);
				const WORD_T lambda_next = XOR(gamma_in, LROT(beta_in, g_r1));
				const WORD_T eta_next = 0;

				bool ret = marx_best_diff_search_i(2, 0, alpha_next, beta_next, gamma_next, delta_next, lambda_next, eta_next);
				if (ret == true)
				{
					return true;
				}
				marx_remove_diff_from_trail(g_T[RIGHT], 0);
				marx_remove_diff_from_trail(g_T[LEFT], 0);
			}
		}
		else
		{
			const WORD_T word_size = ibit + 1; /* partial word size */
			for (WORD_T w = 0; w < 8; w++)
			{
				/* LEFT */
				const WORD_T alpha_i = (w >> 0) & 1;
				const WORD_T beta_i = (w >> 1) & 1;
				const WORD_T gamma_i = (w >> 2) & 1;

				/* set the ibit of the differences (partial differences) */
				const WORD_T alpha_part = alpha_in | (alpha_i << ibit);
				const WORD_T beta_part = beta_in | (beta_i << ibit);
				const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
				const double p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size); /* partial prob. */

				const double p_est = p_part + g_best_B[g_nRounds - 2];

				if (p_est >= g_Bn)
				{
					for (WORD_T v = 0; v < 8; v++)
					{
						/* RIGHT */
						const WORD_T delta_i = (v >> 0) & 1;
						const WORD_T lambda_i = (v >> 1) & 1;
						const WORD_T eta_i = (v >> 2) & 1;

						/* set the ibit of the differences (partial differences) */
						const WORD_T delta_part = delta_in | (delta_i << ibit);
						const WORD_T lambda_part = lambda_in | (lambda_i << ibit);
						const WORD_T eta_part = eta_in | (eta_i << ibit);
						const int q_part = xdp_add_lm_log2(delta_part, lambda_part, eta_part, word_size); /* partial prob. */
						const int pq_est = p_est + q_part;

						if (pq_est >= g_Bn)
						{
							bool ret = marx_best_diff_search_i(iround, ibit + 1, alpha_part, beta_part, gamma_part, delta_part, lambda_part, eta_part);
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
	else
	{
		if (iround == g_nRounds)
		{
			if (ibit == WORD_SIZE)
			{
				const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
				const int cp_left = g_T[LEFT][iround - 2].cp + p;
				const Differential new_diff_left = {alpha_in, beta_in, gamma_in, p, cp_left};
				marx_add_diff_to_trail(g_T[LEFT], iround - 1, new_diff_left);

				const int q = xdp_add_lm_log2(delta_in, lambda_in, eta_in);
				const int cp_right = g_T[RIGHT][iround - 2].cp + q;
				const Differential new_diff_right = {delta_in, lambda_in, eta_in, q, cp_right};
				marx_add_diff_to_trail(g_T[RIGHT], iround - 1, new_diff_right);

				/* p[0]q[0] p[1]q[1] ... p[iround - 1]q[iround - 1] => first (iround) rounds */
				const int p_trail = g_T[LEFT][iround - 1].cp + g_T[RIGHT][iround - 1].cp;

				if (p_trail >= g_Bn)
				{
					/* We have a winner ! */
					return true;
				}

				marx_remove_diff_from_trail(g_T[RIGHT], g_nRounds - 1);
				marx_remove_diff_from_trail(g_T[LEFT], g_nRounds - 1);
			}
			else
			{
				const WORD_T word_size = ibit + 1; /* partial word size */
				const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size)); /* masks word_size LS bits */
				/* LEFT inputs */
				const WORD_T alpha_part = alpha_in & mask_lsb;
				const WORD_T beta_part = beta_in & mask_lsb;
				/* RIGHT inputs */
				const WORD_T delta_part = delta_in & mask_lsb;
				const WORD_T lambda_part = lambda_in & mask_lsb;

				/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] => first (iround - 1) rounds */
				const int pq_iround = g_T[LEFT][iround - 2].cp + g_T[RIGHT][iround - 2].cp;

				for (uint32_t w = 0; w < 2; w++)
				{
					/* LEFT output */
					const WORD_T gamma_i = (w >> 0) & 1;
					const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
					const int p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size); /* LEFT partial prob. */

					/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] (p_part = p[iround - 1]) => first iround rounds */
					const int p_est = pq_iround + p_part;

					if (p_est >= g_Bn)
					{
						for (uint32_t v = 0; v < 2; v++)
						{
							/* RIGHT output */
							const WORD_T eta_i = (v >> 0) & 1;
							const WORD_T eta_part = eta_in | (eta_i << ibit);
							const int q_part = xdp_add_lm_log2(delta_part, lambda_part, eta_part, word_size); // RIGHT partial prob.

							/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] (p_part = p[iround - 1]) => first iround rounds */
							const int pq_est = p_est + q_part;

							if (pq_est >= g_Bn)
							{
								bool ret = marx_best_diff_search_i(iround, ibit + 1, alpha_in, beta_in, gamma_part, delta_in, lambda_in, eta_part);
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
		else
		{
			/* iround != 1 and iround != g_nRounds) */
			if (ibit == WORD_SIZE)
			{
				const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
				const int cp_left = g_T[LEFT][iround - 2].cp + p;
				const Differential new_diff_left = {alpha_in, beta_in, gamma_in, p, cp_left};
				marx_add_diff_to_trail(g_T[LEFT], iround - 1, new_diff_left);

				const int q = xdp_add_lm_log2(delta_in, lambda_in, eta_in);
				const int cp_right = g_T[RIGHT][iround - 2].cp + q;
				const Differential new_diff_right = {delta_in, lambda_in, eta_in, q, cp_right};
				marx_add_diff_to_trail(g_T[RIGHT], iround - 1, new_diff_right);

				/* input differences for next round: LEFT */
				const WORD_T alpha_next = LROT(gamma_in, g_r3);
				const WORD_T beta_next = XOR(eta_in, LROT(lambda_in, g_r2));
				const WORD_T gamma_next = 0;

				/* input differences for next round: RIGHT */
				const WORD_T delta_next = LROT(eta_in, g_r4);
				const WORD_T lambda_next = XOR(gamma_in, LROT(beta_in, g_r1));
				const WORD_T eta_next = 0;

				bool ret = marx_best_diff_search_i(iround + 1, 0, alpha_next, beta_next, gamma_next, delta_next, lambda_next, eta_next);
				if (ret == true)
				{
					return true;
				}

				marx_remove_diff_from_trail(g_T[RIGHT], iround - 1);
				marx_remove_diff_from_trail(g_T[LEFT], iround - 1);
			}
			else
			{
				const WORD_T word_size = ibit + 1; /* partial word size */
				const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size)); /* masks word_size LS bits */
				/* LEFT inputs */
				const WORD_T alpha_part = alpha_in & mask_lsb;
				const WORD_T beta_part = beta_in & mask_lsb;
				/* RIGHT inputs */
				const WORD_T delta_part = delta_in & mask_lsb;
				const WORD_T lambda_part = lambda_in & mask_lsb;
			
				/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] => first (iround - 1) rounds */
				const int pq_iround = g_T[LEFT][iround - 2].cp + g_T[RIGHT][iround - 2].cp;
			
				for (uint32_t w = 0; w < 2; w++)
				{
					/* LEFT output */
					const WORD_T gamma_i = (w >> 0) & 1;
					const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
					const int p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size); /* LEFT partial prob. */
			
					/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] (p_part = p[iround - 1]) => first iround rounds */
					const int p_est = pq_iround + p_part + g_best_B[g_nRounds - iround - 1];
			
					if (p_est >= g_Bn)
					{
						for (uint32_t v = 0; v < 2; v++)
						{
							/* RIGHT output */
							const WORD_T eta_i = (v >> 0) & 1;
							const WORD_T eta_part = eta_in | (eta_i << ibit);
							const int q_part = xdp_add_lm_log2(delta_part, lambda_part, eta_part, word_size); /* RIGHT partial prob. */
			
							/* p[0]q[0] p[1]q[1] ... p[iround - 2]q[iround - 2] (p_part = p[iround - 1]) => first iround rounds */
							const int pq_est = p_est + q_part;
			
							if (pq_est >= g_Bn)
							{ 
								bool ret = marx_best_diff_search_i(iround, ibit + 1, alpha_in, beta_in, gamma_part, delta_in, lambda_in, eta_part);
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
	}
	return false;
}

bool marx_best_diff_search(void)
{
	g_nNodes = 0;
	marx_init_diff_trail(g_T);
	return marx_best_diff_search_i(1, 0, 0, 0, 0, 0, 0, 0);
}

void marx_find_bound(void)
{
	while (1)
	{
		fprintf(stdout, "-- g_Bn = %+3d ... ", g_Bn);
		fflush(stdout);
		std::chrono::seconds startTime = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch());
		bool found = marx_best_diff_search();
		if (found == false)
		{
			fprintf(stdout, "no trail found! ");
			finalize(startTime);
		}
		else
		{
			fprintf(stdout, "trail found! ");
			finalize(startTime);
			marx_print_diff_trail(g_T);
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
	fprintf(stdout, "# V%s: Searching for best differential for MARX with WORD_SIZE = %u, r1 = %u, r2 = %u, r3 = %u, r4 = %u\n", STRINGIFY(MARX_VERSION), WORD_SIZE, g_r1, g_r2, g_r3, g_r4);
	fprintf(stdout, "########################################################################################\n");

	FILE *summaryFileHandle = stdout;
	int opt;
	while ((opt = getopt(argc, argv, "s:")) != -1)
	{
		switch (opt)
		{
			case 's':
				summaryFileHandle = fopen(optarg, "w");
				break;
			case '?':
				fprintf(stderr, "Usage: %s <-s summaryFileName>\n", argv[0]);
				exit(-1);
				break;
		}
	}

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
		if (g_Bn <= -32)
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
