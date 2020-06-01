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
 * \file  speck-best-diff-search-tests.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2015
 * \brief Tests for automatic search for the best XOR differential
 *        trail in block cipher Speck .
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif
#ifndef SPECK_XOR_THRESHOLD_SEARCH_H
#include "speck-xor-threshold-search.hh"
#endif

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

// Global definitions

#if (WORD_SIZE == 64)
// global array of bounds: WORD_SIZE 64
const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 10)), // 5
  (1.0 / (double)(1ULL << 15)), // 6
  (1.0 / (double)(1ULL << 21)), // 7: <- terminated after 12512m43.297s = 9 days
  (1.0 / (double)(1ULL <<  0)), // 8: dummy
  (1.0 / (double)(1ULL <<  0)), // 9: dummy
  (1.0 / (double)(1ULL <<  0)), // 10: dummy
};
#endif // #if (WORD_SIZE == 64)
#if (WORD_SIZE == 48)
// global array of bounds: WORD_SIZE 48
const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 10)), // 5
  (1.0 / (double)(1ULL << 15)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL <<  0)), // 8: dummy
  (1.0 / (double)(1ULL <<  0)), // 9: dummy
  (1.0 / (double)(1ULL <<  0)), // 10: dummy
};
#endif // #if (WORD_SIZE == 48)
// global array of bounds: WORD_SIZE 32
#if (WORD_SIZE == 32)
const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 10)), // 5
  (1.0 / (double)(1ULL << 15)), // 6
  (1.0 / (double)(1ULL << 21)), // 7
  (1.0 / (double)(1ULL << 28)), // 8 <- none found in time 152 hrs = 7 days
  (1.0 / (double)(1ULL <<  0)), // 9: dummy
  (1.0 / (double)(1ULL <<  0)), // 10: dummy
};
#endif // #if (WORD_SIZE == 32)
// global array of bounds: WORD_SIZE 24
#if (WORD_SIZE == 24)
const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  6)), // 4
  (1.0 / (double)(1ULL << 10)), // 5
  (1.0 / (double)(1ULL << 14)), // 6
  (1.0 / (double)(1ULL << 19)), // 7
  (1.0 / (double)(1ULL << 26)), // 8
  (1.0 / (double)(1ULL <<  33)), // 9
  (1.0 / (double)(1ULL <<  0)), // 10: dummy
};
#endif // #if (WORD_SIZE == 24)
// global array of bounds: WORD_SIZE 16
#if (WORD_SIZE == 16)
const double g_best_B[NROUNDS_MAX] = {
  (1.0 / (double)(1ULL <<  0)), // 1
  (1.0 / (double)(1ULL <<  1)), // 2
  (1.0 / (double)(1ULL <<  3)), // 3
  (1.0 / (double)(1ULL <<  5)), // 4
  (1.0 / (double)(1ULL <<  9)), // 5
  (1.0 / (double)(1ULL <<  13)), // 6
  (1.0 / (double)(1ULL <<  18)), // 7
  (1.0 / (double)(1ULL <<  24)), // 8
  (1.0 / (double)(1ULL <<  30)), // 9
  (1.0 / (double)(1ULL <<  34)), // 10
};
#endif // #if (WORD_SIZE == 16)
/**
 * If UPDATE_BOUND is false then the algorithm will find ALL trails
 * with probability (g_Bn * EPS) or higher.
 */
#define UPDATE_BOUND true//false
#define EPS (1.0 / (double)(1ULL <<  0))
double g_Bn = g_best_B[NROUNDS - 1] * EPS; // underestimated bound for round n
differential_3d_t g_T[NROUNDS] = {{0, 0, 0, 0.0, LOG0}}; // trail
differential_3d_t g_best_T[NROUNDS] = {{0, 0, 0, 0.0, LOG0}}; // best trail
#if (WORD_SIZE <= 16)
const uint32_t g_r1 = SPECK_RIGHT_ROT_CONST_16BITS % WORD_SIZE; // rotattion const. 1
const uint32_t g_r2 = SPECK_LEFT_ROT_CONST_16BITS % WORD_SIZE; // rotation const. 2
#else // (WORD_SIZE > 16)
const uint32_t g_r1 = SPECK_RIGHT_ROT_CONST; // rotattion const. 1
const uint32_t g_r2 = SPECK_LEFT_ROT_CONST; // rotation const. 2
#endif // #if (WORD_SIZE <= 16)


/* global array of bounds: WORD_SIZE 64 */
#if (WORD_SIZE == 64)
const int g_best_B_log2[NROUNDS_MAX] = {
    0,                          // 1
    -1,                         // 2
    -3,                         // 3
    -6,                         // 4
    -10,                        // 5
    -15,                        // 6
    -21,                        // 7
};
/* global array of bounds: WORD_SIZE 48 */
#elif (WORD_SIZE == 48)
const int g_best_B_log2[NROUNDS_MAX] = {
    0,                          // 1
    -1,                         // 2
    -3,                         // 3
    -6,                         // 4
    -10,                        // 5
    -15,                        // 6
    -21,                        // 7
};
/* global array of bounds: WORD_SIZE 32 */
#elif (WORD_SIZE == 32)
const int g_best_B_log2[NROUNDS_MAX] = {
    0,                          // 1
    -1,                         // 2
    -3,                         // 3
    -6,                         // 4
    -10,                        // 5
    -15,                        // 6
    -21,                        // 7
};
/* global array of bounds: WORD_SIZE 24 */
#elif (WORD_SIZE == 24)
const int g_best_B_log2[NROUNDS_MAX] = {
    0,                          // 1
    -1,                         // 2
    -3,                         // 3
    -6,                         // 4
    -10,                        // 5
    -14,                        // 6
    -21,                        // 7
};
// global array of bounds: WORD_SIZE 16
#elif (WORD_SIZE == 16)
const int g_best_B_log2[NROUNDS_MAX] = {
    0,                          // 1
    -1,                         // 2
    -3,                         // 3
    -5,                         // 4
    -9,                         // 5
    -13,                        // 6
    -18,                        // 7
};
#else
#error("WORD_SIZE must be either 16, 24, or 32")
#endif // #if(WORD_SIZE == 16)

int g_Bn_log2 = g_best_B_log2[NROUNDS - 1]; // underestimated bound for round n
//differential_3d_t g_T_log2[NROUNDS] = {{0, 0, 0, 0.0}}; // trail
//differential_3d_t g_best_T_log2[NROUNDS] = {{0, 0, 0, 0.0}}; // best trail

/**
 * Full search for the best differential trail of block cipher SPECK
 * (non-recursive).
 *
 * \note Feasible for up to 4 bit words and up to 5 rounds.
 * \note The complexity is 2^{(n+2) w}, where n is the total number of
 *       rounds and w is the word size. Therefore this function is
 *       exponential in the word size and in the number of rounds.
 *
 * \see speck_xor_threshold_search_simple
 */
void speck_best_diff_search_full(differential_3d_t T_best[NROUNDS], // best trail for n rounds
											 double* p_best) // best prob. for n rounds
{
#if (WORD_SIZE <= 4)
  assert(NROUNDS <= 7);

  const uint32_t rconst_1 = SPECK_RIGHT_ROT_CONST_16BITS % WORD_SIZE;
  const uint32_t rconst_2 = SPECK_LEFT_ROT_CONST_16BITS % WORD_SIZE;

  uint64_t ndiffs = (1ULL << ((NROUNDS + 2) * WORD_SIZE));

  printf("[%s:%d] ndiffs 2^%2.0f\n", __FILE__, __LINE__, log2(ndiffs));
  printf("[%s:%d] rconst_1 %d rconst_2 %d\n", __FILE__, __LINE__, rconst_1, rconst_2);

  double p_max = 0.0;
  uint32_t r = 0;
  WORD_T alpha_r = 0;
  WORD_T beta_r = 0;
  WORD_T gamma_r = 0;
  WORD_T beta_prev = 0;
  WORD_T gamma_prev = 0;
  double p_r = 0.0;
  uint32_t j = 0;

  for(uint64_t diffs_i = 1; diffs_i < ndiffs; diffs_i++) {

	 differential_3d_t D[NROUNDS] = {{0, 0, 0, 0.0}};

	 r = 0;
	 alpha_r = (diffs_i >> (r * WORD_SIZE)) & MASK;

	 r = 1;
	 beta_r = (diffs_i >> (r * WORD_SIZE)) & MASK;

	 r = 2;
	 gamma_r = (diffs_i >> (r * WORD_SIZE)) & MASK;

	 j = 0;
	 p_r = xdp_add_lm(alpha_r, beta_r, gamma_r);
	 D[j].dx = alpha_r;
	 D[j].dy = beta_r;
	 D[j].dz = gamma_r;
	 D[j].p = p_r;

	 r += 1;

	 for(j = 1; j < NROUNDS; j++, r++) {

		beta_prev = D[j - 1].dy;
		gamma_prev = D[j - 1].dz;

		alpha_r = RROT(gamma_prev, rconst_1);
		beta_r = XOR(gamma_prev, LROT(beta_prev, rconst_2));
		gamma_r = (diffs_i >> (r * WORD_SIZE)) & MASK;

		p_r = xdp_add_lm(alpha_r, beta_r, gamma_r);
		D[j].dx = alpha_r;
		D[j].dy = beta_r;
		D[j].dz = gamma_r;
		D[j].p = p_r;

	 }

	 double p_tot = 1.0;
	 for(j = 0; j < NROUNDS; j++) {
		p_tot *= D[j].p;
	 }
	 if(p_tot >= p_max) {
		p_max = p_tot;
		for(j = 0; j < NROUNDS; j++) {
		  T_best[j].dx = D[j].dx;
		  T_best[j].dy = D[j].dy;
		  T_best[j].dz = D[j].dz;
		  T_best[j].p = D[j].p;
		}
	 }

  }
  *p_best = p_max;
#endif // #if (WORD_SIZE <= 4)
}


/**
 * Add new element at position i in the trail T
 */
void speck_add_diff_to_trail(differential_3d_t T[NROUNDS], const uint32_t i, const differential_3d_t new_diff)
{
  assert(i < NROUNDS);
  assert(T[i].dx == 0);
  assert(T[i].dy == 0);
  assert(T[i].dz == 0);
  assert(T[i].p == 0.0);
  assert(T[i].log2p == LOG0);

#if 0 // DEBUG
  double p = xdp_add_lm(new_diff.dx, new_diff.dy, new_diff.dz);
  assert(p == new_diff.p);
#endif // #if 0

  T[i].dx = new_diff.dx;
  T[i].dy = new_diff.dy;
  T[i].dz = new_diff.dz;
  T[i].p = new_diff.p;
  T[i].log2p = new_diff.log2p;
}

/**
 * Remove element from position i in the trail T (sets differences and
 * prob. to zero)
 */
void speck_remove_diff_from_trail(differential_3d_t T[NROUNDS], const uint32_t i)
{
  assert(i < NROUNDS);

  T[i].dx = 0; 
  T[i].dy = 0;
  T[i].dz = 0;
  T[i].p = 0.0;
  T[i].log2p = LOG0;;
}

/**
 * Init the trail T
 */
void speck_init_diff_trail(differential_3d_t T[NROUNDS])
{
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 T[i].dx = 0; 
	 T[i].dy = 0;
	 T[i].dz = 0;
	 T[i].p = 0.0;
	 T[i].log2p = LOG0;;
  }
}

/**
 * Print the trail T
 */
void speck_print_diff_trail(differential_3d_t T[NROUNDS])
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  double p = 1.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 printf("%2d: %8X %8X -> %8X %4.2f %4.2f\n", i, T[i].dx, T[i].dy, T[i].dz, T[i].p, log2(T[i].p));
#else
	 printf("%2d: %16llX %16llX -> %16llX %4.2f %4.2f\n", i, (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, T[i].p, log2(T[i].p));
#endif // #if (WORD_SIZE <= 32)

	 double p_tmp = xdp_add_lm(T[i].dx, T[i].dy, T[i].dz);
	 assert(p_tmp == T[i].p);

	 p *= T[i].p;
  }
  printf("p_trail %f %4.2f\n", p, log2(p));
}

/**
 * Print the only the input and output diferences of trail T (i.e. the
 * differential corresponding to T)
 */
void speck_print_differential(differential_3d_t T[NROUNDS])
{
  double p_tot = 1.0;

  WORD_T dx_first = 0;
  WORD_T dy_first = 0;
  WORD_T dx_last = 0;
  WORD_T dy_last = 0;

  for(uint32_t i = 0; i < NROUNDS; i++) {
	 WORD_T dx = T[i].dx;
	 WORD_T dy = T[i].dy;
	 WORD_T dz = T[i].dz;
	 double p_T = T[i].p;

#if 1 // DEBUG
	 double p = xdp_add_lm(dx, dy, dz); 
	 //	 printf("%llX %llX -> %llX %4.2f %4.2f\n", (WORD_MAX_T)dx, (WORD_MAX_T)dy, (WORD_MAX_T)dz, log2(p_T), log2(p));
	 assert(p == p_T);
	 if(i <= (NROUNDS - 2)) {
		WORD_T dx_next = T[i+1].dx;
		WORD_T dy_next = T[i+1].dy;
		WORD_T dx_next_tmp = RROT(dz, g_r1);
		WORD_T dy_next_tmp = XOR(dz, LROT(dy, g_r2));
		assert(dx_next == dx_next_tmp);
		assert(dy_next == dy_next_tmp);
	 }
#endif // #if 1 // DEBUG

	 if(i == 0) { // input to first round
		dx_first = LROT(dx, g_r1); // rotate backwards
		dy_first = dy;
	 } 
	 if(i == (NROUNDS - 1)) { // output from last round
		dx_last = dz;
		dy_last = XOR(dz, LROT(dy, g_r2));;
	 }

	 p_tot *= T[i].p;
  }

#if (WORD_SIZE <= 32)
  printf("%8X %8X %8X %8X %4.0f\n", dx_first, dy_first, dx_last, dy_last, log2(p_tot));
#else
  printf("%16llX %16llX %16llX %16llX %4.0f\n", (WORD_MAX_T)dx_first, (WORD_MAX_T)dy_first, (WORD_MAX_T)dx_last, (WORD_MAX_T)dy_last, log2(p_tot));
#endif // #if (WORD_SIZE <= 32)
}

/**
 * Print the trail T with log2 probabilities
 */
void speck_print_diff_trail_log2(differential_3d_t T[NROUNDS])
{
  printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
  int log2p = 0.0;
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 printf("%2d: %8X %8X -> %8X %4.2f %d\n", i, T[i].dx, T[i].dy, T[i].dz, T[i].p, T[i].log2p);
#else
	 printf("%2d: %16llX %16llX -> %16llX %4.2f %d\n", i, (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, T[i].p, T[i].log2p);
#endif // #if (WORD_SIZE <= 32)

	 double p_tmp = xdp_add_lm_log2(T[i].dx, T[i].dy, T[i].dz);
	 assert(p_tmp == T[i].log2p);

	 log2p += T[i].log2p;
  }
  printf("log2p_trail %d\n", log2p);
}

/**
 * Print the trail in C-style
 * \see speck_print_diff_trail
 */
void speck_print_diff_trail_cstyle(differential_3d_t T[NROUNDS])
{
  printf("differential_3d_t g_T[NROUNDS] = {\n");
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 printf("{%8X, %8X, %8X, (1.0 / (double)(1ULL <<  %d))},\n", T[i].dx, T[i].dy, T[i].dz, (uint32_t)std::abs(log2(T[i].p)));
#else
	 printf("{%16llX, %16llX, %16llX, (1.0 / (double)(1ULL <<  %d))},\n", 
			  (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, (uint32_t)std::abs(log2(T[i].p)));
#endif // #if (WORD_SIZE <= 32)
  }
  printf("};\n");
}

/**
 * Print the trail in C-style with log2 probabilities
 * \see speck_print_diff_trail_cstyle
 */
void speck_print_diff_trail_cstyle_log2(differential_3d_t T[NROUNDS])
{
  printf("differential_3d_t g_T[NROUNDS] = {\n");
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 printf("{%8X, %8X, %8X, (1.0 / (double)(1ULL <<  %d))},\n", T[i].dx, T[i].dy, T[i].dz, (uint32_t)std::abs(T[i].log2p));
#else
	 printf("{%16llX, %16llX, %16llX, (1.0 / (double)(1ULL <<  %d))},\n", 
			  (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, (uint32_t)std::abs(T[i].log2p));
#endif // #if (WORD_SIZE <= 32)
  }
  printf("};\n");
}

/**
 * Print the trail in Latex-style
 * \see speck_print_diff_trail
 */
void speck_print_diff_trail_latex(differential_3d_t T[NROUNDS])
{
  printf("\n%%------------------------trail start----------------------------------------\n");
  printf("\\begin{table}[ht]\n");
  printf("\\caption{Best differential trail for word size %d rounds %d}\n", WORD_SIZE, NROUNDS);
  // printf("\\label{tab:best-diff-trail-w%d-r%d}\n", WORD_SIZE, NROUNDS);
  printf("\\begin{center}\n");
  printf("\\begin{tabular}{c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}}\n");
  printf("\\toprule\n");
  //  printf("$r$ & $\\Delta y$ & & $\\Delta x$ & $p$ & $\\mathrm{log}_2 p$\\\\\n");
  printf("$r$ & $\\alpha$ & $\\beta$ & $\\gamma$ & $\\mathrm{log}_2 p$\\\\\n");
  printf("\\midrule\n");
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 //	 printf("{%8X, %8X, %8X, (1.0 / (double)(1ULL <<  %d))},\n", T[i].dx, T[i].dy, T[i].dz, (uint32_t)std::abs(log2(T[i].p)));
	 if(T[i].p != 1.0) {
		printf("$%2d$ & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} & $%3.2f$ \\\\\n", i, T[i].dx, T[i].dy, T[i].dz, log2(T[i].p));
	 } else {
		printf("$%2d$ & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} & $-%3.2f$ \\\\\n", i, T[i].dx, T[i].dy, T[i].dz, log2(T[i].p));
	 }
#else
	 //	 printf("{%16llX, %16llX, %16llX, (1.0 / (double)(1ULL <<  %d))},\n", 
	 //			  (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, (uint32_t)std::abs(log2(T[i].p)));
	 if(T[i].p != 1.0) {
		printf("$%2d$ & \\texttt{%16llX} & \\texttt{%16llX} & \\texttt{%16llX} & $%3.2f$ \\\\\n", i, (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, log2(T[i].p));
	 } else {
		printf("$%2d$ & \\texttt{%16llX} & \\texttt{%16llX} & \\texttt{%16llX} & $-%3.2f$ \\\\\n", i, (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, log2(T[i].p));
	 }
#endif // #if (WORD_SIZE <= 32)
	 //	 printf("\\midrule\n");
  }
  printf("\\bottomrule\n");
  printf("\\end{tabular}\n");
  printf("\\end{center}\n");
  printf("\\end{table}\n");
  printf("%%------------------------trail end----------------------------------------\n");
}

/**
 * Print the trail in Latex-style with log2 probabilities
 * \see speck_print_diff_trail_latex
 */
void speck_print_diff_trail_latex_log2(differential_3d_t T[NROUNDS])
{
  printf("\n%%------------------------trail start----------------------------------------\n");
  printf("\\begin{table}[ht]\n");
  printf("\\caption{Best differential trail for word size %d rounds %d}\n", WORD_SIZE, NROUNDS);
  // printf("\\label{tab:best-diff-trail-w%d-r%d}\n", WORD_SIZE, NROUNDS);
  printf("\\begin{center}\n");
  printf("\\begin{tabular}{c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}c@{\\hspace{0.4cm}}}\n");
  printf("\\toprule\n");
  //  printf("$r$ & $\\Delta y$ & & $\\Delta x$ & $p$ & $\\mathrm{log}_2 p$\\\\\n");
  printf("$r$ & $\\alpha$ & $\\beta$ & $\\gamma$ & $\\mathrm{log}_2 p$\\\\\n");
  printf("\\midrule\n");
  for(uint32_t i = 0; i < NROUNDS; i++) {
#if (WORD_SIZE <= 32)
	 printf("$%2d$ & \\texttt{%8X} & \\texttt{%8X} & \\texttt{%8X} & $%d$ \\\\\n", i, T[i].dx, T[i].dy, T[i].dz, T[i].log2p);
#else
	 printf("$%2d$ & \\texttt{%16llX} & \\texttt{%16llX} & \\texttt{%16llX} & $%d$ \\\\\n", i, (WORD_MAX_T)T[i].dx, (WORD_MAX_T)T[i].dy, (WORD_MAX_T)T[i].dz, T[i].log2p);
#endif // #if (WORD_SIZE <= 32)
	 //	 printf("\\midrule\n");
  }
  printf("\\bottomrule\n");
  printf("\\end{tabular}\n");
  printf("\\end{center}\n");
  printf("\\end{table}\n");
  printf("%%------------------------trail end----------------------------------------\n");
}

/**
 * Copy trail from_T to to_T
 */
void speck_copy_diff_trail(const differential_3d_t from_T[NROUNDS], differential_3d_t to_T[NROUNDS])
{
  for(uint32_t i = 0; i < NROUNDS; i++) {
	 to_T[i].dx = from_T[i].dx; 
	 to_T[i].dy = from_T[i].dy;
	 to_T[i].dz = from_T[i].dz;
	 to_T[i].p = from_T[i].p;
	 to_T[i].log2p = from_T[i].log2p;
  }
}

/**
 * Search for the best differential trail of block cipher SPECK.
 *
 * \param iround current round: \f$ 0 \ge r < NROUNDS\f$
 * \param ibit current bit position
 * \param alpha first input difference to the addition of round iround
 * \param beta second input difference to the addition of round iround
 * \param gamma output difference from the addition of round iround
 *
 * \see speck_xor_threshold_search_simple
 */
void speck_best_diff_search_i(const uint32_t iround, // current round
										 const uint32_t ibit, // current bit position
										 const WORD_T alpha_in, // input difference to the addition of round iround
										 const WORD_T beta_in, // input difference to the addition of round iround
										 const WORD_T gamma_in) // output difference from the addition of round iround
{
#if 0 // DEBUG
  printf("[%s:%d] Enter iround %d ibit %d diffs %X %X %X\n", __FILE__, __LINE__, 
			iround, ibit, alpha_in, beta_in, gamma_in);
#endif // #if 1 // DEBUG

  if((iround == 1) && (iround != NROUNDS)) {

	 if(ibit == WORD_SIZE) {

		if(!((alpha_in == 0) && (beta_in == 0))) { // discard zero input diff
		  const double p = xdp_add_lm(alpha_in, beta_in, gamma_in);
		  const differential_3d_t new_diff = {alpha_in, beta_in, gamma_in, p, LOG0};
		  speck_add_diff_to_trail(g_T, iround - 1, new_diff);

		  // input differences for next round
		  const WORD_T alpha_next = RROT(gamma_in, g_r1);
		  const WORD_T beta_next = XOR(gamma_in, LROT(beta_in, g_r2));
		  const WORD_T gamma_next = 0;

#if 0 // DEBUG
		  printf("[%s:%d] Add to trail %X %X %X %4.2f\n", __FILE__, __LINE__, new_diff.dx, new_diff.dy, new_diff.dz, log2(new_diff.p));
		  printf("[%s:%d] iround_next %d alpha_next beta_next %X %X\n", __FILE__, __LINE__, iround + 1, alpha_next, beta_next);
#endif // #if 0 // DEBUG

		  speck_best_diff_search_i(iround + 1, 0, alpha_next, beta_next, gamma_next);
		  speck_remove_diff_from_trail(g_T, iround - 1);
		}

	 } else {

		const WORD_T word_size = ibit + 1; // partial word size

		for(WORD_T w = 0; w < 8; w++) {

		  const WORD_T alpha_i = (w >> 0) & 1;
		  const WORD_T beta_i = (w >> 1) & 1;
		  const WORD_T gamma_i = (w >> 2) & 1;

		  // set the ibit of the differences (partial differences)
		  const WORD_T alpha_part = alpha_in | (alpha_i << ibit);
		  const WORD_T beta_part = beta_in | (beta_i << ibit);
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
		  double p_part = xdp_add_lm(alpha_part, beta_part, gamma_part, word_size); // partial prob.

		  double p_est = p_part * g_best_B[NROUNDS - 2];
 
#if 0 // DEBUG
		  if(word_size == WORD_SIZE) {
			 double p_full = xdp_add_lm(alpha_part, beta_part, gamma_part);
			 //			 printf("[%s:%d] %X %X %X %f %f %d\n", __FILE__, __LINE__, alpha_part, beta_part, gamma_part, p_part, p_full, word_size);
			 assert(p_part == p_full);
		  }
#endif // #if 0 // DEBUG
#if 0 // DEBUG
		  printf("[%s:%d] word_size %2d %8X %8X -> %8X %4.2f\n", __FILE__, __LINE__, word_size, alpha_part, beta_part, gamma_part, p_part);
		  printf("ibit %d %X %X %X | ", ibit, alpha_part, beta_part, gamma_part);
		  printf("p_est %4.2f = p_part %4.2f + g_best_B[%d] %4.2f\n", log2(p_est), log2(p_part), NROUNDS - 2, log2(g_best_B[NROUNDS - 2]));
#endif // #if 0 // DEBUG

		  if(p_est >= g_Bn) {
			 speck_best_diff_search_i(iround, ibit + 1, alpha_part, beta_part, gamma_part);
		  }
		}
	 }
  } // ((iround == 1) && (iround != NROUNDS))

  if((iround > 1) && (iround != NROUNDS)) {

	 if(ibit == WORD_SIZE) {

		const double p = xdp_add_lm(alpha_in, beta_in, gamma_in);
		const differential_3d_t new_diff = {alpha_in, beta_in, gamma_in, p, LOG0};
		speck_add_diff_to_trail(g_T, iround - 1, new_diff);

		// input differences for next round
		const WORD_T alpha_next = RROT(gamma_in, g_r1);
		const WORD_T beta_next = XOR(gamma_in, LROT(beta_in, g_r2));
		const WORD_T gamma_next = 0;

#if 0 // DEBUG
		printf("[%s:%d] iround %d add to trail %X %X %X %4.2f\n", __FILE__, __LINE__, 
				 iround, new_diff.dx, new_diff.dy, new_diff.dz, log2(new_diff.p));
		printf("[%s:%d] iround_next %d alpha_next beta_next %X %X\n", __FILE__, __LINE__, iround + 1, alpha_next, beta_next);
#endif // #if 0 // DEBUG

		speck_best_diff_search_i(iround + 1, 0, alpha_next, beta_next, gamma_next);
		speck_remove_diff_from_trail(g_T, iround - 1);

	 } else {

		const WORD_T word_size = ibit + 1; // partial word size
		const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size)); // masks word_size LS bits
		const WORD_T alpha_part = alpha_in & mask_lsb;
		const WORD_T beta_part = beta_in & mask_lsb;

		double p_iround = 1.0;

		// !!! moved out of loop : yann
		// p[0] p[1] ... p[iround - 2] => first (iround - 1) rounds
		for(uint32_t i = 0; i < (iround - 1); i++) {
		  double p_i = g_T[i].p;
		  p_iround *= p_i;
		}

		for(uint32_t w = 0; w < 2; w++) {

		  const WORD_T gamma_i = (w >> 0) & 1; // <-- (w >> 2) bug!
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
		  const double p_part = xdp_add_lm(alpha_part, beta_part, gamma_part, word_size); // partial prob.

#if 0 // DEBUG
		  printf("[%s:%d] iround %2d ibit %2d | p_iround * p_part * g_best_B[%2d] = %4.2f + %4.2f + %4.2f <> %4.2f\n", __FILE__, __LINE__,
					iround, ibit, (NROUNDS - iround - 1), log2(p_iround), log2(p_part), log2(g_best_B[NROUNDS - iround - 1]), log2(g_Bn));
#endif // #if 0 // DEBUG

		  // p[0] p[1] ... p[iround - 2] (p_part = p[iround - 1]) => first iround rounds
		  const double p_est = p_iround * p_part * g_best_B[NROUNDS - iround - 1];


		  if(p_est >= g_Bn) {
			 speck_best_diff_search_i(iround, ibit + 1, alpha_in, beta_in, gamma_part); // <-- bug! alpha_part, beta_part
		  }
		}
	 }
  } // ((iround > 1) && (iround != NROUNDS))


  if(iround == NROUNDS) {

	 if(ibit == WORD_SIZE) {
		const double p = xdp_add_lm(alpha_in, beta_in, gamma_in);
		const differential_3d_t new_diff = {alpha_in, beta_in, gamma_in, p, LOG0};
		speck_add_diff_to_trail(g_T, iround - 1, new_diff);

#if 0 // DEBUG
		printf("[%s:%d] iround %d add to trail %X %X %X %4.2f\n", __FILE__, __LINE__, 
				 iround, new_diff.dx, new_diff.dy, new_diff.dz, log2(new_diff.p));
#endif // #if 0 // DEBUG

		// p[0] p[1] ... p[iround - 1] => first (iround) rounds
		double p_trail = 1.0;
		for(uint32_t i = 0; i < iround; i++) {
		  double p_i = g_T[i].p;
		  p_trail *= p_i;
		}

		if(p_trail >= g_Bn) {
		  /**
			* If UPDATE_BOUND is false then the algorithm will find ALL trails
			* with probability (g_Bn * EPS) or higher.
			*/
#if (UPDATE_BOUND == true)
		  printf("[%s:%d] Update bound: %4.2f -> %4.2f\n", __FILE__, __LINE__, log2(g_Bn), log2(p_trail));
		  g_Bn = p_trail;
#endif // #if UPDATE_BOUND
#if 0
		  speck_print_diff_trail_cstyle(g_T);
#endif
#if 0
		  speck_print_diff_trail(g_T);
#endif
#if 1
		  speck_print_differential(g_T);
#endif
#if 0
		  speck_print_diff_trail_latex(g_T);
#endif
		  speck_copy_diff_trail(g_T, g_best_T);
		}

		speck_remove_diff_from_trail(g_T, iround - 1);

	 } else {

		const WORD_T word_size = ibit + 1; // partial word size
		const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size)); // masks word_size LS bits
		const WORD_T alpha_part = alpha_in & mask_lsb;
		const WORD_T beta_part = beta_in & mask_lsb;

		double p_iround = 1.0;
		// yann
		// p[0] p[1] ... p[iround - 2] => first (iround - 1) rounds
		for(uint32_t i = 0; i < (iround - 1); i++) {
		  double p_i = g_T[i].p;
		  p_iround *= p_i;
		}

		for(uint32_t w = 0; w < 2; w++) {

		  const WORD_T gamma_i = (w >> 0) & 1; // <-- (w >> 2) bug!
		  const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
		  const double p_part = xdp_add_lm(alpha_part, beta_part, gamma_part, word_size); // partial prob.

		  // p[0] p[1] ... p[iround - 2] (p_part = p[iround - 1]) => first iround rounds
		  const double p_est = p_iround * p_part;

		  if(p_est >= g_Bn) {
			 speck_best_diff_search_i(iround, ibit + 1, alpha_in, beta_in, gamma_part); // <-- bug! alpha_part, beta_part
		  }
		}
	 }
  } // (iround == NROUNDS)

#if 0 // DEBUG
  printf("[%s:%d]  Exit iround %d ibit %d diffs %X %X %X\n", __FILE__, __LINE__,
			iround, ibit, alpha_in, beta_in, gamma_in);
#endif // #if 1 // DEBUG
}

void speck_best_diff_search()
{
#if (NROUNDS >= 2)
  uint32_t r = 1;
  uint32_t i = 0;
  WORD_T alpha = 0;
  WORD_T beta = 0;//0x8000;
  WORD_T gamma = 0;

  speck_init_diff_trail(g_T);
  speck_init_diff_trail(g_best_T);

  speck_best_diff_search_i(r, i, alpha, beta, gamma);

  printf("[%s:%d] Best trail on %d rounds (WORD_SIZE %d bits):\n", __FILE__, __LINE__, NROUNDS, WORD_SIZE);
#if 0
  speck_print_diff_trail(g_best_T);
#endif // #if 0
#if 0
  speck_print_diff_trail_cstyle(g_best_T);
#endif // #if 0
#if 0
  speck_print_diff_trail_latex(g_best_T);
#endif // #if 0
#endif // #if (NROUNDS >= 2)
}

/**
 * Search for the best differential trail of block cipher SPECK using
 * log base 2 probabilities.
 *
 * \note Same as speck_best_trail_search_i, but uses log base 2
 * probabilities. Therefore no multiplication is used and so this
 * variant is more efficient.
 *
 * \param iround current round: \f$ 0 \ge r < NROUNDS\f$
 * \param ibit current bit position
 * \param alpha first input difference to the addition of round iround
 * \param beta second input difference to the addition of round iround
 * \param gamma output difference from the addition of round iround
 *
 * Credits: Yann Le Corre
 *
 * \see speck_best_trail_search_i
 */
void speck_best_diff_search_log2_i (const uint32_t iround,	// current round
				    const uint32_t ibit,	// current bit position
				    const WORD_T alpha_in,	// input difference to the addition of round iround
				    const WORD_T beta_in,	// input difference to the addition of round iround
				    const WORD_T gamma_in)	// output difference from the addition of round iround
{
#if 0							// DEBUG
  printf ("Enter iround:%02u ibit:%02u diffs:0x%016X 0x%016X 0x%016X\n", iround, ibit, alpha_in, beta_in, gamma_in);
#endif // #if 1 // DEBUG

  if ((iround == 1) && (iround != NROUNDS))
    {

      if (ibit == WORD_SIZE)
	{
	  if (!((alpha_in == 0) && (beta_in == 0)))
	    {					// discard zero input diff
	      const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
	      const differential_3d_t new_diff = { alpha_in, beta_in, gamma_in, 0.0, p};
	      speck_add_diff_to_trail (g_T, iround - 1, new_diff);

	      // input differences for next round
	      const WORD_T alpha_next = RROT (gamma_in, g_r1);
	      const WORD_T beta_next = XOR (gamma_in, LROT (beta_in, g_r2));
	      const WORD_T gamma_next = 0;

#if 0 // DEBUG
	      printf ("[%s:%d] Add to trail dx = 0x%X dy = 0x%X dz = 0x%X p = %d\n", __FILE__,
		      __LINE__, new_diff.dx, new_diff.dy, new_diff.dz, (new_diff.log2p));
	      printf ("[%s:%d] iround_next %d alpha_next beta_next %X %X\n", __FILE__, __LINE__, iround + 1, alpha_next, beta_next);
#endif // #if 0 // DEBUG

	      speck_best_diff_search_log2_i (iround + 1, 0, alpha_next, beta_next, gamma_next);
	      speck_remove_diff_from_trail (g_T, iround - 1);
	    }

	}
      else
	{
	  const WORD_T word_size = ibit + 1;	// partial word size

	  for (WORD_T w = 0; w < 8; w++)
	    {

	      const WORD_T alpha_i = (w >> 0) & 1;
	      const WORD_T beta_i = (w >> 1) & 1;
	      const WORD_T gamma_i = (w >> 2) & 1;
	      // set the ibit of the differences (partial differences)
	      const WORD_T alpha_part = alpha_in | (alpha_i << ibit);
	      const WORD_T beta_part = beta_in | (beta_i << ibit);
	      const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
	      int p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size);	// partial prob.
	      int p_est = p_part + g_best_B_log2[NROUNDS - 2];
#if 0 // DEBUG
	      printf ("word_size %2d %8X %8X -> %8X %d\n", word_size, alpha_part, beta_part, gamma_part, p_part);
	      printf ("ibit %d %X %X %X | ", ibit, alpha_part, beta_part, gamma_part);
	      printf ("p_est %d = p_part %d + g_best_B_log2[%d] %d\n", p_est, p_part, NROUNDS - 2, g_best_B_log2[NROUNDS - 2]);
	      printf ("g_Bn_log2 = %d\n", g_Bn_log2);
#endif // #if 0 // DEBUG
	      if (p_est >= g_Bn_log2)
		{
		  speck_best_diff_search_log2_i (iround, ibit + 1, alpha_part, beta_part, gamma_part);
		}
	    }
	}
    }							// ((iround == 1) && (iround != NROUNDS))

  if ((iround > 1) && (iround != NROUNDS))
    {

      if (ibit == WORD_SIZE)
	{

	  const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
	  const differential_3d_t new_diff = { alpha_in, beta_in, gamma_in, 0.0, p };
	  speck_add_diff_to_trail (g_T, iround - 1, new_diff);

	  // input differences for next round
	  const WORD_T alpha_next = RROT (gamma_in, g_r1);
	  const WORD_T beta_next = XOR (gamma_in, LROT (beta_in, g_r2));
	  const WORD_T gamma_next = 0;

#if 0 // DEBUG
	  printf ("[%s:%d] iround %d add to trail %X %X %X %d\n",
		  __FILE__, __LINE__, iround, new_diff.dx, new_diff.dy, new_diff.dz, new_diff.p);
	  printf ("[%s:%d] iround_next %d alpha_next beta_next %X %X\n", __FILE__, __LINE__, iround + 1, alpha_next, beta_next);
#endif // #if 0 // DEBUG

	  speck_best_diff_search_log2_i (iround + 1, 0, alpha_next, beta_next, gamma_next);
	  speck_remove_diff_from_trail (g_T, iround - 1);

	}
      else
	{
	  const WORD_T word_size = ibit + 1;	// partial word size
	  const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size));	// masks word_size LS bits
	  const WORD_T alpha_part = alpha_in & mask_lsb;
	  const WORD_T beta_part = beta_in & mask_lsb;

	  int p_iround = 0;

	  // p[0] p[1] ... p[iround - 2] => first (iround - 1) rounds
	  for (uint32_t i = 0; i < (iround - 1); i++)
	    {
	      int p_i = g_T[i].log2p;
	      p_iround += p_i;
	    }

	  for (uint32_t w = 0; w < 2; w++)
	    {

	      const WORD_T gamma_i = (w >> 0) & 1;	// <-- (w >> 2) bug!
	      const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
	      int p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size);	// partial prob.
#if 0							// DEBUG
	      printf
		("[%s:%d] iround %2d ibit %2d | p_est * p_part * g_best_B_log2[%2d] = %d + %d + %d <> %d\n",
		 __FILE__, __LINE__, iround, ibit, (NROUNDS - iround - 1), p_est, p_part, g_best_B_log2[NROUNDS - iround - 1], g_Bn_log2);
#endif // #if 0 // DEBUG

	      // p[0] p[1] ... p[iround - 2] (p_part = p[iround - 1]) => first iround rounds
	      const int p_est = p_iround + p_part + g_best_B_log2[NROUNDS - iround - 1];


	      if (p_est >= g_Bn_log2)
		{
		  speck_best_diff_search_log2_i (iround, ibit + 1, alpha_in, beta_in, gamma_part);	// <-- bug! alpha_part, beta_part
		}
	    }
	}
    }							// ((iround > 1) && (iround != NROUNDS))


  if (iround == NROUNDS)
    {

      if (ibit == WORD_SIZE)
	{
	  const int p = xdp_add_lm_log2(alpha_in, beta_in, gamma_in);
	  const differential_3d_t new_diff = { alpha_in, beta_in, gamma_in, 0.0, p };
	  speck_add_diff_to_trail (g_T, iround - 1, new_diff);

#if 0							// DEBUG
	  printf ("[%s:%d] iround %d add to trail %X %X %X %d\n",
		  __FILE__, __LINE__, iround, new_diff.dx, new_diff.dy, new_diff.dz, new_diff.p);
#endif // #if 0 // DEBUG

	  // p[0] p[1] ... p[iround - 1] => first (iround) rounds
	  int p_trail = 0;
	  for (uint32_t i = 0; i < iround; i++)
	    {
	      int p_i = g_T[i].log2p;
	      p_trail += p_i;
	    }

	  if (p_trail >= g_Bn_log2)
	    {
	      printf ("# Update bound: %d -> %d\n", g_Bn_log2, p_trail);
	      g_Bn_log2 = p_trail;
	      speck_copy_diff_trail (g_T, g_best_T);
#if 1
	      speck_print_diff_trail_cstyle_log2(g_T);
#endif
#if 0
	      speck_print_diff_trail_log2(g_T);
#endif
#if 0
	      speck_print_diff_trail_latex_log2(g_T);
#endif
	    }

	  speck_remove_diff_from_trail (g_T, iround - 1);

	}
      else
	{

	  const WORD_T word_size = ibit + 1;	// partial word size
	  const WORD_MAX_T mask_lsb = (~0ULL >> (64 - word_size));	// masks word_size LS bits
	  const WORD_T alpha_part = alpha_in & mask_lsb;
	  const WORD_T beta_part = beta_in & mask_lsb;

	  int p_iround = 0;

	  // p[0] p[1] ... p[iround - 2] => first (iround - 1) rounds
	  for (uint32_t i = 0; i < (iround - 1); i++)
	    {
	      int p_i = g_T[i].log2p;
	      p_iround += p_i;
	    }

	  for (uint32_t w = 0; w < 2; w++)
	    {

	      const WORD_T gamma_i = (w >> 0) & 1;	// <-- (w >> 2) bug!
	      const WORD_T gamma_part = gamma_in | (gamma_i << ibit);
	      int p_part = xdp_add_lm_log2(alpha_part, beta_part, gamma_part, word_size);	// partial prob.

	      // p[0] p[1] ... p[iround - 2] (p_part = p[iround - 1]) => first iround rounds
	      const int p_est = p_iround + p_part;

	      if (p_est >= g_Bn_log2)
		{
		  speck_best_diff_search_log2_i (iround, ibit + 1, alpha_in, beta_in, gamma_part);	// <-- bug! alpha_part, beta_part
		}
	    }
	}
    }							// (iround == NROUNDS)

#if 0 // DEBUG
  printf ("[%s:%d]  Exit iround %d ibit %d diffs %X %X %X\n", __FILE__, __LINE__, iround, ibit, alpha_in, beta_in, gamma_in);
#endif // #if 1 // DEBUG
}


void speck_best_diff_search_log2()
{
#if (NROUNDS > 2)
  uint32_t r = 1;
  uint32_t i = 0;
  WORD_T alpha = 0;
  WORD_T beta = 0;//0x8000;
  WORD_T gamma = 0;

  speck_init_diff_trail(g_T);
  speck_init_diff_trail(g_best_T);

  speck_best_diff_search_log2_i(r, i, alpha, beta, gamma);

  printf("[%s:%d] Best trail on %d rounds (WORD_SIZE %d bits):\n", __FILE__, __LINE__, NROUNDS, WORD_SIZE);
#if 1
  speck_print_diff_trail_log2(g_best_T);
  //  speck_print_diff_trail_cstyle_log2(g_best_T);
  //  speck_print_diff_trail_latex_log2(g_best_T);
#endif // #if 0
#endif // #if (NROUNDS == 4)
}

/**
 * Convert a trail as returned from \ref speck_best_diff_search_i (=
 * sequence of input and output differences from the modular addition)
 * to a sequence of one round differentials (= sequences of one round
 * input and output differences).
 */
void speck_convert_diff_trail_to_differentials(const uint32_t nrounds, 
														const differential_3d_t trail[SPECK_TRAIL_LEN], 
														differential_t diff_arr[SPECK_TRAIL_LEN],
														WORD_T* delta_L, WORD_T* delta_R)
{
  assert(nrounds <= SPECK_TRAIL_LEN);
  for(uint32_t i = 0; i < nrounds; i++) {
	 WORD_T dx = trail[i].dx;
	 WORD_T dy = trail[i].dy;
	 WORD_T dz = trail[i].dz;
	 double p_trail = trail[i].p;

#if 1 // DEBUG
	 double p = xdp_add_lm(dx, dy, dz); 
	 printf("%llX %llX -> %llX %4.2f %4.2f\n", (WORD_MAX_T)dx, (WORD_MAX_T)dy, (WORD_MAX_T)dz, log2(p_trail), log2(p));
	 assert(p == p_trail);
	 if(i <= (nrounds - 2)) {
		WORD_T dx_next = trail[i+1].dx;
		WORD_T dy_next = trail[i+1].dy;
		WORD_T dx_next_tmp = RROT(dz, g_r1);
		WORD_T dy_next_tmp = XOR(dz, LROT(dy, g_r2));
		assert(dx_next == dx_next_tmp);
		assert(dy_next == dy_next_tmp);
	 }
#endif // #if 1 // DEBUG

	 if(i == 0) { // input to first round
		*delta_L = LROT(dx, g_r1); // rotate backwards
		*delta_R = dy;
	 } else {
		// input to intermediate rounds
		WORD_T dx_diff = LROT(dx, g_r1); // rotate backwards
		WORD_T dy_diff = dy;
		double p_diff = trail[i-1].p;
		differential_t new_diff = {dx_diff, dy_diff, 0, p_diff};
		diff_arr[i-1] = new_diff;

		if(i == (nrounds - 1)) { // output from last round
		  WORD_T dx_last = dz;
		  WORD_T dy_last = XOR(dz, LROT(dy, g_r2));;
		  double p_last = trail[i].p;
		  differential_t new_diff = {dx_last, dy_last, 0, p_last};
		  diff_arr[i] = new_diff;
		}

	 }

  }
}

void speck_compute_next_alpha_beta(const WORD_T beta_in, const WORD_T gamma_in, 
											  WORD_T* alpha_next, WORD_T* beta_next)
{
  *alpha_next = RROT(gamma_in, g_r1);
  *beta_next = XOR(gamma_in, LROT (beta_in, g_r2));
}

void speck_compute_prev_gamma_beta(const WORD_T alpha_in, const WORD_T beta_in, 
											  WORD_T* gamma_prev, WORD_T* beta_prev)
{
  *gamma_prev = LROT(alpha_in, g_r1) & MASK;
  *beta_prev = RROT(XOR(*gamma_prev, beta_in), g_r2) & MASK;
}


// --- TESTS --- 

void test_speck_best_diff_search_full()
{
  const uint32_t rconst_1 = SPECK_RIGHT_ROT_CONST_16BITS % WORD_SIZE;
  const uint32_t rconst_2 = SPECK_LEFT_ROT_CONST_16BITS % WORD_SIZE;
  differential_3d_t T[NROUNDS] = {{0, 0, 0, 0.0}};
  double p_best = 0.0;
  speck_best_diff_search_full(T, &p_best);
  printf("[%s:%d] Best trail for %d rounds (word size %d bits) p 2^%4.2f\n", __FILE__, __LINE__, NROUNDS, WORD_SIZE, log2(p_best));

  for(uint32_t j = 0; j < NROUNDS; j++) {
	 printf("%llX %llX -> %llX %4.2f\n", (WORD_MAX_T)T[j].dx, (WORD_MAX_T)T[j].dy, (WORD_MAX_T)T[j].dz, T[j].p);
	 double p_tmp = xdp_add_lm(T[j].dx, T[j].dy, T[j].dz);
	 assert(p_tmp == T[j].p);
	 if(j > 0) {

		WORD_T beta_prev = T[j - 1].dy;
		WORD_T gamma_prev = T[j - 1].dz;

		WORD_T alpha_j = RROT(gamma_prev, rconst_1);
		WORD_T beta_j = XOR(gamma_prev, LROT(beta_prev, rconst_2));

		assert(alpha_j == T[j].dx);
		assert(beta_j == T[j].dy);
	 }
  }
}

/*
 * Test partial probability
 */
void test_xdp_add_lm()
{
  const WORD_T a = 2;//0x8000000000;
  const WORD_T b = 3;//0x800000000000;
  const WORD_T c = 3;//0x878000000000;
  uint32_t n = 2;//WORD_SIZE;
  assert(n == WORD_SIZE);
  double p_part = xdp_add_lm(a, b, c, n); // partial prob.
  double p = xdp_add_lm(a, b, c); // partial prob.
  printf("[%s:%d] n %d %llX %llX %llX %f %f\n", __FILE__, __LINE__, n, (WORD_MAX_T)a, (WORD_MAX_T)b, (WORD_MAX_T)c, p, p_part);
  assert(p == p_part);
}

/**
 * Check that xdp is monotonously decreasing in the word size.
 */
void test_xdp_add_monotonous_decrease()
{
#if(WORD_SIZE <= 10)
  WORD_T word_size = 6;//WORD_SIZE;
  WORD_T all_words = (1U << word_size);
  for(WORD_T i = 0; i < all_words; i++) {
	 for(WORD_T j = 0; j < all_words; j++) {
		for(WORD_T k = 0; k < all_words; k++) {

		  double prob_prev = xdp_add_lm(i & 1, j & 1, k & 1, 0);

		  printf("[%s:%d] --- %X %X %X ---\n", __FILE__, __LINE__, i, j, k);

		  for(WORD_T w = 1; w < word_size; w++) {

			 WORD_MAX_T mask = (~0ULL >> (64 - w)); // full mask (word_size bits)

			 //			 printf("w %d mask %llX\n", w, mask);

			 WORD_T da = i & mask;
			 WORD_T db = j & mask;
			 WORD_T dc = k & mask;

			 double prob = xdp_add_lm(da, db, dc, w);

			 printf("[%s:%d] xdp(%2d: %X %X -> %X) = prob %f 2^%4.2f prob_prev %f 2^%4.2f\n", __FILE__, __LINE__, 
					  w, da, db, dc, prob, log2(prob), prob_prev, log2(prob_prev));

			 assert(prob <= prob_prev);

			 prob_prev = prob;
		  }
		}
	 }
  }
  printf("[%s:%d] Test OK!\n", __FILE__, __LINE__);
#endif // #if(WORD_SIZE <= 10)
}

void test_mask()
{
#if (WORD_SIZE <= 32)
  for(WORD_T i = 0; i <= 32; i++) {
	 WORD_T word_size = i;
	 WORD_MAX_T mask_1 = (~0ULL >> (64 - word_size)); // full mask (word_size bits)
	 WORD_T mask_2 = ~(0xffffffffUL << word_size);
	 WORD_T mask_3 = (0xffffffffUL >> (32 - (word_size - 1)));
	 printf("[%s:%d] %08llX %08X %08X\n", __FILE__, __LINE__, mask_1, mask_2, mask_3);
	 assert(mask_1 == mask_2);
  }
#endif // #if (WORD_SIZE <= 32)
}

/**
 * Main function.
 */
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  %d NROUNDS %d UPDATE_BOUND %d r1 %d r2 %d g_Bn 2^%4.2f\n", 
			__FILE__, __LINE__, WORD_SIZE, NROUNDS, UPDATE_BOUND, g_r1, g_r2, log2(g_Bn));

  srandom(time(NULL));

  //  speck_best_diff_search();
  //  test_speck_best_diff_search_full();
  speck_best_diff_search_log2();
  //  test_xdp_add_lm();
  //  test_speck_convert_diff_trail_to_differentials();
  //  test_xdp_add_monotonous_decrease();
  //  test_mask();
  return 0;
}
