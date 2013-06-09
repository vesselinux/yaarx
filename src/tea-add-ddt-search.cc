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
 * \file  tea-add-ddt-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Automatic search for ADD differential trails in TEA using full DDT-s.
 * 
 * \attention Exponential complexity in the word size; infeasible for
 *            word sizes bigger than $11$ bits. Used only for tests
 *            and verification.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef ADP_TEA_F_FK_DDT_H
#include "adp-tea-f-fk-ddt.hh"
#endif

/**
 * Experimentally verify the probabilities of the 1-round
 * differentials composing an N-round differential trail for block
 * cipher TEA, against the exact probabilities from a DDT.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param trail best differential trail for \p nrounds.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param key cryptographic key of TEA.
 * \param delta round constant.
 * \param lsh_const LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const RSH constant (\ref TEA_RSH_CONST).
 *
 */
double verify_trail(uint64_t npairs, differential_t trail[NROUNDS], uint32_t nrounds, uint32_t key[4],
						  uint32_t delta, uint32_t lsh_const, uint32_t rsh_const)
{
  double p_ret = 0.0;

  // compute DDT_E
  uint32_t** DDT_E;		  // even
  DDT_E = ddt_alloc();
  ddt_f(DDT_E, key[0], key[1], delta, lsh_const, rsh_const);

  // compute DDT_O
  uint32_t** DDT_O;		  // odd
  DDT_O = ddt_alloc();
  ddt_f(DDT_O, key[2], key[3], delta, lsh_const, rsh_const);

  printf("\nVerify P of differential:\n");
  double p1 = 1.0;
  for(int i = 0; i < (int)nrounds; i++) {

	 uint32_t da[2], db[2];;

	 da[1] = trail[0].dx;
	 if(i == 0) {
		da[0] = 0;
	 } else {
		da[0] = SUB(trail[1].dx, trail[0].dy);
	 }
	 if(i == 0) {
		db[1] = trail[i].dy;
	 } else {
		db[1] = ADD(trail[i].dy, trail[i-1].dx);
	 }
	 db[0] = trail[i].dx;

	 double p = 0.0;
	 if(is_even(i)) {
		p = adp_f_ddt(DDT_E, trail[i].dx, trail[i].dy);
	 } else {
		p = adp_f_ddt(DDT_O, trail[i].dx, trail[i].dy);
	 }

	 p1 *= p;

	 int r = i + 1;				  // number of rounds
	 double p2 = tea_differential_thres_exper_fk(npairs, r, key, da, db);
	 printf("DDT %2d: %f (2^%f) (%8X <- %8X)\n", i, p1, log2(p1), trail[i].dy, trail[i].dx);
	 printf("EXP %2d: %f (2^%f) \n\n", i, p2, log2(p2));

	 if(r == (int)nrounds)
		p_ret = p1;

  }
  // free DDT_E
  ddt_free(DDT_E);
  // free DDT_O
  ddt_free(DDT_O);
  return p_ret;
}

/**
 * 
 * Automatic search for ADD differential trails using precomputed full
 * difference distribution tables (DDT) for \b a \b modified \b version
 * \b of \b TEA that uses the same round constant \f$\delta\f$ in every
 * round.
 * 
 * \attention 
 *            -# Assumes the same \f$\delta\f$ constant is used at 
 *              every round of TEA.
 *            -# Two DDT-s are computed: \p DDT_E contains fixed-key
 * probabilities for the round keys applied in all even rounds:
 * \f$0,2,4,\ldots\f$; \p DDT_O contains fixed-key probabilities for
 * the round keys applied in all odd rounds: \f$1,3,5,\ldots\f$.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param RSDDT_E a DDT for the keys of all even rounds
 *        \f$0,2,4,\ldots\f$ with the elements in each row (i.e. for a
 *        fixed input difference) sorted in descending order of their
 *        probability (a Row-Sorted \p DDT_E).
 * \param RSDDT_O a DDT for the keys of all odd rounds
 *        \f$1,3,5,\ldots\f$ with the elements in each row (i.e. for a
 *        fixed input difference) sorted in descending order of their
 *        probability (a Row-Sorted \p DDT_O).
 * \param SDDT_O a DDT for the keys of all odd rounds will all
 *        elements sorted in descending order of their probability (a
 *        Sorted \p DDT_O).
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param B array containing the best differential probabilities for i rounds: \f$0 \le i < n\f$.
 * \param Bn the best probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best differential trail for \p nrounds.
 *
 * The outline of the array of bounds \f$B\f$ is the following: 
 * 
 * - \f$B[0]\f$: best probability for \f$1\f$ round.
 * - \f$B[1]\f$: best probability for \f$2\f$ rounds.
 * - \f$\ldots\f$
 * - \f$B[i]\f$: best probability for \f$(i+1)\f$ rounds.
 * - \f$\ldots\f$
 * - \f$B[n-2]\f$: best probability for \f$(n-1)\f$ rounds.
 * - \f$B[n-1]\f$: best probability for \f$n\f$ rounds.
 * 
 * \see tea_add_threshold_search
 */
void round_ddt(const int n, const int nrounds, 
					differential_t** RSDDT_E, differential_t** RSDDT_O, differential_t* SDDT_O,
					double B[NROUNDS], double* Bn,
					const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS])
{
  double pn = 0.0;
  // make a local copy of the input diff trail
#if 1
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].npairs = diff_in[i].npairs;
	 diff[i].p = diff_in[i].p;
  }
#endif

  if((n == 0) && (nrounds == 1)) {						  // Only one round, Round-0
	 uint32_t i = 0;
	 //	 while((i != ALL_WORDS) && (RSDDT_E[i][0].npairs != 0)) {
	 while(i != ALL_WORDS) {
		assert(RSDDT_E[i][0].npairs != 0);
		uint32_t dx = RSDDT_E[i][0].dx;
		uint32_t dy = 0;
		pn = max_adp_f_rsddt(RSDDT_E, i, &dy); // even
		assert((pn >= 0.0) && (pn <= 1.0));
		assert(pn != 0.0);
		assert(pn == RSDDT_E[i][0].p);
		if((pn >= *Bn) && (pn != 0.0)) {
#if DEBUG									  // DEBUG
		  printf("\r[%s:%d] %d | Update bound Bn: 2^%f -> 2^%f", __FILE__, __LINE__, n, log2(*Bn), log2(pn));
		  fflush(stdout);
#endif
		  trail[n].dx = dx;
		  trail[n].dy = dy;
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		}
		i++;
	 }
  }
  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 uint32_t i = 0;
	 //	 while((i != ALL_WORDS) && (RSDDT_E[i][0].npairs != 0)) {
	 while(i != ALL_WORDS) {
		assert(RSDDT_E[i][0].npairs != 0);
		uint32_t i_bound = (nrounds - 1 - (n + 1)); // index for the bound
		uint32_t dx = RSDDT_E[i][0].dx;
		uint32_t dy = 0;
		pn = max_adp_f_rsddt(RSDDT_E, i, &dy); // even
		assert((pn >= 0.0) && (pn <= 1.0));
		assert(pn != 0.0);
		//		double p = pn * B[nrounds - 1 - (n + 1)];
		double p = pn * B[i_bound];
		assert(pn <= B[0]);
		assert(p != 0.0);
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
#if DEBUG									  // DEBUG
		  printf("\r[%s:%d] %d | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, dx, dy, log2(p), log2(*Bn));
		  fflush(stdout);
#endif
		  round_ddt(n+1, nrounds, RSDDT_E, RSDDT_O, SDDT_O, B, Bn, diff, trail);
		} 
		i++;
	 }
  }
  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 uint64_t i = 0;
	 double p = 1.0;
	 //	 while((i != (ALL_WORDS * ALL_WORDS)) && (SDDT_O[i].npairs != 0) && (p >= *Bn)) {
	 while((i != (ALL_WORDS * ALL_WORDS)) && (SDDT_O[i].npairs != 0)) {
		uint32_t i_bound = (nrounds - 1 - (n + 1)); // index for the bound
		uint32_t dx = SDDT_O[i].dx;
		uint32_t dy = SDDT_O[i].dy;
		pn = (double)SDDT_O[i].npairs / (double)(ALL_WORDS);
		assert((pn >= 0.0) && (pn <= 1.0));
		//		p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
		p = diff[0].p * pn * B[i_bound];
		assert(p != 0.0);
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
#if DEBUG									  // DEBUG
		  printf("\r[%s:%d] %d | i = %5lld / %lld | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, i, (ALL_WORDS * ALL_WORDS), dx, dy, log2(p), log2(*Bn));
		  fflush(stdout);
#endif
		  round_ddt(n+1, nrounds, RSDDT_E, RSDDT_O, SDDT_O, B, Bn, diff, trail);
		}
		i++;							  // !
	 }
  }
  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t i = 0;
	 bool b_iszero = false;
	 if(is_even(n)) {
		b_iszero = (RSDDT_E[dx][i].npairs == 0);
	 } else {
		b_iszero = (RSDDT_O[dx][i].npairs == 0);
	 }
	 double p = 1.0;
	 while((i != ALL_WORDS) && (!b_iszero)) {
		//	 while((i != ALL_WORDS)) {
		uint32_t dy = 0;
		if(is_even(n)) {
		  dy = RSDDT_E[dx][i].dy;
		  pn = (double)RSDDT_E[dx][i].npairs / (double)(ALL_WORDS);
		  assert(pn == RSDDT_E[dx][i].p);
		  assert(pn != 0.0);
		  assert((pn >= 0.0) && (pn <= 1.0));
		  assert(dx == RSDDT_E[dx][i].dx);
		} else {
		  dy = RSDDT_O[dx][i].dy;
		  pn = (double)RSDDT_O[dx][i].npairs / (double)(ALL_WORDS);
		  assert(pn == RSDDT_O[dx][i].p);
		  assert(pn != 0.0);
		  assert((pn >= 0.0) && (pn <= 1.0));
		  assert(dx == RSDDT_O[dx][i].dx);
		}
		uint32_t i_bound = (nrounds - 1 - (n + 1)); // index for the bound
		p = 1.0;
		for(int j = 0; j < n; j++) { // p[0] * p[1] * p[n-1]
		  p *= diff[j].p;
		}
		//		p = p * pn * B[nrounds - 1 - (n + 1)]; 
		p = p * pn * B[i_bound]; 
		assert(pn != 0.0);
		assert(B[nrounds - 1 - (n + 1)]);
		assert(p != 0.0);
		assert(pn != 0.0);
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
#if DEBUG									  // DEBUG
		  printf("\r[%s:%d] %d | i = %5d / %lld | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, i, ALL_WORDS, dx, dy, log2(p), log2(*Bn));
		  fflush(stdout);
#endif
		  round_ddt(n+1, nrounds, RSDDT_E, RSDDT_O, SDDT_O, B, Bn, diff, trail);
		} 
		i++;							  // !
		uint32_t dx_tmp = ADD(diff[n - 2].dx, diff[n - 1].dy);
		assert(dx_tmp == dx);
		if(is_even(n)) {
		  b_iszero = (RSDDT_E[dx][i].npairs == 0);
		} else {
		  b_iszero = (RSDDT_O[dx][i].npairs == 0);
		}
	 }
  }

  if((n == (nrounds - 1)) && (nrounds > 1)){		  // Last round
	 uint32_t dx = 0;
	 uint32_t dy = 0;	
	 if(nrounds == 2) { // Last round (n = 1) AND only two rounds - freely choose dx
		int idx_best = 0;
		if(diff[0].p == 1.0) {
		  assert(diff[0].dx == 0);
		  assert(diff[0].dy == 0);
		  // if the differential to round 0 is (dx = 0, dx = 0) then take the second best
		  // (index = 1) to avoid the zero difference trail
		  idx_best = 1;			  // !
		}
		dx = SDDT_O[idx_best].dx;
		dy = SDDT_O[idx_best].dy;
		pn = SDDT_O[idx_best].p;
	 } else {						  // more than 2 rounds - dx is fixed
		dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
		dy = 0;
		if(is_even(n)) {
		  pn = max_adp_f_rsddt(RSDDT_E, dx, &dy);
		} else {
		  pn = max_adp_f_rsddt(RSDDT_O, dx, &dy);
		}
	 }
	 assert((pn >= 0.0) && (pn <= 1.0));
	 assert(pn != 0.0);
	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;
	 assert(p != 0.0);
		
#if 1
	 if((p != 1.0) && (p > B[n - 1])) {
		printf("[%s:%d] WARNING! n = %d, %d: %f > %f, %8X, %8X\n", __FILE__, __LINE__, n, n - 1, p, B[n - 1], dx, dy);
	 }
#endif

	 if((p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if DEBUG									  // DEBUG
		printf("\r[%s:%d] %d | Update bound Bn: %f -> %f ", __FILE__, __LINE__, n, *Bn, p);
		fflush(stdout);
		//		  printf(" [%s:%d] %d | Update bound Bn: %f -> %f\n", __FILE__, __LINE__, n, *Bn, p);
#endif
		diff[n].dx = dx;
		diff[n].dy = dy;
		diff[n].p = pn;

		for(int i = 0; i < nrounds; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		} 
		*Bn = p;
		B[n] = p;
	 } 
  }
}

/**
 *
 * Search for ADD differential trails in a modified version of block
 * cipher TEA that uses the same round constant \f$\delta\f$ in every
 * round. Computes full difference distribution tables (DDT) for every
 * key and the same round constant: a wrapper function for \ref
 * round_ddt.
 *
 * \param key cryptographic key of TEA.
 *
 * \attention Assumes the same \f$\delta\f$ constant is used at every
 * round of TEA.
 *
 * \see tea_add_trail_search
 */
void tea_search_ddt(uint32_t key[4])
{
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;
#if 1									  // fixed key
  uint32_t k0 = key[0];
  uint32_t k1 = key[1];
  uint32_t k2 = key[2];
  uint32_t k3 = key[3];
#endif
  uint32_t delta = DELTA_INIT;
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				  // arey of bounds

  // compute DDT_E
  uint32_t** DDT_E;		  // even
#if 1									  // INFO
  printf("[%s:%d] Allocating DDT_E ...", __FILE__, __LINE__);
#endif
  DDT_E = ddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing DDT_E ...", __FILE__, __LINE__);
#endif
  ddt_f(DDT_E, k0, k1, delta, lsh_const, rsh_const);
#if 1									  // INFO
  printf("OK\n");
#endif

  // row-sorted DDT_E
  differential_t** RSDDT_E;
#if 1									  // INFO
  printf("[%s:%d] Allocating RSDDT_E ...", __FILE__, __LINE__);
#endif
  RSDDT_E = rsddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing RSDDT_E ...", __FILE__, __LINE__);
#endif
  ddt_to_diff_struct(DDT_E, RSDDT_E);
#if 1									  // INFO
  printf("OK\n");
#endif
#if 1									  // INFO
  printf("[%s:%d] Sort RSDDT_E ...", __FILE__, __LINE__);
#endif
  ddt_sort_rows(RSDDT_E);
#if 1									  // INFO
  printf("OK\n");
#endif

  // compute DDT_O
  uint32_t** DDT_O;		  // odd
#if 1									  // INFO
  printf("[%s:%d] Allocating DDT_O ...", __FILE__, __LINE__);
#endif
  DDT_O = ddt_alloc();
#if 0									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing DDT_O ...", __FILE__, __LINE__);
#endif
  ddt_f(DDT_O, k2, k3, delta, lsh_const, rsh_const);
#if 1									  // INFO
  printf("OK\n");
#endif

  // row-sorted DDT_O
  differential_t** RSDDT_O;
#if 1									  // INFO
  printf("[%s:%d] Allocating RSDDT_O ...", __FILE__, __LINE__);
#endif
  RSDDT_O = rsddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing RSDDT_O ...", __FILE__, __LINE__);
#endif
  ddt_to_diff_struct(DDT_O, RSDDT_O);
  //  ddt_sort_first_col(RSDDT_O);
#if 1									  // INFO
  printf("OK\n");
#endif

#if 1									  // INFO
  printf("[%s:%d] Sort RSDDT_O ...", __FILE__, __LINE__);
#endif
  ddt_sort_rows(RSDDT_O);
#if 1									  // INFO
  printf("OK\n");
#endif

  // sorted DDT
  differential_t* SDDT_O;
#if 1									  // INFO
  printf("[%s:%d] Allocating SDDT_O ...", __FILE__, __LINE__);
#endif

  SDDT_O = sddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing SDDT_O ...", __FILE__, __LINE__);
#endif
  ddt_to_list(DDT_O, SDDT_O);
#if 1									  // INFO
  printf("OK\n");
#endif
#if 1									  // INFO
  printf("[%s:%d] Sort SDDT_O ...", __FILE__, __LINE__);
#endif
  ddt_sort(SDDT_O);
#if 1									  // INFO
  printf("OK\n");
#endif

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  double Bn = 0.0;				  // initial bound

  for(int nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {

	 // WARNING!!! Funny correction due to floating point inaccuarcy
	 if(nrounds >= 15) {
		Bn = Bn * 0.005;
	 }
#if 1
	 printf("\nBegin searching for %d-round differentials: Bn = %f = 2^%f ...\n", nrounds, Bn, log2(Bn));
#endif

	 // init bounds, probs and diffs
	 for(int i = 0; i < NROUNDS; i++) {
		//	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 int r = 0;						  // initial round

	 round_ddt(r, nrounds, RSDDT_E, RSDDT_O, SDDT_O, B, &Bn, diff, trail);
	 B[nrounds - 1] = Bn;

#if 1 								  // INFO
	 printf("\nDDT Best trail for %d rounds:\n", nrounds);
	 // print bounds
	 for(int i = 0; i < nrounds; i++) {
		printf("B[%2d] = %16.15f (2^%f) ", i, B[i], log2(B[i]));
		if(i > 0) {
		  if(B[i] > B[i-1]) {
			 printf("<- (!)");
		  }
		}
		printf("\n");
	 }
	 double p_tot = 1.0;
	 for(int i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X (%f)", i, trail[i].dy, trail[i].dx, trail[i].p);
		uint32_t sum = ADD(trail[i].dx, trail[i].dy);
		if((sum == 0) && (trail[i].dx != 0)) {
		  printf(" !");
		}
		printf("\n");
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = 2^%f\n", p_tot, log2(p_tot), log2(Bn));
	 printf("key = %8X %8X %8X %8X\n", k0, k1, k2, k3);
#endif

	 // check if a characteristic is iterative
	 // with a period 2 rounds
	 bool b_is_iterative_2r = false;
	 if(nrounds >= 4) {
		b_is_iterative_2r = true;
		int i_start = nrounds - 4;
		uint32_t dx_prev_even, dx_prev_odd, dy_prev_even, dy_prev_odd;
		if(is_even(i_start)) {
		  dx_prev_even = trail[i_start].dx;
		  dy_prev_even = trail[i_start].dy;
		  dx_prev_odd = trail[i_start + 1].dx;
		  dy_prev_odd = trail[i_start + 1].dy;
		} else {
		  dx_prev_odd = trail[i_start].dx;
		  dy_prev_odd = trail[i_start].dy;
		  dx_prev_even = trail[i_start + 1].dx;
		  dy_prev_even = trail[i_start + 1].dy;
		}
		//		for(int i = 2; i < nrounds; i++) {
		int i = i_start + 2;;
		while((i < nrounds) && (b_is_iterative_2r)) {
		  if(is_even(i)) {
			 uint32_t dx_even = trail[i].dx;
			 uint32_t dy_even = trail[i].dy;
			 b_is_iterative_2r = ((dx_even == dx_prev_even) && (dy_even == dy_prev_even));
			 //			 printf("%d %8X == %8X | %8X == %8X\n", i, dx_even, dx_prev_even, dy_even, dy_prev_even);
		  } else {
			 uint32_t dx_odd = trail[i].dx;
			 uint32_t dy_odd = trail[i].dy;
			 b_is_iterative_2r = ((dx_odd == dx_prev_odd) && (dy_odd == dy_prev_odd));
			 //			 printf("%d %8X == %8X | %8X == %8X\n", i, dx_odd, dx_prev_odd, dy_odd, dy_prev_odd);
		  }
		  i++;
		}
	 }

#if 1									  // compute an initial bound for the next round
	 int next_round = nrounds;
	 if(b_is_iterative_2r == true) {
		printf("[%s:%d] Iterative characteristic! Setting the bound!\n", __FILE__, __LINE__);
		if(next_round >= 2) {
		  uint32_t dx = trail[next_round - 2].dx;//ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		  uint32_t dy = trail[next_round - 2].dy;
		  double p_max = trail[next_round - 2].p;
#if 1	// DEBUG
		  printf("[%s:%d] %d: %8X -> %8X %f\n", __FILE__, __LINE__, next_round, dx, dy, p_max);
		  printf("[%s:%d] %8X -> %8X %f | %f * %f = %f = 2^%f\n", __FILE__, __LINE__, dx, dy, p_max, Bn, p_max, Bn * p_max, log2(Bn * p_max));
#endif
		  Bn = Bn * p_max;
		} 
	 } else {						  // not iterative
		if(next_round == 1) {	  // 2 rounds
		  int idx_best = 1;
		  // we skip the trivial differential (dx = 0, dy = 0) that corresponds to idx_best = 0
		  if(Bn < 1.0) {
			 idx_best = 0;
		  }
		  double p_max = SDDT_O[idx_best].p;
		  Bn = Bn * p_max;
		} else {						  // not iterative and not 1st round then extend by one round
#if 1
		  if(next_round < NROUNDS) {
			 printf("[%s:%d] Init bound for round# %d: ", __FILE__, __LINE__, nrounds);
			 uint32_t dx = ADD(trail[nrounds - 2].dx, trail[nrounds - 1].dy);
			 uint32_t dy = 0;
			 double p_max = 0.0;
			 if(is_even(nrounds)) {
				//				printf("[%s:%d] Here!\n", __FILE__, __LINE__);
				uint32_t dx_test = RSDDT_E[dx][0].dx;
				dy = RSDDT_E[dx][0].dy;
				p_max = RSDDT_E[dx][0].p;
				assert(dx_test == dx);
			 } else {
				//				printf("[%s:%d] Here!\n", __FILE__, __LINE__);
				uint32_t dx_test = RSDDT_O[dx][0].dx;
				dy = RSDDT_O[dx][0].dy;
				p_max = RSDDT_O[dx][0].p;
				assert(dx_test == dx);
			 }
			 //			 printf("[%s:%d] Here next_round %d NROUNDS %d\n", __FILE__, __LINE__, next_round, NROUNDS);
			 assert((next_round - 1) < NROUNDS);
			 assert(next_round > 0);
			 trail[next_round].dx = dx;
			 trail[next_round].dy = dy;
			 trail[next_round].p = p_max;
			 Bn = Bn * p_max;
			 printf("Bn_init = %f (2^%f)\n", Bn, log2(Bn));
		  }
#endif
		}
	 }
#endif

	 // check correctness
#if 1 								  // VERIFY
	 for(int i = 0; i < nrounds; i++) {

		uint32_t dx = trail[i].dx;
		uint32_t dy = trail[i].dy;
		double p = 0.0;
		if(is_even(i)) {
		  p = adp_f_ddt(DDT_E, dx, dy);
		} else {
		  p = adp_f_ddt(DDT_O, dx, dy);
		}
		assert(p == trail[i].p);
	 }
	 if(nrounds >=3) {
		for(int i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif
  } // for (rounds)

  tea_add_verify_trail(num_rounds, npairs, key, trail);
  tea_add_verify_differential(num_rounds, npairs, key, trail);

  rsddt_free(RSDDT_E);
  rsddt_free(RSDDT_O);
  sddt_free(SDDT_O);
  // free DDT_E
  ddt_free(DDT_E);
  // free DDT_O
  ddt_free(DDT_O);
}

// --- extended DDT (XDDT) -- separate ddt for each delta ---
/**
 * 
 * Automatic search for ADD differential trails using precomputed full
 * difference distribution tables (DDT) for \b the \b original \b version
 * \b of \b TEA.
 * 
 * \attention For every round constant \f$\delta\f$, two DDT-s are
 *            computed: \p DDT_E containing the fixed-key
 *            fixed-\f$\delta\f$ probabilities for the round keys
 *            applied in all even rounds: \f$0,2,4,\ldots\f$ and \p
 *            DDT_O containing the fixed-key fixed-\f$\delta\f$
 *            probabilities for the round keys applied in all odd
 *            rounds: \f$1,3,5,\ldots\f$. Since \f$\delta\f$ is
 *            updated every second round, for \f$N\f$ rounds
 *            \f$2(N/2)\f$ DDT-s will be computed.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param XRSDDT_E an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all even rounds \f$0,2,4,\ldots\f$ with the elements in each
 *        row (i.e. for a fixed input difference) sorted in descending
 *        order of their probability (an eXtended Row-Sorted \p DDT_E).
 * \param XRSDDT_O an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all odd rounds \f$1,3,5,\ldots\f$ with the elements in each
 *        row (i.e. for a fixed input difference) sorted in descending
 *        order of their probability (an eXtended  Row-Sorted \p DDT_O).
 * \param XSDDT_O an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all odd rounds will all elements sorted in descending order
 *        of their probability (an eXtended  Sorted \p DDT_O).
 * \param B array containing the best differential probabilities for i
 *        rounds: \f$0 \le i < n\f$.
 * \param Bn the best probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best differential trail for \p nrounds.
 *
 * The outline of the array of bounds \f$B\f$ is the following: 
 * 
 * - \f$B[0]\f$: best probability for \f$1\f$ round.
 * - \f$B[1]\f$: best probability for \f$2\f$ rounds.
 * - \f$\ldots\f$
 * - \f$B[i]\f$: best probability for \f$(i+1)\f$ rounds.
 * - \f$\ldots\f$
 * - \f$B[n-2]\f$: best probability for \f$(n-1)\f$ rounds.
 * - \f$B[n-1]\f$: best probability for \f$n\f$ rounds.
 * 
 * \see round_ddt
 */
void round_xddt(const int n, const int nrounds, 
					 differential_t*** XRSDDT_E, differential_t*** XRSDDT_O, differential_t** XSDDT_O,
					 const double B[NROUNDS], double* Bn,
					 differential_t diff_in[NROUNDS], differential_t trail[NROUNDS])
{
  double pn = 0.0;

  // make a local copy of the input diff trail
#if 1
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].npairs = diff_in[i].npairs;
	 diff[i].p = diff_in[i].p;
  }
#endif
  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 uint32_t dx = 0;
	 uint32_t idx_delta = 0;
	 while((dx != ALL_WORDS) && (XRSDDT_E[idx_delta][dx][0].npairs != 0)) {
		uint32_t dy = 0;
		pn = max_adp_f_rsddt(XRSDDT_E[idx_delta], dx, &dy); // even
		assert((pn >= 0.0) && (pn <= 1.0));
		if((pn >= *Bn) && (pn != 0.0)) {
#if DEBUG_XDDT									  // DEBUG_XDDT
		  printf(" [%s:%d] %d | Update bound Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(pn));
#endif
		  trail[n].dx = dx;
		  trail[n].dy = dy;
		  trail[n].p = pn;
		  *Bn = pn;
		}
		dx++;							  // !
	 }
  }
  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 uint32_t dx = 0;				  // vpv-20120802
	 uint32_t idx_delta = 0;
	 while((dx != ALL_WORDS) && (XRSDDT_E[idx_delta][dx][0].npairs != 0)) {
		uint32_t dy = 0;
		pn = max_adp_f_rsddt(XRSDDT_E[idx_delta], dx, &dy); // even
		assert((pn >= 0.0) && (pn <= 1.0));
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(pn != 0.0);
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
#if DEBUG_XDDT									  // DEBUG_XDDT
		  printf("\r[%s:%d] %d | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, dx, dy, log2(p), log2(*Bn));
		  fflush(stdout);
#endif
		  round_xddt(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_O, B, Bn, diff, trail);
		}
		dx++;							  // !
	 }
  }
  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 uint32_t i = 0;
	 uint32_t idx_delta = 0;
	 while((i != (ALL_WORDS * ALL_WORDS)) && (XSDDT_O[idx_delta][i].npairs != 0)) {
		uint32_t dx = XSDDT_O[idx_delta][i].dx;
		uint32_t dy = XSDDT_O[idx_delta][i].dy;
		pn = (double)XSDDT_O[idx_delta][i].npairs / (double)(ALL_WORDS);
		assert((pn >= 0.0) && (pn <= 1.0));
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
#if DEBUG_XDDT									  // DEBUG_XDDT
		  printf("\r[%s:%d] %d | i = %5d / %lld | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, i, (ALL_WORDS * ALL_WORDS), dx, dy, log2(p), log2(*Bn));
		  fflush(stdout);
#endif
		  round_xddt(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_O, B, Bn, diff, trail);
		}
		i++;							  // !
	 }
  }
  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
		uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
		uint32_t i = 0;
		uint32_t idx_delta = (n / 2); // 1 / 2 = 0, 3 / 2 = 1, div
		while((i != ALL_WORDS) && (XRSDDT_E[idx_delta][dx][i].npairs != 0)) {
		  uint32_t dy = 0;
		  if(is_even(n)) {
			 dy = XRSDDT_E[idx_delta][dx][i].dy;
			 pn = (double)XRSDDT_E[idx_delta][dx][i].npairs / (double)(ALL_WORDS);
			 assert((pn >= 0.0) && (pn <= 1.0));
			 assert(dx == XRSDDT_E[idx_delta][dx][i].dx);
		  } else {
			 dy = XRSDDT_O[idx_delta][dx][i].dy;
			 pn = (double)XRSDDT_O[idx_delta][dx][i].npairs / (double)(ALL_WORDS);
			 assert((pn >= 0.0) && (pn <= 1.0));
			 assert(dx == XRSDDT_O[idx_delta][dx][i].dx);
		  }
		  double p = 1.0;
		  for(int j = 0; j < n; j++) { // p[0] * p[1] * p[n-1]
			 p *= diff[j].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
#if DEBUG_XDDT									  // DEBUG_XDDT
			 printf("\r[%s:%d] %d | i = %5d / %lld | DX = %8X, DY = %8X, p = 2^%f, Bn = 2^%f", __FILE__, __LINE__, n, i, ALL_WORDS, dx, dy, log2(p), log2(*Bn));
			 fflush(stdout);
#endif
			 round_xddt(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_O, B, Bn, diff, trail);
		  }
		  i++;							  // !
		}

  }
  if((n == (nrounds - 1)) && (nrounds > 1)){		  // Last round
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t dy = 0;
	 uint32_t idx_delta = (n / 2); // 1 / 2 = 0, 3 / 2 = 1, div
	 if(is_even(n)) {
		pn = max_adp_f_rsddt(XRSDDT_E[idx_delta], dx, &dy);
	 } else {
		pn = max_adp_f_rsddt(XRSDDT_O[idx_delta], dx, &dy);
	 }
	 assert((pn >= 0.0) && (pn <= 1.0));
	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;
	 if((p >= *Bn) && (p != 1.0) && (p != 0.0)) { // vpv-20120802! - skip the 0-diff trail (p = 1.0)
#if DEBUG_XDDT									  // DEBUG_XDDT
		printf(" \n[%s:%d] %d | Update bound Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
#endif
		diff[n].dx = dx;
		diff[n].dy = dy;
		diff[n].p = pn;
		*Bn = p;
		for(int i = 0; i < nrounds; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

/**
 * Search for ADD differential trails in the original version of block
 * cipher TEA. Computes full difference distribution tables (DDT) for
 * every key and every round constant: a wrapper function for \ref
 * round_xddt.
 *
 * \param key cryptographic key of TEA.
 *
 * \see round_xddt
 */
void tea_search_xddt(uint32_t key[4])
{
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;
#if 1									  // fixed key
  uint32_t k0 = key[0];
  uint32_t k1 = key[1];
  uint32_t k2 = key[2];
  uint32_t k3 = key[3];
#endif

  //  uint32_t delta = DELTA_INIT;
  uint32_t delta[TEA_NCYCLES] = {0};
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  differential_t diff[NROUNDS];	 // array of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				    // array of bounds

  // compute all tea delta-s
  tea_compute_delta_const(delta);

  assert(NDELTA <= TEA_NCYCLES);

#if 0									  // DEBUG
  for(int i = 0; i < TEA_NCYCLES; i++) { 
	 printf("[%2d]%8X\n", i, delta[i]);
  }
#endif

  // compute XDDT_E
  uint32_t*** XDDT_E;		  // even
  XDDT_E = xddt_alloc();
  for(int i = 0; i < NDELTA; i++) {
	 ddt_f(XDDT_E[i], k0, k1, delta[i], lsh_const, rsh_const);
  }

  // row-sorted XDDT_E
  differential_t*** XRSDDT_E;
  XRSDDT_E = xrsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_diff_struct(XDDT_E[i], XRSDDT_E[i]);
	 ddt_sort_rows(XRSDDT_E[i]);
  }

  // compute XDDT_O
  uint32_t*** XDDT_O;		  // odd
  XDDT_O = xddt_alloc();
  for(int i = 0; i < NDELTA; i++) {
	 ddt_f(XDDT_O[i], k2, k3, delta[i], lsh_const, rsh_const);
  }

  // row-sorted XDDT_O
  differential_t*** XRSDDT_O;
  XRSDDT_O = xrsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_diff_struct(XDDT_O[i], XRSDDT_O[i]);
	 ddt_sort_rows(XRSDDT_O[i]);
  }

  // sorted XDDT
  differential_t** XSDDT_O;
  XSDDT_O = xsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_list(XDDT_O[i], XSDDT_O[i]);
	 ddt_sort(XSDDT_O[i]);
  }

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  for(int nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {

#if DEBUG
	 printf("\nBegin searching for %d-round differentials...\n", nrounds);
#endif

	 // init bounds, probs and diffs
	 for(int i = 0; i < NROUNDS; i++) {
		//	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;

		trail[i].dx = 0;
		trail[i].dy = 0;
		trail[i].p = 0.0;
	 }

	 double Bn = 0.0;				  // initial bound
	 int r = 0;						  // initial round

	 round_xddt(r, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_O, B, &Bn, diff, trail);

	 B[nrounds - 1] = Bn;

#if 1 								  // INFO
	 printf("Best trail for %2d rounds:\n", nrounds);
	 // print bounds
	 for(int i = 0; i < nrounds; i++) {
		printf("B[%d] = %16.15f (2^%f) ", i, B[i], log2(B[i]));
		if(i > 0) {
		  if(B[i] > B[i-1]) {
			 printf("<- (!)");
		  }
		}
		printf("\n");
	 }
	 double p_tot = 1.0;
	 for(int i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X (%f)", i, trail[i].dy, trail[i].dx, trail[i].p);
		uint32_t sum = ADD(trail[i].dx, trail[i].dy);
		if((sum == 0) && (trail[i].dx != 0)) {
		  printf(" !");
		}
		printf("\n");
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = 2^%f\n", p_tot, log2(p_tot), log2(Bn));
	 printf("key = %8X %8X %8X %8X\n", k0, k1, k2, k3);
#endif
	 //	 print_trail_latex(fp_xddt_latex, nrounds, g_key_arrey, trail);

	 // check correctness
#if 1 								  // VERIFY
	 for(int i = 0; i < nrounds; i++) {

		uint32_t dx = trail[i].dx;
		uint32_t dy = trail[i].dy;
		double p = 0.0;
		uint32_t idx_delta = (i / 2);
		if(is_even(i)) {
		  p = adp_f_ddt(XDDT_E[idx_delta], dx, dy);
		} else {
		  p = adp_f_ddt(XDDT_O[idx_delta], dx, dy);
		}
		assert(p == trail[i].p);

	 }
	 if(nrounds >=3) {
		for(int i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif
  } // for (rounds)

  // check probabilities of differentials for one round
  tea_add_verify_trail(num_rounds, npairs, key, trail);
  // check probabilities of differentials for multiple rounds
  tea_add_verify_differential(num_rounds, npairs, key, trail);

  xsddt_free(XSDDT_O);
  xrsddt_free(XRSDDT_O);
  xddt_free(XDDT_O);
  xrsddt_free(XRSDDT_E);
  xddt_free(XDDT_E);
}

/**
 * 
 * Automatic search for ADD differential trails using precomputed full
 * difference distribution tables (DDT) for \b the \b original \b version
 * \b of \b TEA.
 * 
 * \ref round_xddt_bottom_up is conceptually the same as \ref
 *  round_xddt, except that \b the \b search \b proceeds \b from \b
 *  the \b bottom \b up i.e. first finds the best 1-round trail for
 *  the last round \f$N\f$, next finds the best 2-round trail for
 *  rounds \f$N-1, N\f$, etc. finds the best \f$i\f$-round trail for
 *  rounds \f$i, i+1, \ldots, N\f$ and finally finds the best
 *  \f$N\f$-round trail.
 *
 * \attention For every round constant \f$\delta\f$, two DDT-s are
 *            computed: \p DDT_E containing the fixed-key
 *            fixed-\f$\delta\f$ probabilities for the round keys
 *            applied in all even rounds: \f$0,2,4,\ldots\f$ and \p
 *            DDT_O containing the fixed-key fixed-\f$\delta\f$
 *            probabilities for the round keys applied in all odd
 *            rounds: \f$1,3,5,\ldots\f$. Since \f$\delta\f$ is
 *            updated every second round, for \f$N\f$ rounds
 *            \f$2(N/2)\f$ DDT-s will be computed.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param XRSDDT_E an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all even rounds \f$0,2,4,\ldots\f$ with the elements in each
 *        row (i.e. for a fixed input difference) sorted in descending
 *        order of their probability (an eXtended Row-Sorted \p DDT_E).
 * \param XRSDDT_O an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all odd rounds \f$1,3,5,\ldots\f$ with the elements in each
 *        row (i.e. for a fixed input difference) sorted in descending
 *        order of their probability (an eXtended  Row-Sorted \p DDT_O).
 * \param XSDDT_O an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all odd rounds will all elements sorted in descending order
 *        of their probability (an eXtended  Sorted \p DDT_O).
 * \param XSDDT_E an array of fixed-key fixed-\f$\delta\f$ DDT-s for
 *        all even rounds will all elements sorted in descending order
 *        of their probability (an eXtended  Sorted \p DDT_E).
 * \param B array containing the best differential probabilities for i
 *        rounds: \f$0 \le i < n\f$.
 * \param Bn the best probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best differential trail for \p nrounds.
 *
 * The outline of the array of bounds \f$B\f$ is the following: 
 * 
 * - \f$B[0]\f$: best probability for \f$n\f$ rounds.
 * - \f$B[1]\f$: best probability for \f$(n-1)\f$ rounds.
 * - \f$\ldots\f$
 * - \f$B[i]\f$: best probability for \f$(n-i)\f$ rounds (rounds\f$n-i, n-i+1, \ldots, n\f$).
 * - \f$\ldots\f$
 * - \f$B[n-2]\f$: best probability for \f$2\f$ rounds (rounds \f$n-1,n\f$).
 * - \f$B[n-1]\f$: best probability for \f$1\f$ round (round \f$n\f$).
 * 
 * \see round_xddt
 */
void round_xddt_bottom_up(const int n, const int nrounds, 
								  differential_t*** XRSDDT_E, differential_t*** XRSDDT_O, 
								  differential_t** XSDDT_E, differential_t** XSDDT_O, 
								  const double B[NROUNDS], double* Bn,
								  differential_t diff_in[NROUNDS], differential_t trail[NROUNDS])
{
#if 1
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < NROUNDS; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].npairs = diff_in[i].npairs;
	 diff[i].p = diff_in[i].p;
  }
#endif
  double pn = 0.0;
  if((n < (NROUNDS - 1)) && ((NROUNDS - n) == nrounds)) {		  // First round
	 uint32_t idx_delta = (n/2);
	 if(is_even(n)) {
		uint32_t dx = 0;
		while((dx != ALL_WORDS) && (XRSDDT_E[idx_delta][dx][0].npairs != 0)) {
		  uint32_t dy = 0;
		  pn = max_adp_f_rsddt(XRSDDT_E[idx_delta], dx, &dy); // even
		  assert((pn >= 0.0) && (pn <= 1.0));
		  double p = pn * B[n + 1];
		  assert(pn != 0.0);
		  //		  printf("[%s:%d] %8X %8X %f | p = %f Bn = %f\n", __FILE__, __LINE__, dx, dy, pn, p, *Bn);
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  dx++;							  // !
		  //		  dx = ALL_WORDS;
		}
	 } else {
		uint32_t dx = 0;
		while((dx != ALL_WORDS) && (XRSDDT_O[idx_delta][dx][0].npairs != 0)) {
		  uint32_t dy = 0;
		  pn = max_adp_f_rsddt(XRSDDT_O[idx_delta], dx, &dy); // even
		  assert((pn >= 0.0) && (pn <= 1.0));
		  double p = pn * B[n + 1];
		  assert(pn != 0.0);
		  //		  printf("[%s:%d] %8X %8X %f | p = %f Bn = %f\n", __FILE__, __LINE__, dx, dy, pn, p, *Bn);
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  dx++;							  // !
		  //		  dx = ALL_WORDS;
		}
	 }
	 //	 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
  }
  if((n < (NROUNDS - 1)) && ((NROUNDS - n) == (nrounds - 1))) {		  // Second round and not last round
	 uint32_t idx_delta = (n/2);
	 if(is_even(n)) {
		uint32_t i = 0;
		while((i != (ALL_WORDS * ALL_WORDS)) && (XSDDT_E[idx_delta][i].npairs != 0)) {
		  uint32_t dx = XSDDT_E[idx_delta][i].dx;
		  uint32_t dy = XSDDT_E[idx_delta][i].dy;
		  pn = (double)XSDDT_E[idx_delta][i].npairs / (double)(ALL_WORDS);
		  assert((pn >= 0.0) && (pn <= 1.0));
		  double p = diff[n - 1].p * pn * B[n + 1];
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  i++;							  // !
		  //		  i = ALL_WORDS * ALL_WORDS;
		}
	 } else {
		uint32_t i = 0;
		while((i != (ALL_WORDS * ALL_WORDS)) && (XSDDT_O[idx_delta][i].npairs != 0)) {
		  uint32_t dx = XSDDT_O[idx_delta][i].dx;
		  uint32_t dy = XSDDT_O[idx_delta][i].dy;
		  pn = (double)XSDDT_O[idx_delta][i].npairs / (double)(ALL_WORDS);
		  assert((pn >= 0.0) && (pn <= 1.0));
		  double p = diff[n - 1].p * pn * B[n + 1];
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  i++;							  // !
		  //		  i = ALL_WORDS * ALL_WORDS;
		}
	 }
  }
  if((n < (NROUNDS - 1)) && ((NROUNDS - n) != nrounds) && ((NROUNDS - n) != (nrounds - 1))) {		  // Round-i and not first round and not second round
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t idx_delta = (n / 2);
	 if(is_even(n)) {
		uint32_t i = 0;
		while((i != ALL_WORDS) && (XRSDDT_E[idx_delta][dx][i].npairs != 0)) {
		  uint32_t dy = XRSDDT_E[idx_delta][dx][i].dy;
		  pn = (double)XRSDDT_E[idx_delta][dx][i].npairs / (double)(ALL_WORDS);
		  double p = 1.0;
		  assert((NROUNDS - nrounds) < n);
		  for(int j = (NROUNDS - nrounds); j < n; j++) { // p[i] * p[i+1] * ... * p[n-1]
			 p *= diff[j].p;
		  }
		  p = p * pn * B[n + 1]; 
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  i++;							  // !
		  //		  i = ALL_WORDS;
		}
	 } else {
		uint32_t i = 0;
		while((i != ALL_WORDS) && (XRSDDT_O[idx_delta][dx][i].npairs != 0)) {
		  uint32_t dy = XRSDDT_O[idx_delta][dx][i].dy;
		  pn = (double)XRSDDT_O[idx_delta][dx][i].npairs / (double)(ALL_WORDS);
		  double p = 1.0;
		  assert((NROUNDS - nrounds) < n);
		  for(int j = (NROUNDS - nrounds); j < n; j++) { // p[i] * p[i+1] * ... * p[n-1]
			 p *= diff[j].p;
		  }
		  p = p * pn * B[n + 1]; 
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 round_xddt_bottom_up(n+1, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, Bn, diff, trail);
		  }
		  i++;							  // !
		  //		  i = ALL_WORDS;
		}
	 }
  }
  if(n == (NROUNDS - 1)) { // Last round
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t dy = 0;
	 uint32_t idx_delta = (n / 2);
	 assert(!is_even(n));		  // the last round is always ODD as we always require even number of rounds
	 pn = max_adp_f_rsddt(XRSDDT_O[idx_delta], dx, &dy);
	 assert((pn >= 0.0) && (pn <= 1.0));
	 double p = 1.0;
	 assert((NROUNDS - nrounds) < n);
    for(int j = (NROUNDS - nrounds); j < n; j++) { // p[i] * p[i+1] * ... * p[n-1]
		p *= diff[j].p;
	 }
	 p *= pn;
	 if((p >= *Bn) && (p != 1.0) && (p != 0.0)) {
#if 1//DEBUG_XDDT									  // DEBUG_XDDT
		printf(" \r[%s:%d] %d | Update bound Bn: 2^%f -> 2^%f", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		fflush(stdout);
#endif
		diff[n].dx = dx;
		diff[n].dy = dy;
		diff[n].p = pn;
		*Bn = p;
		assert((NROUNDS - nrounds) < NROUNDS);
		for(int i = (NROUNDS - nrounds); i < NROUNDS; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

/**
 * Search for ADD differential trails in the original version of block
 * cipher TEA. Computes full difference distribution tables (DDT) for
 * every key and every round constant. Conceptually the same as \ref
 * tea_search_xddt, except that the search starts from the last
 * round and proceeds up to the first (i.e. in a bottom-up amnner).
 * This function is a wrapper for \ref round_xddt_bottom_up.
 *
 * \param key cryptographic key of TEA.
 *
 * \see round_xddt_bottom_up
 */
void tea_search_xddt_bottom_up(uint32_t key[4])
{
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;
#if 1									  // fixed key
  uint32_t k0 = key[0];
  uint32_t k1 = key[1];
  uint32_t k2 = key[2];
  uint32_t k3 = key[3];
#endif

  //  uint32_t delta = DELTA_INIT;
  uint32_t delta[TEA_NCYCLES] = {0};
  uint32_t lsh_const = TEA_LSH_CONST;
  uint32_t rsh_const = TEA_RSH_CONST;

  differential_t diff[NROUNDS];	 // array of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				    // array of bounds

  // compute all tea delta-s
  tea_compute_delta_const(delta);

  assert(NDELTA <= TEA_NCYCLES);

  // compute XDDT_E
  uint32_t*** XDDT_E;		  // even
  XDDT_E = xddt_alloc();
  for(int i = 0; i < NDELTA; i++) {
	 ddt_f(XDDT_E[i], k0, k1, delta[i], lsh_const, rsh_const);
  }

  // row-sorted XDDT_E
  differential_t*** XRSDDT_E;
  XRSDDT_E = xrsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_diff_struct(XDDT_E[i], XRSDDT_E[i]);
	 ddt_sort_rows(XRSDDT_E[i]);
  }

  // compute XDDT_O
  uint32_t*** XDDT_O;		  // odd
  XDDT_O = xddt_alloc();
  for(int i = 0; i < NDELTA; i++) {
	 ddt_f(XDDT_O[i], k2, k3, delta[i], lsh_const, rsh_const);
  }

  // row-sorted XDDT_O
  differential_t*** XRSDDT_O;
  XRSDDT_O = xrsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_diff_struct(XDDT_O[i], XRSDDT_O[i]);
	 ddt_sort_rows(XRSDDT_O[i]);
  }

  // sorted XDDT_O
  differential_t** XSDDT_O;
  XSDDT_O = xsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_list(XDDT_O[i], XSDDT_O[i]);
	 ddt_sort(XSDDT_O[i]);
  }

  // sorted XDDT_E
  differential_t** XSDDT_E;
  XSDDT_E = xsddt_alloc();

  for(int i = 0; i < NDELTA; i++) {
	 ddt_to_list(XDDT_E[i], XSDDT_E[i]);
	 ddt_sort(XSDDT_E[i]);
  }

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  // init bounds, probs and diffs
  for(int i = 0; i < NROUNDS; i++) {
	 diff[i].dx = 0;
	 diff[i].dy = 0;
	 diff[i].p = 0.0;
  }

  for(int i = 0; i < NROUNDS; i++) {
	 trail[i].dx = 0;
	 trail[i].dy = 0;
	 trail[i].p = 0.0;
  }

  // Init the bounds for the last two rounds
  // Round N - 1
  trail[NROUNDS - 1].dx = 0;
  trail[NROUNDS - 1].dy = 0;
  trail[NROUNDS - 1].p = 1.0;
  B[NROUNDS - 1] = trail[NROUNDS - 1].p;

  diff[NROUNDS - 1].dx = 0;
  diff[NROUNDS - 1].dy = 0;
  diff[NROUNDS - 1].p = 1.0;

  // Round N - 2
  uint32_t idx_delta = ((NROUNDS - 1) / 2); // XSDDT_E[4], round index 8
  assert(idx_delta = 4);
  uint32_t idx = 1;			  // get the second element as the first (idx = 0) has dx = dy = 0
  trail[NROUNDS - 2].dx = XSDDT_E[idx_delta][idx].dx;
  trail[NROUNDS - 2].dy = XSDDT_E[idx_delta][idx].dy;
  trail[NROUNDS - 2].p = XSDDT_E[idx_delta][idx].p;
  B[NROUNDS - 2] = trail[NROUNDS - 2].p * B[NROUNDS - 1];

  diff[NROUNDS - 2].dx = trail[NROUNDS - 2].dx;
  diff[NROUNDS - 2].dy = trail[NROUNDS - 2].dy;
  diff[NROUNDS - 2].p = trail[NROUNDS - 2].p;

  for(int nrounds = 3; nrounds <= NROUNDS; nrounds++ ) {

#if 1									  // DEBUG
	 printf("\nBegin searching for %d-round differentials...\n", nrounds);
#endif

	 // init bounds, probs and diffs
	 for(int i = 0; i < (NROUNDS - 2); i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 for(int i = 0; i < (NROUNDS - 2); i++) {
		trail[i].dx = 0;
		trail[i].dy = 0;
		trail[i].p = 0.0;
	 }

	 printf("[%s:%d] B[%d] = %f (%8X %8X) | B[%d] %f\n", __FILE__, __LINE__, NROUNDS - 2, B[NROUNDS - 2], trail[NROUNDS - 2].dx, trail[NROUNDS - 2].dy, NROUNDS - 1, B[NROUNDS - 1]);

	 double Bn = 0.0;				  // initial bound
	 int r = NROUNDS - nrounds;						  // initial round
	 printf("[%s:%d] Initial bound Bn = %f\n", __FILE__, __LINE__, Bn);
	 round_xddt_bottom_up(r, nrounds, XRSDDT_E, XRSDDT_O, XSDDT_E, XSDDT_O, B, &Bn, diff, trail);
	 printf("[%s:%d] Updated bound Bn = %f\n", __FILE__, __LINE__, Bn);
	 B[r] = Bn;

#if 1 								  // INFO
	 printf("Best trail for %2d rounds:\n", nrounds);
	 for(int i = r; i < NROUNDS; i++) {
		printf("B[%d] = %16.15f (2^%f)\n", i, B[i], log2(B[i]));
	 }
	 double p_tot = 1.0;
	 for(int i = r; i < NROUNDS; i++) {
		printf("%2d: %8X <- %8X (%f)", i, trail[i].dy, trail[i].dx, trail[i].p);
		uint32_t sum = ADD(trail[i].dx, trail[i].dy);
		if((sum == 0) && (trail[i].dx != 0)) {
		  printf(" !");
		}
		printf("\n");
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = 2^%f\n", p_tot, log2(p_tot), log2(Bn));
	 printf("key = %8X %8X %8X %8X\n", k0, k1, k2, k3);
#endif
	 //	 print_trail_latex(fp_xddt_latex, nrounds, g_key_arrey, trail);

	 // check correctness
#if 1 								  // VERIFY
	 for(int i = r; i < NROUNDS; i++) {
		uint32_t dx = trail[i].dx;
		uint32_t dy = trail[i].dy;
		double p = 0.0;
		uint32_t idx_delta = (i / 2);
		if(is_even(i)) {
		  p = adp_f_ddt(XDDT_E[idx_delta], dx, dy);
		} else {
		  p = adp_f_ddt(XDDT_O[idx_delta], dx, dy);
		}
		printf("%8X <- %8X ", dy, dx);
		printf("%f %f\n", p, trail[i].p);
		assert(p == trail[i].p);
		if(i >= (r + 3)) {
#if 0									  // DEBUG
		  printf("i = %d: %8X %8X\n", i, trail[i].dx, ADD(trail[i - 2].dx, trail[i - 1].dy));
#endif  // #if 0									  // DEBUG
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif

  } // for (rounds)

  // check probabilities of differentials for one round
  tea_add_verify_trail(num_rounds, npairs, key, trail);
  // check probabilities of differentials for multiple rounds
  tea_add_verify_differential(num_rounds, npairs, key, trail);

  xsddt_free(XSDDT_O);
  xsddt_free(XSDDT_E);
  xrsddt_free(XRSDDT_O);
  xrsddt_free(XRSDDT_E);
  xddt_free(XDDT_O);
  xddt_free(XDDT_E);
}
