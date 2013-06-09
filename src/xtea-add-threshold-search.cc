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
 * \file  xtea-add-threshold-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Automatic search for ADD differential trails in block cipher XTEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "adp-xor.hh"
#endif
#ifndef MAX_ADP_XOR_H
#include "max-adp-xor.hh"
#endif
#ifndef ADP_XOR_FI_H
#include "adp-xor-fi.hh"
#endif
#ifndef MAX_ADP_XOR_FI_H
#include "max-adp-xor-fi.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef ADP_XTEA_F_FK_H
#include "adp-xtea-f-fk.hh"
#endif
#ifndef XTEA_F_ADD_PDDT_H
#include "xtea-f-add-pddt.hh"
#endif

/**
 * 
 * Automatic search for ADD differential trails in block cipher XTEA
 * using pDDT.
 *
 * \note For more details on the algorithm see \ref
 *       tea_add_threshold_search.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_key all round keys for the full XTEA.
 * \param round_delta all round constants for the full XTEA. 
 * \param A transition probability matrices for
 *        \f$\mathrm{adp}^{\oplus}\f$ (\ref adp_xor_sf).
 * \param AA transition probability matrices for XOR with fixed input
 *        \f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}\f$ (\ref
 *        adp_xor_fixed_input_sf).
 * \param B array containing the best differential probabilities for i
 *        rounds: \f$0 \le i < n\f$.
 * \param Bn the best found probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best found differential trail for \p nrounds.
 * \param lsh_const LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const RSH constant (\ref TEA_RSH_CONST).
 * \param diff_mset_p set of differentials \f$(dx,dy,p)\f$ (the pDDT)
 *        ordered by probability p.
 * \param diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (the
 *        pDDT) ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
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
 * \see tea_add_threshold_search.
 *
 */
void xtea_add_threshold_search(const int n, const int nrounds, const uint32_t npairs, 
										 const uint32_t round_key[64], const uint32_t round_delta[64],
										 gsl_matrix* A[2][2][2], gsl_matrix* AA[2][2][2], double B[NROUNDS], double* Bn,
										 const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										 uint32_t lsh_const, uint32_t rsh_const,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].npairs = diff_in[i].npairs;
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 assert(*Bn == 0.0);
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
#if 1									  // adjust to key
		pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const);
#endif
		assert(pn != 0.0);
		if((pn >= *Bn) && (pn != 0.0)) {
		  trail[n].dx = dx;
		  trail[n].dy = dy;
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
	 }
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
#if 1									  // adjust to key
		pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const);
#endif
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);

		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) { // !!! discard zero probability, vpv-20120906
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  xtea_add_threshold_search(n+1, nrounds, npairs, round_key, round_delta, A, AA, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }		 // while
  }		 // if(n == 0)

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
#if 1									  // adjust to key
		pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const);
#endif
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];

		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) { // !!! discard zero probability, vpv-20120906
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  xtea_add_threshold_search(n+1, nrounds, npairs, round_key, round_delta, A, AA, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }
  }

  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t dy = 0;

	 differential_t diff_dy;
	 diff_dy.dx = dx;  
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
	 if(!b_found) {				  // if not found, add new

		pn = first_nz_adp_xtea_f(A, AA, round_key[n], round_delta[n], dx, &dy, lsh_const, rsh_const);
#if 0									  // adjust to key
		pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const);
#endif
		assert(pn != 0.0);  // vpv

		diff_dy.dx = dx;  
		diff_dy.dy = dy;
		diff_dy.p = pn;

		// Add the new diff to Dp only if it has better prob. than the min.
#if 1
		double p_min = diff_mset_p->rbegin()->p;
		if(diff_dy.p >= p_min) {
		  diff_mset_p->insert(diff_dy);
		}
#else
		diff_mset_p->insert(diff_dy);
#endif
		diff_set_dx_dy->insert(diff_dy);
		find_iter = diff_set_dx_dy->lower_bound(diff_dy);
	 } 
	 assert((find_iter->dx == dx));

	 while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) {
		assert((find_iter->dx == dx));
		diff_dy = *find_iter;

		dx = diff_dy.dx;
		dy = diff_dy.dy;
		pn = diff_dy.p;
#if 1									  // adjust to key
		pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the fixed round key
#endif
		double p = 1.0;
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  p *= diff[i].p;
		}
		p = p * pn * B[nrounds - 1 - (n + 1)]; 

		// store the beginnig
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator begin_iter = diff_set_dx_dy->begin();
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  xtea_add_threshold_search(n+1, nrounds, npairs, round_key, round_delta, A, AA, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		}
		if(begin_iter != diff_set_dx_dy->begin()) { // if the root was updated, start from beginning
		  diff_dy.dx = dx;  
		  diff_dy.dy = 0;
		  diff_dy.p = 0.0;
		  find_iter = diff_set_dx_dy->lower_bound(diff_dy);
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  assert((find_iter->dx == dx));
		} else {
		  find_iter++;
		}
	 }
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = 0;
	 uint32_t dy = 0;

	 if(nrounds == 2) { // Last round (n = 1) AND only two rounds - freely choose dx
		dx = diff_mset_p->begin()->dx;
		dy = diff_mset_p->begin()->dy;
		pn = diff_mset_p->begin()->p;
	 } else {

		dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
		dy = 0;

		differential_t diff_max_dy;
		diff_max_dy.dx = dx;  
		diff_max_dy.dy = 0;
		diff_max_dy.p = 0.0;

		// check if a diff with the same dx is already in the set
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
		if(!b_found) {				  // if not found, add new

		  pn = first_nz_adp_xtea_f(A, AA, round_key[n], round_delta[n], dx, &dy, lsh_const, rsh_const);
#if 0									  // adjust to key
		  pn = adp_xtea_f_approx(npairs, dx, dy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the fixed round key
#endif
		  assert(pn != 0.0); // vpv
		  
		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  // Add the new diff to Dp only if it has better prob. than the min.
#if 1
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }
#else
		  diff_mset_p->insert(diff_max_dy);
#endif

		  diff_set_dx_dy->insert(diff_max_dy);
		  find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		} 
		assert((find_iter->dx == dx));

		diff_max_dy = *find_iter;
		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available
#if 1
		  double find_iter_p = adp_xtea_f_approx(npairs, find_iter->dx, find_iter->dy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the fixed round key
#else
		  double find_iter_p = find_iter->p;
#endif
		  if(find_iter_p > diff_max_dy.p) {
			 diff_max_dy = *find_iter;
		  }
		  find_iter++;
		}
		dx = diff_max_dy.dx;
		dy = diff_max_dy.dy;
		pn = diff_max_dy.p;
	 }

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

	 if((p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
#if 1									  // DEBUG
		if (p > *Bn) {
		  printf("[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		}
#endif
		diff[n].dx = dx;
		diff[n].dy = dy;
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		for(int i = 0; i < nrounds; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		}
	 }
  }
}

/**
 * Search for ADD differential trails in block cipher XTEA: wrapper
 * function for \ref tea_add_threshold_search.
 *
 * \param key cryptographic key of XTEA.
 * \param round_key all round keys for the full XTEA.
 * \param round_delta all round constants for the full XTEA. 
 *
 * \b Algorithm \b Outline:
 * 
 * The procedure operates as follows:
 * 
 * -# Compute a pDDT for F (\ref xtea_f_add_pddt).
 * -# Adjust the probabilities of the pDDT to the round key and
 *    constant (\ref adp_xtea_f_approx).
 * -# Execute the search for differential trails for \f$n\f$ rounds (n
 *    = \ref NROUNDS) through a successive application of \ref xtea_add_threshold_search :
 *    - Compute the best found probability on 1 round: \f$B[0]\f$.
 *    - Using \f$B[0]\f$ compute the best found probability on 2 rounds: \f$B[1]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[i-1]\f$ compute the best found probability on \f$(i+1)\f$ rounds: \f$B[i]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[n-2]\f$ compute the best found probability on \f$n\f$ rounds: \f$B[n-1]\f$.
 * -# Print the best found trail on \f$n\f$ rounds on standrad output and terminate.
 *
 * \see xtea_add_threshold_search, tea_add_trail_search
 *
 */
void xtea_add_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64])
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = XTEA_ADD_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;

  differential_t diff[NROUNDS];	  // arrey of differences
  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				  // arey of bounds

  // init matrices

  // init A
  gsl_matrix* A[2][2][2];
  adp_xor_alloc_matrices(A);
  adp_xor_sf(A);
  adp_xor_normalize_matrices(A);

  // init AA (A for adp_xor with one fixed input)
  gsl_matrix* AA[2][2][2];
  adp_xor_fixed_input_alloc_matrices(AA);
  adp_xor_fixed_input_sf(AA);
  adp_xor_fixed_input_normalize_matrices(AA);

  // init C
  gsl_vector* C = gsl_vector_calloc(ADP_XOR_MSIZE);
  gsl_vector_set(C, ADP_XOR_ISTATE, 1.0);

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  // init the trail
  for(int i = 0; i < NROUNDS; i++) {
	 trail[i].dx = 0;
	 trail[i].dy = 0;
	 trail[i].p = 0.0;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  xtea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, A, AA, C, key[0], round_delta[0], &diff_set_dx_dy);

  xtea_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);

  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  // initial bound
  //  double Bn = 0.0;
  double Bn_init = 0.0;

  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 double Bn = Bn_init;		  // initial bound
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 xtea_add_threshold_search(r, nrounds, npairs, round_key, round_delta, A, AA, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy);
	 assert(B[nrounds - 1] == Bn);
	 assert(B[nrounds - 1] != 0.0);

#if 1									  // DEBUG
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // INFO
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X (2^%f)\n", i, trail[i].dy, trail[i].dx, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif

#if 1
	 // check correctness
#if 1 								  // CHECK
	 printf("\n");
	 for(uint32_t i = 0; i < nrounds; i++) {

		uint32_t dx = trail[i].dx;
		uint32_t dy = trail[i].dy;

#if 0									  // exact computation
		double p = adp_xtea_f(WORD_SIZE, dx, dy, key, delta, lsh_const, rsh_const);
#else	 // approximation
		double p = adp_xtea_f_approx(npairs, dx, dy, round_key[i], round_delta[i], lsh_const, rsh_const);
#endif

		printf("[%s:%d] %8X <- %8X ", __FILE__, __LINE__, dy, dx);
		printf("%f %f (2^%f) (2^%f) | #CP 2^%f\n", p, trail[i].p, log2(p), log2(trail[i].p), log2(npairs));
#if 0//DEBUG									  // DEBUG
		if(trail[i].p) {
		  assert(p);
		}
#endif
		//		assert(p == trail[i].p);

	 }
	 if(nrounds >=3) {
		for(int i = (nrounds - 1); i >= 2; i--) {
#if 0									  // DEBUG
		  printf("[%s:%d] i = %2d: %8X %8X\n", __FILE__, __LINE__, i, trail[i].dx, ADD(trail[i - 2].dx, trail[i - 1].dy));
#endif
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif

	 // compute an initial bound for the next round by extending the charecteiristic greedily
	 bool b_init_bound = false;
#if 1
	 int next_round = nrounds;
	 if(b_init_bound) {
		uint32_t dx = ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		uint32_t dy = 0;

#if 0									  // maximum dy
		double p_next = max_dy_adp_xtea_f(WORD_SIZE, dx, &dy, key, delta, lsh_const, rsh_const);
#else	 // arbitrary dy
		double p_next = first_nz_adp_xtea_f(A, AA, round_key[next_round], round_delta[next_round], dx, &dy, lsh_const, rsh_const);
#if 0
		if((p_next == 0.0) && (next_round > 2)) {
		  p_next = max_dy_adp_xtea_f(WORD_SIZE, dx, &dy, key, delta, lsh_const, rsh_const);
		}
#endif
#if 1
		if((p_next == 0.0) && (next_round > 2)) {
		  while(!p_next) {
			 //			 dy = random32() & MASK;
			 uint32_t hw = random() % WORD_SIZE;
			 dy = gen_sparse(hw, WORD_SIZE);
			 uint32_t ninputs = (1U << 15);
			 p_next = adp_xtea_f_approx(ninputs, dx, dy, round_key[next_round], round_delta[next_round], lsh_const, rsh_const);
			 printf("\r[%s:%d] %2d: %8X -> %8X %f 2^%f", __FILE__, __LINE__, hw, dx, dy, p_next, log2(p_next));
			 fflush(stdout);
		  }
		}
#endif
#endif

		printf("[%s:%d] Extend trail to round %d: %8X -> %8X %f (2^%f)\n", 
				 __FILE__, __LINE__, next_round, dx, dy, p_next, log2(p_next));
		Bn_init = B[next_round - 1] * p_next;
		if(next_round > 1) {		  // the initial Bn is 0.0
		  assert(Bn_init != 0.0);
		}

		//		Bn_init = 0.0;
		if(diff_set_dx_dy.size() < XTEA_ADD_MAX_PDDT_SIZE) {
		  differential_t tmp_diff;
		  tmp_diff.dx = dx;
		  tmp_diff.dy = dy;
		  tmp_diff.p = p_next;

		  assert(diff_set_dx_dy.size() <= XTEA_ADD_MAX_PDDT_SIZE);
		  diff_set_dx_dy.insert(tmp_diff);
		  diff_mset_p.insert(tmp_diff);
		}
		trail[next_round].dx = dx;
		trail[next_round].dy = dy;
		trail[next_round].p = p_next;
		bool b_test = ((dx != 0) && (dy != 0) && (p_next != 0.0));
		if(!b_test) {
		  Bn_init = 0.0;
		}
	 } else {
		Bn_init = 0.0;
		trail[next_round].dx = 0;
		trail[next_round].dy = 0;
		trail[next_round].p = 0;
	 }
#endif

#endif  // #if 0
  }	  // for(nrounds...)

  // check probabilities of differentials for one round
  xtea_add_verify_trail(num_rounds, npairs, round_key, round_delta, trail);
  // check probabilities of differentials for multiple rounds
  xtea_add_verify_differential(num_rounds, npairs, lsh_const, rsh_const, key, trail);

  gsl_vector_free(C);
  adp_xor_free_matrices(A);
  adp_xor_fixed_input_free_matrices(AA);
}
