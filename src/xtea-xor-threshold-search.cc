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
 * \file  xtea-xor-threshold-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Automatic search for XOR differential trails in block cipher XTEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ADD_H
#include "xdp-add.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif
#ifndef XDP_XTEA_F_FK_H
#include "xdp-xtea-f-fk.hh"
#endif
#ifndef XTEA_F_ADD_PDDT_H
#include "xtea-f-xor-pddt.hh"
#endif

#define XTEA_P_ADJUST_APPROX 1

/** 
 * Compute an initial estimate of the probability of a differential
 * trail on \f$(n+1)\f$ rounds, by greedily extending the best found
 * trail for \f$n\f$ rounds.
 *
 * \param next_round index of round \f$(n+1)\f$ to which a trail on
 *                   \f$n\f$ rounds will be extended.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param A transition probability matrices for
 *        \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add_sf).
 * \param B array containing the best differential probabilities for i
 *        rounds: \f$0 \le i < n\f$.
 * \param trail best found differential trail for \p n rounds.
 * \param diff_set_dx_dy pDDT as a set of differentials \f$(dx,dy,p)\f$
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param round_key all round keys for the full XTEA.
 * \param round_delta all round constants for the full XTEA. 
 *
 * \see xtea_xor_trail_search
 *
 */ 
double xtea_xor_init_estimate(uint32_t next_round, uint32_t lsh_const, uint32_t rsh_const, uint32_t npairs,
										gsl_matrix* A[2][2][2], double B[NROUNDS], differential_t trail[NROUNDS], 
										std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										uint32_t round_key[64], uint32_t round_delta[64])
{
  double Bn_init = 0.0;
  uint32_t dxx = trail[next_round - 1].dx;
  uint32_t dx = trail[next_round - 1].dy;
  uint32_t dy = 0;
  double p_f = nz_xdp_xtea_f(A, dx, &dy, lsh_const, rsh_const);
  uint32_t dyy = 0;			  // to be computed
  //  double p_add2 = max_xdp_add(A, dxx, dy, &dyy);
  double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
  double p_next = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX									  // !!!
  p_next = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[next_round], round_delta[next_round], lsh_const, rsh_const);
#endif  // #if XTEA_P_ADJUST_APPROX
  Bn_init = B[next_round - 1] * p_next;

  if(diff_set_dx_dy->size() < XTEA_XOR_MAX_PDDT_SIZE) {
	 differential_t tmp_diff;
	 tmp_diff.dx = dx;
	 tmp_diff.dy = dy;		  // !
	 tmp_diff.p = p_f;		  // !

	 if(tmp_diff.p >= XTEA_XOR_P_THRES) {
		uint32_t old_size = diff_set_dx_dy->size();
		diff_set_dx_dy->insert(tmp_diff);
		uint32_t new_size = diff_set_dx_dy->size();
		if(old_size != new_size) {
		  diff_mset_p->insert(tmp_diff);
		}
	 }
  }
  trail[next_round].dx = dx;
  trail[next_round].dy = dyy; // !
  trail[next_round].p = p_next; // !
  bool b_test = (((dxx != 0)|| (dx != 0) || (dyy != 0)) && (p_next != 0.0));
  if(!b_test) {
	 Bn_init = 0.0;
  }
#if 1									  // DEBUG
  printf("[%s:%d] Extend trail to round %d: %8X -> %8X %f (2^%f) | Bn_init = 2^%f\n", 
			__FILE__, __LINE__, next_round, dx, dy, p_next, log2(p_next), log2(Bn_init));
#endif
  return Bn_init;
}

/**
 * 
 * Automatic search for XOR differential trails in block cipher TEA.
 * using pDDT.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_key all round keys for the full XTEA.
 * \param round_delta all round constants for the full XTEA. 
 * \param A transition probability matrices for
 *        \f$\mathrm{xdp}^{+}\f$ (\ref xdp_add_sf).
 * \param B array containing the best differential probabilities for i
 *        rounds: \f$0 \le i < n\f$.
 * \param Bn the best found probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best found differential trail for \p nrounds.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param diff_mset_p pDDT as a set of differentials \f$(dx,dy,p)\f$
 *        ordered by probability p.
 * \param diff_set_dx_dy pDDT as a set of differentials \f$(dx,dy,p)\f$
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param dxx_init initial left input difference to XTEA
 * \param dxx_init_in the initial left input difference to XTEA
 *        corresponding to the best found trail (initialized to \p
 *        dxx_init and updated dynamically).
 * 
 * \attention The pDDT contains differentials and their probabilities
 *            for the XTEA F-function \f$F\f$ (\ref xtea_f) as opposed
 *            to the function \f$F'\f$ (\ref xtea_f2) that also
 *            includes the second ADD operation. In other words, the
 *            pDDT does \em not take into account the differential
 *            probabilities arising from the second ADD operation. The
 *            latter are computed during the search.
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
 * \b More \b Details
 *  
 * The differential probability (DP) for one round of XTEA is computed
 * as the product of the DP of \f$F\f$ (\ref xtea_f) and the DP of the
 * modular addition in F' (\ref xtea_f2). The functions \f$F\f$ and
 * \f$F'\f$ are defined as:
 * \f$F(x) = y = x + ((x \ll 4) \oplus (x \gg 5))\f$, 
 * \f$ F'(xx, x) = yy = xx + (y \oplus (\delta + \mathrm{key}))\f$.
 * Thus the DP of one round of XTEA is essentiallly the DP of \f$F'\f$
 * and is approximated as:
 *
 * \f$\mathrm{xdp}^{F'}(dxx, dx \rightarrow dyy) = 
 * \mathrm{xdp}^{F}(dx \rightarrow dy) \cdot \mathrm{xdp}^{+}(dy, dxx \rightarrow dyy)\f$.
 * 
 * \attention The pDDT contais entries of the form \f$(dx,~ dy,~
 *            \mathrm{xdp}^{F}(dx \rightarrow dy))\f$. However, every
 *            entry in the arrays of differentials \p trail and \p
 *            diff_in contains elements of the form: \f$(dx,~ dyy,~
 *            \mathrm{xdp}^{F'}(dxx, dx \rightarrow dyy))\f$. Although
 *            \p trail and \p dif_in do not contain the difference
 *            \f$dxx\f$, the latter can be easily computed
 *            noting that \f$dxx = dx_{-1}\f$, where \f$dx_{-1}\f$ is
 *            the input difference to \f$F\f$ from the previous round.
 *
 * For more details on the search algorithm see \ref
 * tea_add_threshold_search .
 * 
 *  \see xtea_xor_trail_search
 *
 */
void xtea_xor_threshold_search(const int n, const int nrounds, const uint32_t npairs, 
										 const uint32_t round_key[64], const uint32_t round_delta[64],
										 gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
										 const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										 uint32_t lsh_const, uint32_t rsh_const,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										 uint32_t dxx_init, uint32_t* dxx_init_in)
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
		double p_f = mset_iter->p;
		uint32_t dxx = dy;		  // the second input difference to the first round is set to dy
		uint32_t dyy = 0;			  // to be computed
		//		double p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		// the final prob. is the product of the probabilities of the F-function and the second add operation
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

		if((pn >= *Bn) && (pn != 0.0)) { // discard zero probability
		  dxx_init = dxx;
		  trail[n].dx = dx;
		  trail[n].dy = dyy;		  // !
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		double p_f = mset_iter->p;
		uint32_t dxx = dy;		  // the second input difference to the first round is set to dy
		uint32_t dyy = 0;			  // to be computed
		//		double p_add2 = max_xdp_add(A, dxx, dy, &dyy);		
		double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);		
		pn = p_add2 * p_f;		  // product of the probabilities of the F-function and the second add operation
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);

		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) { // discard zero probability
		  dxx_init = dxx;
		  diff[n].dx = dx;
		  diff[n].dy = dyy;		  // !
		  diff[n].p = pn;
		  xtea_xor_threshold_search(n+1, nrounds, npairs, round_key, round_delta, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, dxx_init, dxx_init_in);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }		 // while()
  }

  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round
	 assert(diff_set_dx_dy->size() == diff_mset_p->size());

	 uint32_t dx = diff[n - 1].dy; // !
	 uint32_t dy = 0;

	 differential_t diff_dy;
	 diff_dy.dx = dx;  
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
	 if(!b_found) {				  // if not found, add new
		double pn = nz_xdp_xtea_f(A, dx, &dy, lsh_const, rsh_const); // max
		diff_dy.dx = dx;  
		diff_dy.dy = dy;
		diff_dy.p = pn;

		if(diff_dy.p >= XTEA_XOR_P_THRES) {
		  uint32_t old_size = diff_set_dx_dy->size();
		  diff_set_dx_dy->insert(diff_dy);
		  uint32_t new_size = diff_set_dx_dy->size();
		  if(old_size != new_size) {
			 diff_mset_p->insert(diff_dy);
		  }
		}
	 } else {						  // found
		assert((find_iter->dx == dx));
		diff_dy = *find_iter;
	 } 

	 dx = diff_dy.dx;
	 dy = diff_dy.dy;
	 double p_f = diff_dy.p;
	 uint32_t dxx = diff[n - 1].dx;
	 uint32_t dyy = 0;			  // to be computed
	 //		double p_add2 = max_xdp_add(A, dxx, dy, &dyy);		
	 double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);		
	 pn = p_add2 * p_f;		  // product of the probabilities of the F-function and the second add operation
#if XTEA_P_ADJUST_APPROX
	 pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

	 double p = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p *= diff[i].p;
	 }
	 p = p * pn * B[nrounds - 1 - (n + 1)]; 

	 // store the beginnig
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator begin_iter = diff_set_dx_dy->begin();
	 if((p >= *Bn) && (p != 0.0)) {
		diff[n].dx = dx;
		diff[n].dy = dyy;	  // !
		diff[n].p = pn;
		xtea_xor_threshold_search(n+1, nrounds, npairs, round_key, round_delta, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, dxx_init, dxx_init_in);
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

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = 0;
	 uint32_t dy = 0;	
	 uint32_t dxx = 0;
	 uint32_t dyy = 0;	
	 double p_f = 0.0;
	 double p_add2 = 0.0;

	 if(nrounds == 2) { // Last round (n = 1) AND only two rounds - freely choose dx
		dx = diff_mset_p->begin()->dx;
		dy = diff_mset_p->begin()->dy;
		p_f = diff_mset_p->begin()->p;
		dxx = diff[n - 1].dx;
		dyy = 0;			  // to be computed
		//		p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX
	 } else {

		dx = diff[n - 1].dy;
		dy = 0;

		differential_t diff_max_dy;
		diff_max_dy.dx = dx;  
		diff_max_dy.dy = 0;
		diff_max_dy.p = 0.0;

		// check if a diff with the same dx is already in the set
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
		if(!b_found) {				  // if not found, add new

		  pn = nz_xdp_xtea_f(A, dx, &dy, lsh_const, rsh_const);

		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  // Add the new diff to Dp only if it has better prob. than the min.
		  if(pn >= XTEA_XOR_P_THRES) {
			 bool b_found = (diff_set_dx_dy->find(diff_max_dy) != diff_set_dx_dy->end());
			 if(!b_found) {
				uint32_t old_size = diff_set_dx_dy->size();
				diff_set_dx_dy->insert(diff_max_dy);
				uint32_t new_size = diff_set_dx_dy->size();
				if(old_size != new_size) {
				  diff_mset_p->insert(diff_max_dy);
				}
			 }
		  }

		} else {
		  assert((find_iter->dx == dx));

		  diff_max_dy = *find_iter;
		  while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available

			 if(find_iter->p > diff_max_dy.p) {
				diff_max_dy = *find_iter;
			 }
			 find_iter++;
		  }
		}

		dx = diff_max_dy.dx;
		dy = diff_max_dy.dy;
		p_f = diff_max_dy.p;
		dxx = diff[n - 1].dx;
		dyy = 0;			  // to be computed
		//	 p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

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
		diff[n].dy = dyy;			  // !
		diff[n].p = pn;
		*Bn = p;
		B[n] = p;
		*dxx_init_in = dxx_init;
		for(int i = 0; i < nrounds; i++) {
		  trail[i].dx = diff[i].dx;
		  trail[i].dy = diff[i].dy;
		  trail[i].p = diff[i].p;
		  //		  printf("[%s:%d] %d | %8X %8X 2^%f\n", __FILE__, __LINE__, i, trail[i].dx, trail[i].dy, log2(trail[i].p));
		}
	 }
  }
}

/**
 * Search for XOR differential trails in block cipher XTEA: wrapper
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
 * -# Compute a pDDT for F (\ref xtea_f_xor_pddt).
 * -# Execute the search for differential trails for \f$n\f$ rounds (n
 *    = \ref NROUNDS) through a successive application of \ref xtea_xor_threshold_search :
 *    - Compute the best found probability on 1 round: \f$B[0]\f$.
 *    - Using \f$B[0]\f$ compute the best found probability on 2 rounds: \f$B[1]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[i-1]\f$ compute the best found probability on \f$(i+1)\f$ rounds: \f$B[i]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[n-2]\f$ compute the best found probability on \f$n\f$ rounds: \f$B[n-1]\f$.
 * -# Print the best found trail on \f$n\f$ rounds on standrad output and terminate.
 *
 * \see xtea_xor_threshold_search
 *
 */
uint32_t xtea_xor_trail_search(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64],
										 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										 std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
										 double B[NROUNDS], differential_t trail[NROUNDS])
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = XTEA_XOR_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;

  differential_t diff[NROUNDS];	  // arrey of differences
  //  differential_t trail[NROUNDS];  // a differential trail
  //  double B[NROUNDS];				  // arey of bounds

  // init matrices

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

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

  //  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  //  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  xtea_f_xor_pddt(word_size, p_thres, lsh_const, rsh_const, diff_set_dx_dy);
#if 0
  uint32_t key_0 = round_key[0];
  uint32_t delta_0 = round_delta[0];
  xtea_f_xor_pddt_adjust_to_key(num_rounds, npairs, lsh_const, rsh_const, key_0, delta_0, p_thres, diff_set_dx_dy);
#endif
  xtea_xor_pddt_dxy_to_dp(diff_mset_p, *diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dp , p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_mset(diff_mset_p);
#endif

  printf("Initial set sizes: Dp %d, Dxy %d\n", (uint32_t)diff_mset_p->size(), (uint32_t)diff_set_dx_dy->size());
  assert(diff_set_dx_dy->size() == diff_mset_p->size());
  assert(diff_set_dx_dy->size() != 0);

  // initial bound
  double Bn_init = 0.0;
  uint32_t dxx_init = 0;
  uint32_t dxx_init_in = 0;

  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  //  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {
  uint32_t nrounds = 0;
  do {
	 nrounds++;

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f, Dp %d Dxy %d\n", __FILE__, __LINE__, nrounds, log2(Bn_init), (uint32_t)diff_mset_p->size(), (uint32_t)diff_set_dx_dy->size());

	 double Bn = Bn_init;		  // initial bound
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round
	 dxx_init = 0;

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 xtea_xor_threshold_search(r, nrounds, npairs, round_key, round_delta, A, B, &Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, dxx_init, &dxx_init_in);
	 assert(B[nrounds - 1] == Bn);
	 dxx_init = dxx_init_in;

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
	 printf("pDDT sizes: Dp %d, Dxy %d\n", (uint32_t)diff_mset_p->size(), (uint32_t)diff_set_dx_dy->size());
	 assert(diff_mset_p->size() == diff_set_dx_dy->size());
#endif
#if 1									  // INFO
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X (2^%f)\n", i, trail[i].dy, trail[i].dx, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif
	 // compute initial estimate for next round
	 uint32_t next_round = nrounds;
	 Bn_init = xtea_xor_init_estimate(next_round, lsh_const, rsh_const, npairs, A, B, trail, diff_set_dx_dy, diff_mset_p, round_key, round_delta);

	 //  } while((nrounds < NROUNDS) && ((B[nrounds - 1] > p_rand) || (nrounds == 0)));
  } while(nrounds < NROUNDS);
  //  } // for(nrounds...)

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

  num_rounds = nrounds;

  // check probabilities of differentials for one round
  xtea_xor_verify_trail(num_rounds, npairs, round_key, round_delta, dxx_init, trail);

  xtea_xor_verify_differential(num_rounds, npairs, lsh_const, rsh_const, key, dxx_init, trail);

  xdp_add_free_matrices(A);
  return num_rounds;
}


/**
 * Full threshold search.
 */
void xtea_xor_threshold_search_full(const int n, const int nrounds, const uint32_t npairs, 
												const uint32_t round_key[64], const uint32_t round_delta[64],
												gsl_matrix* A[2][2][2], double B[NROUNDS], double* Bn,
												const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
												uint32_t lsh_const, uint32_t rsh_const,
												std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p,
												std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
												uint32_t dxx_init, uint32_t* dxx_init_in)
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
	 //	 assert(*Bn == 0.0);
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		double p_f = mset_iter->p;
		uint32_t dxx = dy;		  // the second input difference to the first round is set to dy
		uint32_t dyy = 0;			  // to be computed
		//		double p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		// the final prob. is the product of the probabilities of the F-function and the second add operation
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

#if 1									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, (uint32_t)diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((pn >= *Bn) && (pn != 0.0)) { // discard zero probability
		  dxx_init = dxx;
		  trail[n].dx = dx;
		  trail[n].dy = dyy;		  // !
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} else {
		  b_end = true;
		}
		mset_iter++;
		cnt++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		double p_f = mset_iter->p;
		uint32_t dxx = dy;		  // the second input difference to the first round is set to dy
		uint32_t dyy = 0;			  // to be computed
		double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);		
		pn = p_add2 * p_f;		  // product of the probabilities of the F-function and the second add operation
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);

		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) { // discard zero probability
		  dxx_init = dxx;
		  diff[n].dx = dx;
		  diff[n].dy = dyy;		  // !
		  diff[n].p = pn;
		  xtea_xor_threshold_search_full(n+1, nrounds, npairs, round_key, round_delta, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, dxx_init, dxx_init_in);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }		 // while()
  }

  if((n >= 1) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = diff[n - 1].dy; // !
	 uint32_t dy = 0;

	 differential_t diff_dy;
	 diff_dy.dx = dx;  
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 // {---
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy->end()) && (hway_iter->dx == dx);

	 std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy;
	 uint32_t dx_prev = diff[n - 1].dx;
	 assert(diff_set_dx_dy->size() != 0);
	 uint32_t cnt_new = xtea_f_da_db_xor_pddt(WORD_SIZE, p_min, lsh_const, rsh_const, dx_prev, diff_dy.dx, diff_set_dx_dy, diff_mset_p,  &croads_diff_set_dx_dy);
	 if(cnt_new != 0) {
#if 1									  // DEBUG
		printf("\r[%s:%d] [%2d / %2d]: Added %d new country roads: p_min = %f (2^%f). New sizes: Dp %d Dxy %d.", 
				 __FILE__, __LINE__, n, NROUNDS, cnt_new, p_min, log2(p_min), (uint32_t)diff_mset_p->size(), (uint32_t)diff_set_dx_dy->size());
		fflush(stdout);
#endif
	 }

	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_iter = croads_diff_set_dx_dy.lower_bound(diff_dy);
	 bool b_found_in_croads = (croad_iter != croads_diff_set_dx_dy.end()) && (croad_iter->dx == dx);

	 std::multiset<differential_t, struct_comp_diff_p> found_mset_p;

	 if(b_found_in_hways) {
		//		while((hway_iter->dx == dx) && (hway_iter->p >= p_min)) {
		while(hway_iter->dx == dx) {
		  found_mset_p.insert(*hway_iter);
		  hway_iter++;
		}
	 }

	 if(b_found_in_croads) {
		assert(croad_iter->p >= p_min);
		while((croad_iter->dx == dx) && (croad_iter->p >= p_min)) {
		//		while(croad_iter->dx == dx) {

		  uint32_t dy = croad_iter->dy;
		  uint32_t dx_prev = diff[n - 1].dx;
		  bool b_is_hway = xtea_is_dx_in_set_dx_dy(dy, dx_prev, *diff_set_dx_dy);
#if 0
		  b_is_hway = true;		  // !!!!
#endif
		  assert(b_is_hway);
		  if(b_is_hway) {
			 found_mset_p.insert(*croad_iter);
		  }
		  croad_iter++;
		}
	 }

	 std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = found_mset_p.begin();
	 // ---}

	 //	 while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) {
	 if(find_iter->dx == dx) {
		while((find_iter->dx == dx) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  // Add the new diff to Dp only if it has better prob. than the min.
		  if(diff_dy.p >= XTEA_XOR_P_THRES) {
			 uint32_t old_size = diff_set_dx_dy->size();
			 diff_set_dx_dy->insert(diff_dy);
			 uint32_t new_size = diff_set_dx_dy->size();
			 if(old_size != new_size) {
				diff_mset_p->insert(diff_dy);
			 }
		  }

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  double p_f = diff_dy.p;
		  uint32_t dxx = diff[n - 1].dx;
		  uint32_t dyy = 0;			  // to be computed
		  //		  double p_add2 = max_xdp_add(A, dxx, dy, &dyy);		
		  double p_add2 = max_xdp_add_lm(dxx, dy, &dyy);		
		  pn = p_add2 * p_f;		  // product of the probabilities of the F-function and the second add operation
#if XTEA_P_ADJUST_APPROX
		  pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  // store the beginnig
		  std::set<differential_t, struct_comp_diff_dx_dy>::iterator begin_iter = diff_set_dx_dy->begin();
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dyy;	  // !
			 diff[n].p = pn;
			 xtea_xor_threshold_search_full(n+1, nrounds, npairs, round_key, round_delta, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, dxx_init, dxx_init_in);
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
  }

  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = 0;
	 uint32_t dy = 0;	
	 uint32_t dxx = 0;
	 uint32_t dyy = 0;	
	 double p_f = 0.0;
	 double p_add2 = 0.0;

	 if(nrounds == 2) { // Last round (n = 1) AND only two rounds - freely choose dx
		dx = diff_mset_p->begin()->dx;
		dy = diff_mset_p->begin()->dy;
		p_f = diff_mset_p->begin()->p;
		dxx = diff[n - 1].dx;
		dyy = 0;			  // to be computed
		//		p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX
	 } else {

		dx = diff[n - 1].dy;
		dy = 0;

		differential_t diff_max_dy;
		diff_max_dy.dx = dx;  
		diff_max_dy.dy = 0;
		diff_max_dy.p = 0.0;

		// check if a diff with the same dx is already in the set
		std::set<differential_t, struct_comp_diff_dx_dy>::iterator find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		bool b_found = (find_iter != diff_set_dx_dy->end()) && (find_iter->dx == dx);
		if(!b_found) {				  // if not found, add new

		  pn = nz_xdp_xtea_f(A, dx, &dy, lsh_const, rsh_const);

		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  // Add the new diff to Dp only if it has better prob. than the min.
		  if(pn >= XTEA_XOR_P_THRES) {
			 bool b_found = (diff_set_dx_dy->find(diff_max_dy) != diff_set_dx_dy->end());
			 if(!b_found) {
				uint32_t old_size = diff_set_dx_dy->size();
				diff_set_dx_dy->insert(diff_max_dy);
				uint32_t new_size = diff_set_dx_dy->size();
				if(old_size != new_size) {
				  diff_mset_p->insert(diff_max_dy);
				}
			 }
		  }

		  // Add the new diff to Dp only if it has better prob. than the min.
#if 0
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }

		  diff_set_dx_dy->insert(diff_max_dy);
		  find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
#endif	
		} else {
		  assert((find_iter->dx == dx));

		  diff_max_dy = *find_iter;
		  while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available

			 if(find_iter->p > diff_max_dy.p) {
				diff_max_dy = *find_iter;
			 }
			 find_iter++;
		  }
		}

		dx = diff_max_dy.dx;
		dy = diff_max_dy.dy;
		p_f = diff_max_dy.p;
		dxx = diff[n - 1].dx;
		dyy = 0;			  // to be computed
		//	 p_add2 = max_xdp_add(A, dxx, dy, &dyy);
		p_add2 = max_xdp_add_lm(dxx, dy, &dyy);
		pn = p_add2 * p_f;
#if XTEA_P_ADJUST_APPROX
		pn = xdp_xtea_f2_fk_approx(npairs, dxx, dx, dyy, round_key[n], round_delta[n], lsh_const, rsh_const); // adjust the probability to the round key
#endif  // #if XTEA_P_ADJUST_APPROX

	 }

	 double p = 1.0;
	 for(int i = 0; i < n; i++) {
		p *= diff[i].p;
	 }
	 p *= pn;

    if((p >= *Bn) && (p != 1.0) && (p != 0.0)) { // skip the 0-diff trail (p = 1.0)
	 //	 if((p >= *Bn) && (p != 1.0) && (p != 0.0) && (dx != trail[n].dx) && (dyy != trail[n].dy)) { // skip the 0-diff trail (p = 1.0)
		bool b_same_diffs = false;
		if((n > 2) && (dx == trail[n].dx) && (dyy == trail[n].dy)) {
		  b_same_diffs = true;
		}
#if 1									  // DEBUG
		if(!b_same_diffs) {
		  if (p > *Bn) {
			 printf("[%s:%d] %d | Update best found Bn: 2^%f -> 2^%f\n", __FILE__, __LINE__, n, log2(*Bn), log2(p));
		  }
#endif
		  diff[n].dx = dx;
		  diff[n].dy = dyy;			  // !
		  diff[n].p = pn;
		  *Bn = p;
		  B[n] = p;
		  *dxx_init_in = dxx_init;
		  for(int i = 0; i < nrounds; i++) {
			 trail[i].dx = diff[i].dx;
			 trail[i].dy = diff[i].dy;
			 trail[i].p = diff[i].p;
			 //		  printf("[%s:%d] %d | %8X %8X 2^%f\n", __FILE__, __LINE__, i, trail[i].dx, trail[i].dy, log2(trail[i].p));
		  }
		}
	 }
  }
}

/**
 * Full threshold search using
 * \ref xtea_xor_threshold_search_full
 */
uint32_t xtea_xor_trail_search_full(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64],
												std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy, // Dxy
												std::multiset<differential_t, struct_comp_diff_p> diff_mset_p,	 // Dp
												double BB[NROUNDS], differential_t trail[NROUNDS])
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  //  double p_thres = XTEA_XOR_P_THRES;
  //  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;
  uint32_t ret_nrounds = 0;

  differential_t diff[NROUNDS];	  // arrey of differences
  //  differential_t trail[NROUNDS];  // a differential trail
  double B[NROUNDS];				  // arey of bounds

  // init matrices

  // init A
  gsl_matrix* A[2][2][2];
  xdp_add_alloc_matrices(A);
  xdp_add_sf(A);
  xdp_add_normalize_matrices(A);

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

#if 0																					 // precomputed
  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp
  xtea_f_xor_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
#if 0
  uint32_t key_0 = round_key[0];
  uint32_t delta_0 = round_delta[0];
  xtea_f_xor_pddt_adjust_to_key(num_rounds, npairs, lsh_const, rsh_const, key_0, delta_0, p_thres, &diff_set_dx_dy);
#endif
  xtea_xor_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dp , p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_mset(diff_mset_p);
#endif
#endif  // #if 0

  printf("Initial set sizes: Dp %d, Dxy %d\n", (uint32_t)diff_mset_p.size(), (uint32_t)diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  // initial bound
  double Bn_init = 0.0;
  uint32_t dxx_init = 0;
  uint32_t dxx_init_in = 0;

  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  //  for(uint32_t nrounds = 1; nrounds <= NROUNDS; nrounds++ ) {
  double scale_fact = 1.0;
  uint32_t nrounds = 0;
  do {
	 nrounds++;
	 double Bn = 1.0;//BB[nrounds - 1] * scale_fact; // !!!
	 if(nrounds == 0) {
		Bn = 0.0;
	 } else {
		Bn = BB[nrounds - 1] * scale_fact;
	 }

	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 //	 double Bn = Bn_init;		  // initial bound
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round
	 dxx_init = 0;

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 xtea_xor_threshold_search_full(r, nrounds, npairs, round_key, round_delta, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy, dxx_init, &dxx_init_in);
	 //	 assert(B[nrounds - 1] == Bn);
	 dxx_init = dxx_init_in;

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
	 printf("pDDT sizes: Dp %d, Dxy %d\n", (uint32_t)diff_mset_p.size(), (uint32_t)diff_set_dx_dy.size());
#endif
#if 1									  // INFO
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X (2^%f)\n", i, trail[i].dy, trail[i].dx, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif
	 // compute initial estimate for next round
	 uint32_t next_round = nrounds;
#if 0
	 Bn_init = xtea_xor_init_estimate(next_round, lsh_const, rsh_const, npairs, A, B, trail, &diff_set_dx_dy, round_key, round_delta);
#else
	 Bn_init = BB[next_round];
#endif
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		//		if((B[i-1] < B[i]) || (trail[i].p == 0.0)) {
		if((B[i-1] < B[i]) || (scale_fact < 0.00005)) {
		//		if((B[i-1] < B[i]) || (scale_fact < 0.25)) {
		  nrounds = 0;
		  //		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
			 B[j] = BB[j];
			 trail[j].dx = 0;
			 trail[j].dy = 0;
			 trail[j].p = 0;
		  }
		  printf("[%s:%d] Start again from round 1: trail[%d].p = 2^%f\n", __FILE__, __LINE__, i, log2(trail[i].p));
		} else {
		  if(trail[i].p == 0) {
			 nrounds -= 1;
#if 1									  // !!!
			 scale_fact *= 0.5;
#endif
			 for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
				B[j] = BB[j];
			 }
			 printf("[%s:%d] Start again from round %d: scale_fact = %f\n", __FILE__, __LINE__, i, scale_fact);
		  } else {
			 if(scale_fact < 1.0) {
				scale_fact = 1.0;
			 }
		  }
		}
	 }
	 //  } while((nrounds < NROUNDS) && ((B[nrounds - 1] > p_rand) || (nrounds == 0)));
  //  } // for(nrounds...)
  } while(nrounds < NROUNDS);

  ret_nrounds = nrounds;

  // check probabilities of differentials for one round
  xtea_xor_verify_trail(num_rounds, npairs, round_key, round_delta, dxx_init, trail);

  xtea_xor_verify_differential(num_rounds, npairs, lsh_const, rsh_const, key, dxx_init, trail);

  xdp_add_free_matrices(A);
  return ret_nrounds;
}
