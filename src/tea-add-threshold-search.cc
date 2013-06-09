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
 * \file  tea-add-threshold-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief Automatic search for ADD differential trails in block cipher TEA.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR3_H
#include "adp-xor3.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif
#ifndef EADP_TEA_F_H
#include "eadp-tea-f.hh"
#endif
#ifndef TEA_F_ADD_PDDT_H
#include "tea-f-add-pddt.hh"
#endif


/**
 * Count the number of differentials in a \p trail that have
 * probabilities below a given threshold.
 *
 * \param trail a differential trail for \p trail_len rounds.
 * \param trail_len length of the differential trail.
 * \param p_thres probability threshold.
 */
uint32_t tea_add_threshold_count_lp(differential_t trail[NROUNDS], uint32_t trail_len, double p_thres)
{
  assert(trail_len < NROUNDS);
  uint32_t cnt = 0;

  for(uint32_t i = 0; i < trail_len; i++) {
	 if(trail[i].p < p_thres) {
		cnt++;
	 }
  }

  return cnt;
}

/**
 * 
 * Automatic search for ADD differential trails in block cipher TEA.
 * using pDDT.
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param key cryptographic key of TEA.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param B array containing the best differential probabilities for i rounds: \f$0 \le i < n\f$.
 * \param Bn the best probability on \f$n\f$ rounds, updated dynamically.
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
 * \b Algorithm \b Outline:
 *  
 * The algorithm is based on Matsui search strategy described in
 * [Sect. 4, Matsui, <A
 * href="http://dblp.uni-trier.de/rec/bibtex/conf/eurocrypt/Matsui94">On
 * correlation between the order of S-boxes and the strength of
 * DES</A>, EUROCRYPT'94]. The main idea is to view the F-function of
 * TEA as an S-box for which a partial difference distribution table
 * (pDDT) is constructed (\ref tea_f_add_pddt). Then a recursive
 * search for differential trails over a given number of rounds \f$n
 * \ge 1\f$ is performed. From knowledge of the best probabilities
 * \f$B_{1}, B_{2}, \ldots, B_{n-1}\f$ for the first \f$(n-1)\f$
 * rounds and an initial estimate \f${\overline B_n}\f$ for the
 * probability for \f$n\f$ rounds the best probability \f$B_{n}\f$ for
 * \f$n\f$ rounds is derived. Note that for the estimate the following
 * must hold: \f${\overline B_n} \leq B_n\f$.
 *
 * In addition to Matsui's notation for the probability of the best
 * \f$n\f$-round trail \f$B_n\f$ and of its estimation \f${\overline
 * B_n}\f$ we introduce \f${\widehat B_n}\f$ to denote the probability
 * of \em the \em best \em found trail for \f$n\f$ rounds:
 * \f${\overline B_n} \leq {\widehat B_n} \leq B_n\f$. Given a pDDT
 * \f$D\f$ of maximum size \f$m\f$, an estimation for the best
 * \f$n\f$-round probability \f${\overline B_n}\f$ with its
 * corresponding \f$n\f$-round differential trail \f${\overline T}\f$
 * and the probabilities \f${{\widehat B_1}, {\widehat B_2}, \ldots,
 * {\widehat B_{n-1}}}\f$ of the best found trails for the first \f$(n
 * - 1)\f$ rounds, \ref tea_add_threshold_search outputs an
 * \f$n\f$-round trail \f${\widehat T}\f$ that has probability
 * \f${\widehat{B_n}} \ge {\overline B_n}\f$.
 * 
 * \ref tea_add_threshold_search operates by recursively extending a
 * trail for \f$i\f$ rounds to \f$(i+1)\f$ rounds, beginning with \f$i
 * = 1\f$ and terminating at \f$i = n\f$. This is done by exploring
 * multiple differential trails constructed from the entries of the
 * pDDT \f$D\f$ at every round. If, in the process, a differential
 * that is not already in \f$D\f$ is encountered it is added to
 * \f$D\f$, provided that the maximum size \f$m\f$ has not been
 * reached. The recursion at level \f$i\f$ continues to level
 * \f$(i+1)\f$ only if the probability of the constructed
 * \f$i\f$-round trail multiplied by the probability of the best found
 * trail for \f$(n - i)\f$ rounds is at least \f${\overline B_n}\f$
 * i.e. if, \f$p_1 p_2 \ldots p_i\, {\widehat B_{n - i}} \ge
 * {\overline B_n}\f$ holds. For \f$i = n\f$ the last equation is
 * equivalent to: \f$p_1 p_2 \ldots p_n = {\widehat B_{n}} \ge
 * {\overline B_n}\f$. If the latter holds, the initial estimate is
 * updated with the new: \f${\overline B_n} \gets {\widehat B_{n}}\f$
 * and the corresponding trail is also updated accordingly:
 * \f${\overline T_n} \gets {\widehat T_{n}}\f$. Upon termination the
 * best found trail \f${\widehat T_{n}}\f$ and its probability
 * \f${\widehat{B_n}}\f$ are returned as result.
 * 
 * \attention In the process of the search if an input differences
 * \f$\alpha\f$ is encountered for which a corresponding output
 * difference \f$\beta\f$ is not found in the pDDT (i.e. the
 * differential \f$(\alpha \rightarrow \beta_i)\f$ is not in the pDDT
 * for no \f$i\f$), then an arbitarary non-zero probability output
 * differnece \f$\beta\f$ is computed with the \ref nz_eadp_tea_f
 * procedure . See also \ref tea_add_threshold_search_full where a
 * more extensive search over the space of possible output differences
 * \f$\beta\f$ is performed in this case.
 * 
 * \b Termination
 *
 * The algorithm terminates when one of the following two events
 * happens first:
 *
 * -# The initial estimate \f${\overline B_n}\f$ can not be improved
 * further.
 * -# The maximum size \f$m\f$ of the pDDT \f$D\f$ is reached and all
 * differentials in \f$D\f$ in every round have been explored.
 *
 * \b Complexity 
 *
 * The complexity of \ref tea_add_threshold_search depends on the
 * following factors:
 *
 * -# The closeness of the best found probabilities \f${{\widehat
 * B_1}, {\widehat B_2}, \ldots, {\widehat B_{n-1}}}\f$ for the first
 * \f$(n - 1)\f$ rounds to the actual best probabilities.
 * -# The tightness of the initial estimate \f${\overline B_n}\f$.
 * -# The number of elements in \f$D\f$. The latter is determined by
 * the probability threshold used to compute \f$D\f$ and by the
 * maximum number of elements \f$m\f$ allowed.
 *
 * In the worst-case, in every round, except the last, \f$m\f$
 * iterations will be executed. Therefore the worst-case complexity is
 * \f$\mathcal{O}(m^{n-1})\f$, where \f$n\f$ is the number of
 * rounds. Although the algorithm is worst-case exponential in the
 * number of rounds, it is much more efficient in practice.
 *
 * \attention The algorithm does not guarantee to find the \em best
 * trail.
 *
 * \note The pDDT of TEA contains the expected differential
 * probabilities of F averaged over all keys and round constants. To
 * obtain better estimate of the probabilities of trails for a fixed
 * key and round constants, in the process of the search the
 * probability of each differential is additionally adjusted to the
 * value of the round key and constant by performing one-round
 * encryptions over \p npairs pairs of chosen plaintexts.
 *
 * \see tea_add_threshold_search_full
 */
void tea_add_threshold_search(const int n, const int nrounds, const uint32_t npairs, const uint32_t key[4],
										gsl_matrix* A[2][2][2][2], double B[NROUNDS], double* Bn,
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
	 diff[i].p = diff_in[i].p;
  }

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 assert(*Bn == 0.0);
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
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
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
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

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
		} else {
		  b_end = true;
		} 
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		} else {
		  mset_iter++;
		}
	 }	// while()
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
#if 0									  // this make the search inefficient for n >= 16
		max_eadp_tea_f(A, dx, &dy, &pn, lsh_const, rsh_const); // max_dy eadp_tea_f
#else
		double p_thres = 0.0;
		pn = nz_eadp_tea_f(A, p_thres, dx, &dy); // just get an arbitrary non-zero dy
#endif
		diff_dy.dx = dx;  
		diff_dy.dy = dy;
		diff_dy.p = pn;

		// Add the new diff to Dp only if it has better prob. than the min.
		double p_min = diff_mset_p->rbegin()->p;
		if(diff_dy.p >= p_min) {
		  diff_mset_p->insert(diff_dy);
		}

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
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key

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
		  tea_add_threshold_search(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy);
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
		//		b_found = false;
		if(!b_found) {				  // if not found, add new

		  max_eadp_tea_f(A, dx, &dy, &pn, lsh_const, rsh_const); // max_dy eadp_tea_f
		  pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed key

		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  // Add the new diff to Dp only if it has better prob. than the min.
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }

		  diff_set_dx_dy->insert(diff_max_dy);
		  find_iter = diff_set_dx_dy->lower_bound(diff_max_dy);
		} 
		assert((find_iter->dx == dx));

		diff_max_dy = *find_iter;
		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available
		  double find_iter_p = tea_add_diff_adjust_to_key(npairs, n, find_iter->dx, find_iter->dy, key); // adjust the probability to the fixed key
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
 * Full threshold search for ADD differential trails in block cipher TEA,
 * that uses initial bounds pre-computed with \ref tea_add_threshold_search .
 * 
 * \param n index of the current round: \f$0 \le n < \mathrm{nrounds}\f$.
 * \param nrounds total number of rounds (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param key cryptographic key of TEA.
 * \param A transition probability matrices for \f$\mathrm{adp}^{3\oplus}\f$ (\ref adp_xor3_sf).
 * \param B array of initial bounds pre-computed with \ref tea_add_threshold_search .
 * \param Bn the best probability on \f$n\f$ rounds, updated dynamically.
 * \param diff_in array of differentials.
 * \param trail best found differential trail for \p nrounds.
 * \param lsh_const LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const RSH constant (\ref TEA_RSH_CONST).
 * \param diff_mset_p set of differentials \f$(dx,dy,p)\f$ (\b Highways)
 *        ordered by probability p.
 * \param diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (\b Highways)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 * \param croads_diff_mset_p temporrary set of differentials \f$(dx,dy,p)\f$ (\b Countryroads)
 *        ordered by probability p.
 * \param croads_diff_set_dx_dy set of differentials \f$(dx,dy,p)\f$ (\b Countryroads)
 *        ordered by index \f$i = (dx~ 2^{n} + dy)\f$.
 *
 * \b Algorithm \b Outline:
 *  
 * The high-level logic of the algorithm is conceptually the same as
 * \ref tea_add_threshold_search . The main difference is in the way
 * it handles the case when an input difference \f$\alpha\f$ is
 * encountered for which a corresponding output difference \f$\beta\f$
 * is not found in the pre-computed pDDT. In this case a list of many
 * possible output differences is computed and is explored during the
 * search. More deatiled explanation follows.
 * 
 * Let \f$\alpha_r\f$ be an input difference to round \f$r\f$ such
 * that the differential \f$(\alpha_r \rightarrow \beta_i)\f$ is not
 * in the pDDT for no value of \f$i\f$. In this case the algorithm
 * uses \ref tea_f_da_add_pddt to compute all differences
 * \f$\beta_i\f$ that satisfy the following conditions:
 *
 * -# The differential \f$(\alpha_r \rightarrow \beta_i)\f$ is such
 * that its probability \f$p_r\f$ can still improve the probability of
 * the best found trail for the given number of rounds i.e. \f$p_r \ge
 * {{\overline B_n}}/{(p_1 p_2 \cdots p_{r-1} {\widehat B_{n-r}})}\f$.
 * -# The output difference \f$\beta_i\f$ is such that it guarantees
 * that the input difference for the next round \f$\alpha_{r+1} =
 * \alpha_{r-1} + \beta_{i}\f$ will have a matching entry in the
 * pre-computed pDDT. This condition guarantees that the resulting
 * output difference \f$\alpha_{r+1}\f$ for the next round will have a
 * matching output differences \f$\beta_{r+1}\f$ in the initial pDDT.
 *
 * All differentials \f$(\alpha_r, \beta_r, p_r)\f$ computed according
 * to the above rules are stored in a temporary pDDT. The
 * differentials in this pDDT are explored during the next stages
 * of the search togeter with the differentials from the initial
 * pDDT.
 *
 * \b The \b Highways \b and \b Countryroads \b Analogy 
 *
 * Denote the temporary pDDT constructed as explained above by \f$C\f$
 * and the initial pDDT that is pre-computed at the start of the
 * search by \f$ H \f$. Then the two tables \f$ H \f$ and \f$C\f$ can be thought
 * of as lists of \b highways and \b countryroads on a road map. The
 * differentials contained in \f$H\f$ have high probabilities w.r.t. to
 * the fixed probability threshold and correspond therefore to fast
 * roads such as \b highways. Analogously, the differentials in \f$C\f$
 * have low probabilities and can be seen as slow roads or \b
 * countryroads. To continue this analogy, the problem of finding a
 * high probability differential trail for \f$n\f$ rounds can be seen as a
 * problem of finding a fast route between points \f$1\f$ and \f$n\f$ on the
 * map. Clearly such a route must be composed of as many highways as
 * possible. Condition (2), mentioned above, essentially guarantees
 * that any country road that we may take in our search for a fast
 * route will bring us back on a highway. Note that it is possible
 * that the fastest route contains two or more country roads in
 * sequence. While such a case will be missed, it may be accounted for by
 * lowering the initial probability threshold.
 * 
 * \b Full \b Threshold \b Search \b Pseudo-Code
 * 
 * \image html threshold-search.png "Full Threshold Search Pseudo-Code" width=10cm
 *
 * \see tea_add_threshold_search
 */
void tea_add_threshold_search_full(const int n, const int nrounds, const uint32_t npairs, const uint32_t key[4],
											  gsl_matrix* A[2][2][2][2], double B[NROUNDS], double* Bn,
											  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
											  uint32_t lsh_const, uint32_t rsh_const,
											  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // highways
											  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
											  std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
											  std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy)
{
  double pn = 0.0;

  // make a local copy of the input diff trail
  differential_t diff[NROUNDS] = {{0, 0, 0, 0.0}};
  for(int i = 0; i < n; i++) {
	 diff[i].dx = diff_in[i].dx;
	 diff[i].dy = diff_in[i].dy;
	 diff[i].p = diff_in[i].p;
  }

#if 1
  uint32_t max_lp = n;//4;//3;//3;//n;//3;
  uint32_t cnt_lp = 0;
  uint32_t trail_len = n;
  double p_thres = TEA_ADD_P_THRES;
  cnt_lp = tea_add_threshold_count_lp(diff, trail_len, p_thres);
#endif
  //  printf("[%s:%d] cnt_lp %d / %d\n", __FILE__, __LINE__, cnt_lp, max_lp);

  if((n == 0) && (nrounds == 1)) {						  // Only one round
	 //	 assert(*Bn == 0.0);
	 bool b_end = false;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 uint32_t cnt = 0;
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;;
#if 1
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
#endif // #if 0 
#if 1									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
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
		pn = mset_iter->p;
#if 1
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
#endif // #if 0 
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy);
		} else {
		  b_end = true;
		}
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  cnt = 0;
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }
  }

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 bool b_end = false;
	 uint32_t cnt = 0;
	 std::multiset<differential_t, struct_comp_diff_p>::iterator mset_iter = diff_mset_p->begin();
	 while((mset_iter != diff_mset_p->end()) && (!b_end)) {
		uint32_t dx = mset_iter->dx;
		uint32_t dy = mset_iter->dy;
		pn = mset_iter->p;
#if 1
		pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
#endif // #if 0 
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
		std::multiset<differential_t, struct_comp_diff_p>::iterator begin_iter = diff_mset_p->begin();
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2d] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, cnt, diff_mset_p->size(), dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;
		  diff[n].dy = dy;
		  diff[n].p = pn;
		  tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy);
		} else {
		  b_end = true;
		} 
		if(begin_iter != diff_mset_p->begin()) { // if the root was updated, start from beginning
		  mset_iter = diff_mset_p->begin();
		  printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
		  cnt = 0;
		} else {
		  mset_iter++;
		  cnt++;
		}
	 }	// while()
  }

  //  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
  if((n >= 2) && (n != (nrounds - 1)) && (cnt_lp <= max_lp)) {
	 uint32_t dx = ADD(diff[n - 2].dx, diff[n - 1].dy);
	 uint32_t dy = 0;

	 differential_t diff_dy;
	 diff_dy.dx = dx;  
	 diff_dy.dy = 0;
	 diff_dy.p = 0.0;

	 // check if the differential is not already in the set
	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator hway_iter = diff_set_dx_dy->lower_bound(diff_dy);
 	 bool b_found_in_hways = (hway_iter != diff_set_dx_dy->end()) && (hway_iter->dx == dx);

#if 1									  // !!!
	 croads_diff_set_dx_dy->clear();
	 croads_diff_mset_p->clear();
#endif

	 std::set<differential_t, struct_comp_diff_dx_dy>::iterator croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
	 bool b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);

#if 0									  // DEBUG
	 printf("[%s:%d] diff[%2d]:\n", __FILE__, __LINE__, n);
	 for(int i = 0; i < n; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, diff[i].dy, diff[i].dx, diff[i].p, log2(diff[i].p));
	 }
	 printf("[%s:%d] R%2d: Looking for %8X = (%8X + %8X) -> ?\n", __FILE__, __LINE__, n, dx, diff[n - 2].dx, diff[n - 1].dy);
	 printf("[%s:%d] R%2d: Highways:\n", __FILE__, __LINE__, n);
	 print_mset(*diff_mset_p);
	 printf("[%s:%d] R%2d: Country roads:\n", __FILE__, __LINE__, n);
	 print_set(*croads_diff_set_dx_dy);
	 if(b_found) {
		printf("\r[%s:%d] R%2d: Found transition %8X = (%8X + %8X) -> ?, Croad size Dxy %d", __FILE__, __LINE__, n, dx, diff[n - 2].dx, diff[n - 1].dy, croads_diff_set_dx_dy->size());
		fflush(stdout);
	 } else {
		printf("\r[%s:%d] R%2d: Not found transition %8X = (%8X + %8X) -> ?, Croad size Dxy %d", __FILE__, __LINE__, n, dx, diff[n - 2].dx, diff[n - 1].dy, croads_diff_set_dx_dy->size());
		fflush(stdout);
	 }
#endif

	 // p_i >= p_min = Bn / p1 * p2 ... * p{i-1} * B{n-i} 
	 double p_min = 0.0;
	 p_min = 1.0;
	 for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		p_min *= diff[i].p;
	 }
	 p_min = p_min * 1.0 * B[nrounds - 1 - (n + 1)]; 
	 p_min = *Bn / p_min;
	 assert(p_min <= 1.0);

	 //	 if(!b_found_in_hways && !b_found_in_croads) { // if not found neither in Highways nor in Country roads, add as new country road
	 //	 if(!b_found_in_hways) { // if not found in Highways, add as new country road (if it exists will not be added)
	 //	 if(!b_found_in_hways || !b_found_in_croads) { // if not found neither in Highways nor in Country roads, add as new country road
	 {
		uint32_t dx_prev = diff[n - 1].dx;
		assert(diff_set_dx_dy->size() != 0);
		uint32_t cnt_new = tea_f_da_add_pddt(WORD_SIZE, p_min, lsh_const, rsh_const, diff_dy.dx, dx_prev, diff_set_dx_dy, diff_mset_p, croads_diff_set_dx_dy, croads_diff_mset_p);
		if(cnt_new != 0) {
#if 1									  // DEBUG
		  printf("\r[%s:%d] [%2d / %2d]: Added %d new country roads: p_min = %f (2^%f). New sizes: Dxy %d, Dp %d (cnt_lp %d / %d).", 
					__FILE__, __LINE__, n, NROUNDS, cnt_new, p_min, log2(p_min), croads_diff_set_dx_dy->size(), croads_diff_mset_p->size(), cnt_lp, max_lp);
		  fflush(stdout);
#endif
		}
		croad_iter = croads_diff_set_dx_dy->lower_bound(diff_dy);
		b_found_in_croads = (croad_iter != croads_diff_set_dx_dy->end()) && (croad_iter->dx == dx);
#if 0									  // DEBUG
		printf("\r[%s:%d] p_min = 2^%f / (", __FILE__, __LINE__, log2(*Bn));
		for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
		  printf("[%d] 2^%f * ", i, log2(diff[i].p));
		}
		printf("B[%d] 2^%f) = ", nrounds - 1 - (n + 1), log2(B[nrounds - 1 - (n + 1)]));
		printf(" 2^%f | p_thres 2^%f", log2(p_min), log2(TEA_ADD_P_THRES));
		fflush(stdout);
#endif // #if 0									  // EDBUG
	 } 

	 //	 std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy;
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
		  bool b_is_hway = is_dx_in_set_dx_dy(dy, dx_prev, *diff_set_dx_dy);
		  assert(b_is_hway);
		  if(b_is_hway) {
			 found_mset_p.insert(*croad_iter);
		  }
		  croad_iter++;
		}
	 }

	 std::multiset<differential_t, struct_comp_diff_p>::iterator find_iter = found_mset_p.begin();

#if 0									  // DEBUG
	 printf("\r[%s:%d] %2d: Temp set size %d ", __FILE__, __LINE__, n, found_mset_p.size());
	 fflush(stdout);
#endif

	 //		while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) {
	 if(find_iter->dx == dx) {
		while((find_iter->dx == dx) && (find_iter != found_mset_p.end())) {
		  assert((find_iter->dx == dx));
		  diff_dy = *find_iter;

		  dx = diff_dy.dx;
		  dy = diff_dy.dy;
		  pn = diff_dy.p;

		  //		  printf("[%s:%d] %8X -> %8X 2^%f\n", __FILE__, __LINE__, dx, dy, log2(pn));
#if 1
		  pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed round key
#endif // #if 0 

		  double p = 1.0;
		  for(int i = 0; i < n; i++) { // p[0] * p[1] * p[n-1]
			 p *= diff[i].p;
		  }
		  p = p * pn * B[nrounds - 1 - (n + 1)]; 

		  // store the beginnig
#if 0
		  std::set<differential_t, struct_comp_diff_dx_dy>::iterator begin_iter = diff_set_dx_dy->begin();
#endif
		  if((p >= *Bn) && (p != 0.0)) {
			 diff[n].dx = dx;
			 diff[n].dy = dy;
			 diff[n].p = pn;
			 tea_add_threshold_search_full(n+1, nrounds, npairs, key, A, B, Bn, diff, trail, lsh_const, rsh_const, diff_mset_p, diff_set_dx_dy, croads_diff_mset_p, croads_diff_set_dx_dy);
		  }
#if 0
		  if(begin_iter != diff_set_dx_dy->begin()) { // if the root was updated, start from beginning
			 diff_dy.dx = dx;  
			 diff_dy.dy = 0;
			 diff_dy.p = 0.0;
			 find_iter = diff_set_dx_dy->lower_bound(diff_dy);
			 printf("[%s:%d] Return to beginning\n", __FILE__, __LINE__);
			 assert((find_iter->dx == dx));
			 assert(1 == 0);
		  } else {
			 find_iter++;
		  }
#else
		  find_iter++;
#endif
		}	// while
	 }		// if
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

		  max_eadp_tea_f(A, dx, &dy, &pn, lsh_const, rsh_const); // max_dy eadp_tea_f
#if 1
		  pn = tea_add_diff_adjust_to_key(npairs, n, dx, dy, key); // adjust the probability to the fixed key
#endif // #if 0 

		  diff_max_dy.dx = dx; 
		  diff_max_dy.dy = dy;
		  diff_max_dy.p = pn;

		  //		  printf("[%s:%d] Last round %8X %8X 2^%f\n", __FILE__, __LINE__, dx, dy, log2(pn));

		  // Add the new diff to Dp only if it has better prob. than the min.
		  if(pn >= TEA_ADD_P_THRES) {
			 bool b_found = (diff_set_dx_dy->find(diff_max_dy) != diff_set_dx_dy->end());
			 if(!b_found) {
				diff_mset_p->insert(diff_max_dy);
				diff_set_dx_dy->insert(diff_max_dy);
			 }
		  }
#if 0
		  //		  croads_diff_mset_p->insert(diff_max_dy);
		  //		  croads_diff_set_dx_dy->insert(diff_max_dy);
		  double p_min = diff_mset_p->rbegin()->p;
		  if(diff_max_dy.p >= p_min) {
			 diff_mset_p->insert(diff_max_dy);
		  }
		  diff_set_dx_dy->insert(diff_max_dy);
#endif
		} else {
		  assert((find_iter->dx == dx));

		  diff_max_dy = *find_iter;
		  while((find_iter->dx < (dx + 1)) && (find_iter != diff_set_dx_dy->end())) { // get the max among the available
			 double find_iter_p = tea_add_diff_adjust_to_key(npairs, n, find_iter->dx, find_iter->dy, key); // adjust the probability to the fixed key
			 if(find_iter_p > diff_max_dy.p) {
				diff_max_dy = *find_iter;
			 }
			 find_iter++;
		  }
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
 * Search for ADD differential trails in block cipher TEA: wrapper
 * function for \ref tea_add_threshold_search.
 *
 * \param key cryptographic key of TEA.
 * \param B array of bounds.
 * \param trail best found differential trail.
 *
 * \b Algorithm \b Outline:
 * 
 * The procedure operates as follows:
 * 
 * -# Compute a pDDT for F (\ref tea_f_add_pddt).
 * -# Adjust the probabilities of the pDDT to the round key and
 *    constant (\ref tea_f_add_pddt_adjust_to_key).
 * -# Execute the search for differential trails for \f$n\f$ rounds (n
 *    = \ref NROUNDS) through a successive application of \ref tea_add_threshold_search :
 *    - Compute the best found probability on 1 round: \f$B[0]\f$.
 *    - Using \f$B[0]\f$ compute the best found probability on 2 rounds: \f$B[1]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[i-1]\f$ compute the best found probability on \f$(i+1)\f$ rounds: \f$B[i]\f$.
 *    - \f$\ldots\f$
 *    - Using \f$B[0],\ldots,B[n-2]\f$ compute the best found probability on \f$n\f$ rounds: \f$B[n-1]\f$.
 * -# Print the best found trail on \f$n\f$ rounds on standrad output and terminate.
 *
 * \see tea_add_threshold_search
 *
 */
uint32_t tea_add_trail_search(uint32_t key[4], double B[NROUNDS], differential_t trail[NROUNDS])
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = TEA_ADD_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t num_rounds = NROUNDS;

  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  differential_t diff[NROUNDS];	  // arrey of differences
  //  differential_t trail[NROUNDS];  // a differential trail
  //  double B[NROUNDS];				  // arey of bounds

  // init matrices
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dxy before adjust key\n", __FILE__, __LINE__);
  print_set(diff_set_dx_dy);
#endif

#if 1
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
#endif
#if 0									  // DEBUG
  printf("[%s:%d] Dxy after adjust key, p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_set(diff_set_dx_dy);
#endif

  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);
#if 0									  // DEBUG
  printf("[%s:%d] Dp , p_thres = %f 2^%f\n", __FILE__, __LINE__, p_thres, log2(p_thres));
  print_mset(diff_mset_p);
#endif

  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  double Bn_init = 0.0;

  uint32_t nrounds = 0;
  do {
	 nrounds++;
	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn_init), key[0], key[1], key[2], key[3]);
	 double Bn = Bn_init;
	 B[nrounds - 1] = Bn_init;
	 int r = 0;						  // initial round

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 tea_add_threshold_search(r, nrounds, npairs, key, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy);

	 assert(B[nrounds - 1] == Bn);

#if 1									  // DEBUG
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
		  //		  if((0.5 * B[i-1]) < B[i]) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 uint32_t next_round = nrounds;
	 if((next_round >= 2) && (next_round < NROUNDS)) {
		uint32_t dx = ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		uint32_t dy = 0;
		double p = 0.0;

		max_eadp_tea_f(A, dx, &dy, &p, lsh_const, rsh_const); // max_dy eadp_tea_f
		p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		if(p == 0.0) {
		  p = nz_eadp_tea_f(A, 0.0, dx, &dy); // just get an arbitrary non-zero dy
		  p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		}
		//		assert(p != 0.0);
		Bn_init = B[next_round - 1] * p;
		B[next_round] = Bn_init;

		//		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		trail[next_round].dx = dx;
		trail[next_round].dy = dy;
		trail[next_round].p = p;

		differential_t diff;
		diff.dx = dx;
		diff.dy = dy;
		diff.p = p;
		diff_set_dx_dy.insert(diff);
		diff_mset_p.insert(diff);
	 } else {
		Bn_init = 0.0;
	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		//		if(B[i-1] < B[i]) {
		if(B[i-1] < (B[i] * 0.5) ) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
	 }
  } while((nrounds < NROUNDS) && ((B[nrounds - 1] > p_rand) || (nrounds == 0)));
  //  } // for(int nrounds = 1 ...

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

  num_rounds = nrounds;
  tea_add_verify_trail(num_rounds, npairs, key, trail);
  tea_add_verify_differential(num_rounds, npairs, key, trail);
  adp_xor3_free_matrices(A);
  return num_rounds;
}

/**
 * Full threshold search using bounds pre-computed with \ref
 * tea_add_trail_search ; basically a wrapper function for \ref
 * tea_add_threshold_search_full .
 *
 * \param key cryptographic key of TEA.
 * \param BB array of bounds.
 * \param trail best found differential trail.
 *
 * The function takes as input an array of initial bounds \p B and the
 * corresponding best found trail, computed with a prior call to \p
 * tea_add_trail_search and outputs a trail that is at least as good
 * as the niput.
 *
 * \see tea_add_threshold_search_full
 *
 */
uint32_t tea_add_trail_search_full(uint32_t key[4], double BB[NROUNDS], differential_t trail[NROUNDS], uint32_t num_rounds)
{
  uint32_t lsh_const = TEA_LSH_CONST; 
  uint32_t rsh_const = TEA_RSH_CONST;
  double p_thres = TEA_ADD_P_THRES;//0.005;//0.01;//TEA_ADD_P_THRES;
  uint32_t word_size = WORD_SIZE;
  uint32_t npairs = NPAIRS;
  uint32_t ret_nrounds = 0;

  std::multiset<differential_t, struct_comp_diff_p> croads_diff_mset_p; // country roads
  std::set<differential_t, struct_comp_diff_dx_dy> croads_diff_set_dx_dy;

  gsl_matrix* A[2][2][2][2];	  // matrices to compute ADP
  differential_t diff[NROUNDS];	  // arrey of differences
  double B[NROUNDS];				  // arey of bounds

  // init matrices
  adp_xor3_alloc_matrices(A);
  adp_xor3_sf(A);
  adp_xor3_normalize_matrices(A);

  // init bounds
  //double f = 2.0;
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  // init trail
  for(int i = 0; i < NROUNDS; i++) {
	 trail[i].dx = 0;
	 trail[i].dy = 0;
	 trail[i].p = 0.0;
  }

  printf("[%s:%d] num_rounds for second pass: %d\n", __FILE__, __LINE__, num_rounds);

  std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy; // Dxy
  std::multiset<differential_t, struct_comp_diff_p> diff_mset_p;	 // Dp

  tea_f_add_pddt(word_size, p_thres, lsh_const, rsh_const, &diff_set_dx_dy);
  tea_f_add_pddt_adjust_to_key(num_rounds, npairs, key, p_thres, &diff_set_dx_dy);
  tea_f_add_pddt_dxy_to_dp(&diff_mset_p, diff_set_dx_dy);

  printf("Initial set sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
  assert(diff_set_dx_dy.size() == diff_mset_p.size());

  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  // SECOND ROUND SEARCH
  double scale_fact = 1.0;
  uint32_t nrounds = 0;
  do {
	 nrounds++;
	 double Bn = BB[nrounds - 1] * scale_fact; // !!!
	 int r = 0;		  // initial round

	 if(BB[nrounds - 1] == 0.0) {
		assert(Bn == 0.0);
		uint32_t Bn_init = 0.0;
		// Compute an initial bound for the next round
		uint32_t next_round = nrounds - 1;
		if((next_round >= 2) && (next_round < NROUNDS)) {
		  uint32_t dx = ADD(trail[next_round - 2].dx, trail[next_round - 1].dy);
		  uint32_t dy = 0;
		  double p = 0.0;

		  max_eadp_tea_f(A, dx, &dy, &p, lsh_const, rsh_const); // max_dy eadp_tea_f
		  p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		  if(p == 0.0) {
			 p = nz_eadp_tea_f(A, 0.0, dx, &dy); // just get an arbitrary non-zero dy
			 p = tea_add_diff_adjust_to_key(npairs, next_round, dx, dy, key); // adjust the probability to the fixed key
		  }
		  //		assert(p != 0.0);

		  B[next_round] = B[next_round - 1] * p;//Bn_init;
		  Bn_init = B[next_round];

		  printf("[%s:%d] Set Bn_init = 2^%f, B[%d] = 2^%f = 2^%f * 2^%f\n", __FILE__, __LINE__, log2(Bn_init), next_round, log2(B[next_round]), log2(p), log2(B[next_round - 1]));

		  trail[next_round].dx = dx;
		  trail[next_round].dy = dy;
		  trail[next_round].p = p;

		  differential_t diff;
		  diff.dx = dx;
		  diff.dy = dy;
		  diff.p = p;
		  if(p >= p_thres) {
			 diff_set_dx_dy.insert(diff);
			 diff_mset_p.insert(diff);
		  } else {
			 croads_diff_set_dx_dy.insert(diff);
			 croads_diff_mset_p.insert(diff);
		  }
		} else {
		  Bn_init = 0.0;
		}
		Bn = B[next_round];
	 }


	 printf("[%s:%d] nrounds = %d, Bn_init = 2^%f (B[%d] = 2^%f) : key %8X %8X %8X %8X\n", __FILE__, __LINE__, nrounds, log2(Bn), nrounds - 1, log2(B[nrounds - 1]), key[0], key[1], key[2], key[3]);

	 // init diffs
	 for(int i = 0; i < NROUNDS; i++) {
		diff[i].dx = 0;
		diff[i].dy = 0;
		diff[i].p = 0.0;
	 }

	 tea_add_threshold_search_full(r, nrounds, npairs, key, A, B, &Bn, diff, trail, lsh_const, rsh_const, &diff_mset_p, &diff_set_dx_dy, &croads_diff_mset_p, &croads_diff_set_dx_dy);

#if 1									  // DEBUG
	 printf("[%s:%d] %s()\n", __FILE__, __LINE__, __FUNCTION__);
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("B[%2d] = 2^%f", i, log2(B[i]));
		if(i > 0) {
		  if(B[i-1] < B[i]) {
		  //		  if(B[i-1] < (B[i] * 0.5)) {
			 printf(" <-");
		  }
		}
		printf("\n");
	 }
	 //	 printf("pDDT sizes: Dp %d, Dxy %d | Cp %d, Cxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size(), croads_diff_mset_p.size(), croads_diff_set_dx_dy.size());
	 printf("pDDT sizes: Dp %d, Dxy %d\n", diff_mset_p.size(), diff_set_dx_dy.size());
#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X <- %8X %f (2^%f)\n", i, trail[i].dy, trail[i].dx, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  if(trail[i].p != 0.0) {
			 assert(trail[i].dx == ADD(trail[i - 2].dx, trail[i - 1].dy));
		  }
		}
	 }
#endif  // #if 1	  // VERIFY

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if((B[i-1] < B[i]) || (scale_fact < 0.00005)) {
		//		if((B[i-1] < (0.5 * B[i])) || (scale_fact < 0.00005)) {
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
			 scale_fact *= 0.5;
			 //			 for(int j = 0; j < NROUNDS; j++) { // copy the original bounds
			 //				B[j] = BB[j];
			 //			 }
			 printf("[%s:%d] Start again from round %d: scale_fact = %f\n", __FILE__, __LINE__, i, scale_fact);
		  } else {
			 if(scale_fact < 1.0) {
				scale_fact = 1.0;
			 }
		  }
		}
	 }
	 //bool b_adv = 
  } while((nrounds < NROUNDS) && ((B[nrounds - 1] > p_rand) || (nrounds == 0)));
  //  } while((nrounds < NROUNDS) && ((B[nrounds - 1] != 0.0) || (nrounds == 0) ) && (B[nrounds - 1] > p_rand));
  //  } // 2-nd round search

  //  assert(croad_dx_dy == croads_diff_set_dx_dy.end());
  //  assert(hway_dx_dy == diff_set_dx_dy.end());

  //  std::set<differential_t, struct_comp_diff_p>::iterator croad_p = croads_diff_mset_p.lower_bound(tmp_diff);
  //  std::set<differential_t, struct_comp_diff_p>::iterator hway_p = diff_mset_p.lower_bound(tmp_diff);
  //  assert(croad_p == croads_diff_mset_p.end());
  //  assert(hway_p == diff_mset_p.end());

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

  ret_nrounds = nrounds;
#if 0
  tea_add_verify_trail(ret_nrounds, npairs, key, trail);
  tea_add_verify_differential(ret_nrounds, npairs, key, trail);
#endif
  adp_xor3_free_matrices(A);
  return ret_nrounds;
}
