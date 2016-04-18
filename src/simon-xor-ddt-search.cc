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
 * \file  simon-xor-ddt-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Automatic search for XOR differentials in block cipher
 *        Simon32 (16 bit words) using either the full DDT or a
 *        complete partial DDT for all differences with max Hamming
 *        weight 5.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif
#ifndef XDP_ROT_AND_H
#include "xdp-rot-and.hh"
#endif
#ifndef SIMON_H
#include "simon.hh"
#endif
#ifndef SIMON_XOR_THRESHOLD_SEARCH_H
#include "simon-xor-threshold-search.hh"
#endif
#ifndef SIMON_XOR_DDT_SEARCH_H
#include "simon-xor-ddt-search.hh"
#endif

/**
 * \see comp_rows
 */
bool simon_comp_differentials_npairs(differential_t a, differential_t b)
{
  //  bool b_less = (a[0].p > b[0].p);	  // higher probability first
  bool b_less = (a.npairs > b.npairs);	  // more pairs  first
  return b_less;
}

bool simon_comp_differentials_diffs(differential_t a, differential_t b)
{
  bool b_less = (a.dx < b.dx);	  // more pairs last
  if(a.dx == b.dx) {
	 b_less = (a.dy < b.dy);
  }

  return b_less;
}


#if(WORD_SIZE <= 16)				  // Full DDT

/**
 * \see ddt_alloc
 */
double** simon_ddt_alloc()
{
  double** T;
  T = (double **)calloc(ALL_WORDS, sizeof(double *)); // !!!
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 T[i] = (double *)calloc(ALL_WORDS, sizeof(double));
  }
  return T;
}

/**
 * \see ddt_free
 */
void simon_ddt_free(double** T)
{
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 free(T[i]);
  }
  free(T);
}

/**
 * \see rsddt_alloc
 */
differential_t** simon_rsddt_alloc()
{
  differential_t** T;
  T = (differential_t **)calloc(ALL_WORDS, sizeof(differential_t *));
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 T[i] = (differential_t *)calloc(ALL_WORDS, sizeof(differential_t));
  }
  return T;
}

/**
 * \see rsddt_free
 */
void simon_rsddt_free(differential_t** T)
{
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 free(T[i]);
  }
  free(T);
}

/**
 * \see ddt_sort_rows
 */
void simon_ddt_sort_rows(differential_t** T)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 std::sort(T[dx], T[dx] + ALL_WORDS);
  }
}


/**
 * \see ddt_sort
 */
void simon_ddt_sort(differential_t* SDDT)
{
  std::sort(SDDT, SDDT + (ALL_WORDS * ALL_WORDS));
}

/**
 * \see sddt_alloc
 */
differential_t* simon_sddt_alloc()
{
  differential_t* ST;
  ST = (differential_t *)calloc((size_t)(ALL_WORDS * ALL_WORDS), sizeof(differential_t));
  return ST;
}

/**
 * \see sddt_free
 */
void simon_sddt_free(differential_t* ST)
{
  free(ST);
}

/**
 * Convert a DDT to a list of differentials.
 * \see ddt_to_list
 */
void simon_ddt_to_list(double** DDT, differential_t* SDDT)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		uint64_t idx = (dx * ALL_WORDS) + dy;
		SDDT[idx].dx = dx;
		SDDT[idx].dy = dy;
		SDDT[idx].npairs = 0;
		SDDT[idx].p = DDT[dx][dy];
	 }
  }
}

/**
 * \see ddt_to_diff_struct
 */
void simon_ddt_to_diff_struct(double** DDT, differential_t** SDDT)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		SDDT[dx][dy].dx = dx;
		SDDT[dx][dy].dy = dy;
		SDDT[dx][dy].npairs = 0;  // unused
		SDDT[dx][dy].p = DDT[dx][dy];
	 }
  }
}

// full DDT as arrey
void simon_rot_and_ddt(double** D, const uint32_t s, const uint32_t t, const double p_thres)
{
  assert(WORD_SIZE <= 16);
  assert(p_thres == 0.0);
  for(uint32_t delta = 0; delta < ALL_WORDS; delta++) {
	 for(uint32_t dc = 0; dc < ALL_WORDS; dc++) {
		double p = xdp_rot_and(delta, dc, s, t);
		D[delta][dc] = p;
	 }
#if 1
	 if((delta % 1000) == 0) {									  // DEBUG
		printf("row %10d / %10lld\r", delta, ALL_WORDS);
		fflush(stdout);
	 }
#endif
  }
}

void simon_xor_ddt_search(const int n, const int nrounds, 
								  double B[NROUNDS], double* Bn,
								  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
								  const uint32_t dyy_init,
								  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
								  differential_t* SDDT, // sorted DDT
								  differential_t** RSDDT, // row-sorted DDT
								  double p_thres)
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
	 uint32_t i = 0;
	 while(i != ALL_WORDS) {

		uint32_t dx = RSDDT[i][0].dx; // alpha
		uint32_t dy = RSDDT[i][0].dy; // max gamma
		pn = RSDDT[i][0].p;
#if 1											// DEBUG
		uint32_t dy_tmp = 0;
		double p_tmp = max_xdp_rot_and(dx, &dy_tmp, lrot_const_s, lrot_const_t);
		assert(pn == p_tmp);
#endif
		uint32_t dxx = dy ^ dyy_init ^ LROT(dx, lrot_const_u); // gamma ^ dy_i ^ (alpha <<< 2)
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2lld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, i, ALL_WORDS, dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((pn >= *Bn) && (pn != 0.0)) {
		  trail[n].dx = dx;		  // dx_{i}
		  trail[n].dy = dxx;		  // dx_{i+1} 
		  trail[n].p = pn;
		  *Bn = pn;
		  B[n] = pn;
		} 
		i++;
	 }	// while()
  }

  if((n == 0) && (nrounds > 1)) {						  // Round-0 and not last round
	 uint32_t i = 0;
	 while(i != ALL_WORDS) {
		uint32_t dx = RSDDT[i][0].dx; // alpha
		uint32_t dy = RSDDT[i][0].dy; // max gamma
		pn = RSDDT[i][0].p;
#if 1											// DEBUG
		uint32_t dy_tmp = 0;
		double p_tmp = max_xdp_rot_and(dx, &dy_tmp, lrot_const_s, lrot_const_t);
		assert(pn == p_tmp);
#endif
		uint32_t dxx = dy ^ dyy_init ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dy_i ^ (alpha <<< 2)
		double p = pn * B[nrounds - 1 - (n + 1)];
		assert(B[nrounds - 1 - (n + 1)] != 0.0);
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2lld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, i, ALL_WORDS, dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;		  // dx_{i}
		  diff[n].dy = dxx;		  // dx_{i+1}
		  diff[n].p = pn;
		  simon_xor_ddt_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, SDDT, RSDDT, p_thres);
		} 
		i++;
	 }
  }

  if((n == 1) && (n != (nrounds - 1))) {						  // Round-1 and not last round
	 uint32_t i = 0;
	 //	 while((i != ALL_WORDS) && (SDDT[i].p != 0.0)) {
	 while((i != (ALL_WORDS * ALL_WORDS)) && (SDDT[i].p != 0.0)) { // !!
		uint32_t dx = SDDT[i].dx; // alpha
		uint32_t dy = SDDT[i].dy; // gamma
		pn = SDDT[i].p;
		uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)
		double p = diff[0].p * pn * B[nrounds - 1 - (n + 1)];
#if 0									  // DEBUG
		printf("\r[%s:%d] %2d: [%2d / %2lld] %8X -> %8X, 2^%f, 2^%f", __FILE__, __LINE__, n, i, ALL_WORDS, dx, dy, log2(pn), log2(*Bn));
		fflush(stdout);
#endif
		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;		  // dx_{i}
		  diff[n].dy = dxx;		  // dx_{i+1}
		  diff[n].p = pn;
		  simon_xor_ddt_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, SDDT, RSDDT, p_thres);
		} 
		i++;
	 }	// while()
  }

  if((n >= 2) && (n != (nrounds - 1))) { // Round-i and not last round
	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = 0;					 // gamma
	 uint32_t i = 0;
	 while((i != ALL_WORDS) && (RSDDT[dx][i].p != 0.0)) {

		dy = RSDDT[dx][i].dy;
		pn = RSDDT[dx][i].p;

		double p = 1.0;
		for(int j = 0; j < n; j++) { // p[0] * p[1] * p[n-1]
		  p *= diff[j].p;
		}
		p = p * pn * B[nrounds - 1 - (n + 1)]; 

		uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
		uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		if((p >= *Bn) && (p != 0.0)) {
		  diff[n].dx = dx;		  // dx_{i}
		  diff[n].dy = dxx;	  // dx_{i+1}
		  diff[n].p = pn;
		  simon_xor_ddt_search(n+1, nrounds, B, Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, SDDT, RSDDT, p_thres);
		}
		i++;
	 }	// while
  }
  if((n == (nrounds - 1)) && (nrounds > 1)) {		  // Last round

	 uint32_t dx = diff[n - 1].dy; // dx_{i} = dy_{i - 1}
	 uint32_t dy = RSDDT[dx][0].dy; // max gamma
	 pn = RSDDT[dx][0].p;
#if 1											// DEBUG
	 uint32_t dy_tmp = 0;
	 double p_tmp = max_xdp_rot_and(dx, &dy_tmp, lrot_const_s, lrot_const_t);
	 assert(pn == p_tmp);
#endif

	 uint32_t dyy = diff[n-1].dx; // dy_{i} = dx_{i-1}
	 uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

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
		diff[n].dy = dxx;
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

uint32_t simon_xor_ddt_trail_search(uint32_t key[SIMON_MAX_NROUNDS], double B[NROUNDS], differential_t trail[NROUNDS], uint32_t num_rounds)
{
  uint32_t lrot_const_s = SIMON_LROT_CONST_S; 
  uint32_t lrot_const_t = SIMON_LROT_CONST_T;
  uint32_t lrot_const_u = SIMON_LROT_CONST_U;
  double p_thres = XDP_ROT_AND_P_THRES;
  uint32_t npairs = SIMON_NPAIRS;

  differential_t diff[NROUNDS];	  // arrey of differences

  // init bounds
  for(int i = 0; i < NROUNDS; i++) {
	 B[i] = 0.0;
  }

  double** DDT;
#if 1									  // INFO
  printf("[%s:%d] Allocating DDT ...", __FILE__, __LINE__);
#endif
  DDT = simon_ddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing DDT ...", __FILE__, __LINE__);
#endif
  simon_rot_and_ddt(DDT, lrot_const_s, lrot_const_t, p_thres);
#if 1									  // INFO
  printf("OK\n");
#endif

  // sorted DDT
  differential_t* SDDT;
#if 1									  // INFO
  printf("[%s:%d] Allocating SDDT ...", __FILE__, __LINE__);
#endif
  SDDT = simon_sddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing SDDT ...", __FILE__, __LINE__);
#endif
  simon_ddt_to_list(DDT, SDDT);
#if 1									  // INFO
  printf("OK\n");
#endif
#if 1									  // INFO
  printf("[%s:%d] Sort SDDT ...", __FILE__, __LINE__);
#endif
  simon_ddt_sort(SDDT);
#if 1									  // INFO
  printf("OK\n");
#endif

  // row-sorted DDT
  differential_t** RSDDT;
#if 1									  // INFO
  printf("[%s:%d] Allocating RSDDT ...", __FILE__, __LINE__);
#endif
  RSDDT = simon_rsddt_alloc();
#if 1									  // INFO
  printf("OK\n");
  printf("[%s:%d] Computing RSDDT ...", __FILE__, __LINE__);
#endif
  simon_ddt_to_diff_struct(DDT, RSDDT);
#if 1									  // INFO
  printf("OK\n");
#endif
#if 1									  // INFO
  printf("[%s:%d] Sort RSDDT ...", __FILE__, __LINE__);
#endif
  simon_ddt_sort_rows(RSDDT);
#if 1									  // INFO
  printf("OK\n");
#endif


  double p_rand = 1.0 / (double)(1ULL << ((2 * WORD_SIZE) - 1));
  printf("[%s:%d] p_rand 2^%f\n", __FILE__, __LINE__, log2(p_rand));

  double Bn_init = 0.0;
  uint32_t dyy_init = 0;

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

	 simon_xor_ddt_search(r, nrounds, B, &Bn, diff, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u, SDDT, RSDDT, p_thres);

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

#endif
#if 1									  // DEBUG
	 double p_tot = 1.0;
	 for(uint32_t i = 0; i < nrounds; i++) {
		printf("%2d: %8X -> %8X %f (2^%f)\n", i, trail[i].dx, trail[i].dy, trail[i].p, log2(trail[i].p));
		p_tot *= trail[i].p;
	 }
	 printf("p_tot = %16.15f = 2^%f, Bn = %f = 2^%f\n", p_tot, log2(p_tot), Bn, log2(Bn));
#endif  // #if 0									  // DEBUG
#if 1	  // VERIFY
	 if(nrounds >=3) {
		for(uint32_t i = (nrounds - 1); i >= 2; i--) {
		  assert(trail[i].dx == trail[i-1].dy);
		  //		  assert(trail[i].dy == trail[i-1].dx);
		}
	 }
#endif  // #if 1	  // VERIFY

	 // Compute an initial bound for the next round
	 uint32_t next_round = nrounds;
	 if((next_round >= 2) && (next_round < NROUNDS)) {
		uint32_t dx = trail[next_round - 1].dy; // dx_{i} = dy_{i - 1}
		uint32_t dy = RSDDT[dx][0].dy; // max gamma
		double p = RSDDT[dx][0].p;
#if 1											// DEBUG
		uint32_t dy_tmp = 0;
		double p_tmp = max_xdp_rot_and(dx, &dy_tmp, lrot_const_s, lrot_const_t);
		assert(p == p_tmp);
#endif
		assert(p != 0.0);
		uint32_t dyy = diff[next_round - 1].dx; // dy_{i} = dx_{i-1}
		uint32_t dxx = dy ^ dyy ^ LROT(dx, lrot_const_u); // dx_{i+1} = gamma ^ dx_{i-1} ^ (alpha <<< 2)

		Bn_init = B[next_round - 1] * p;
		B[next_round] = Bn_init;

		//		printf("[%s:%d] Set B[%d] = 2^%f\n", __FILE__, __LINE__, next_round, log2(Bn_init));
		trail[next_round].dx = dx;
		trail[next_round].dy = dxx;
		trail[next_round].p = p;

		assert(trail[next_round].dx == trail[next_round-1].dy);
	 } else {
		Bn_init = 0.0;
	 }

	 // If the bound for i rounds is better than the bound for (i - 1) rounds -- start the search again from round 1
	 uint32_t i = nrounds - 1;
	 if(i > 0) {
		if(B[i-1] < B[i]) {
		  nrounds = 0;
		  Bn_init = 0.0;
		  for(int j = 0; j < NROUNDS; j++) {
			 B[j] = 0.0;
		  }
		  printf("[%s:%d] Start again from round 1\n", __FILE__, __LINE__);
		}
		assert(B[i-1] >= B[i]);
	 }
  } while((nrounds < NROUNDS) && ((B[nrounds - 1] > p_rand) || (nrounds == 0)));

  printf("[%s:%d] nrounds = %d\n", __FILE__, __LINE__, nrounds);
  assert(nrounds <= NROUNDS);

  num_rounds = nrounds;
  simon_verify_xor_trail(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);
  simon_verify_xor_differential(num_rounds, npairs, key, trail, dyy_init, lrot_const_s, lrot_const_t, lrot_const_u);

  simon_rsddt_free(RSDDT);
  simon_sddt_free(SDDT);
  simon_ddt_free(DDT);
  return num_rounds;
}
#endif  // #if(WORD_SIZE <= 16), full DDT


/*
 * ---------------------------------------------------------------------
 * START Full search for differentials for Simon32 (16 bit words) limited
 *       to all words of max Hamming weight 5
 * ---------------------------------------------------------------------
 */ 


/**
 * Generate all words of given Hamming weight (recursive version)
 */ 
uint32_t gen_word_hw_i(const uint32_t k, const uint32_t n, const uint32_t hw,
							  uint32_t* x_in, uint32_t* x_cnt, std::vector<uint32_t>* X)
{
  uint32_t x = *x_in;
  uint32_t mask = (0xffffffff >> (32 - n));
  if(k == n) {
	 X->push_back(x);
	 (*x_cnt)++;
	 uint32_t hw_x = hw32(x & mask); 
#if 0									  // DEBUG
	 printf("[%s:%d] %10d | %8X %d\n", __FILE__, __LINE__, *x_cnt, x, hw_x);
#endif
	 assert(hw_x <= hw);
	 return x;
  }

  for(uint32_t i = 0; i < 2; i++) {
	 x |= (i << k);
	 if(hw32(x & mask) <= hw) {
		gen_word_hw_i(k+1, n, hw, &x, x_cnt, X);
	 }
  }
  return 0;
}

/**
 * Generate all words of given Hamming weight --
 * wrapper for \ref gen_word_hw_i (recursive version)
 */ 
uint32_t gen_word_hw(const uint32_t n, const uint32_t hw, 
							std::vector<uint32_t>* X)
{
  uint32_t k = 0;
  uint32_t x = 0;
  uint32_t x_cnt = 0;

  gen_word_hw_i(k, n, hw, &x, &x_cnt, X);

  return x_cnt;
}

/**
 * Generate all words of given Hamming weight 
 * Same as \ref gen_word_hw but exhasutively trying out all inputs
 * (non-recursive version)
 */ 
uint32_t gen_word_hw_all(const uint32_t word_size, const uint32_t hw)
{
  uint32_t cnt = 0;
  uint32_t mask = (0xffffffff >> (32 - word_size));
  uint64_t N = (1ULL << word_size);
  for(uint32_t x = 0; x < N; x++) {
	 uint32_t hw_x = hw32(x & mask); 
	 if(hw_x <= hw) {
#if 0									  // DEBUG
		printf("[%s:%d] %10d| %8X %d\n", __FILE__, __LINE__, cnt, x, hw_x);
#endif
		cnt++;
	 }
  }
  return cnt;
}

/**
 * Compute one row of a partial DDT \p T for a given input \p dx
 * \sa simon_compute_partial_ddt
 */
void simon_ddt_add_row(std::unordered_map<uint32_t, std::vector<differential_t>>* T,
							  const uint32_t dx, const uint32_t hw_max)
{
  const uint32_t s = SIMON_LROT_CONST_S;
  const uint32_t t = SIMON_LROT_CONST_T;
  const uint32_t u = SIMON_LROT_CONST_U;

#if 1									  // DEBUG
  bool b_test = false;
#endif
  //  std::vector<differential_t>* DZ = (std::vector<differential_t> *)calloc(1, sizeof(std::vector<differential_t>));
  std::vector<differential_t> DZ;// = (std::vector<differential_t> *)calloc(1, sizeof(std::vector<differential_t>));
  for(uint32_t dz = 0; dz < ALL_WORDS; dz++) {
	 double p = xdp_rot_and(dx, dz, s, t);
	 if(p > 0.0) {
		uint32_t dx_lrot = LROT(dx, u);
		differential_t diff = {0, 0, 0, 0.0};
		diff.dx = dx;
		diff.dy = dx_lrot ^ dz;
		diff.p = p;
		DZ.push_back(diff);
#if 1									  // DEBUG
		if(!b_test) {
		  b_test = true;
		}
#endif
#if 0									  // DEBUG
		printf("[%s:%d] %8X -> %8X 2^%f\n", __FILE__, __LINE__, diff.dx, diff.dy, log2(p));
#endif
	 }
  }
  std::pair<uint32_t, std::vector<differential_t>> new_pair (dx, DZ);
  T->insert(new_pair);
  assert(b_test);
}

/**
 * Compute a partial DDT \p T for a subset of inputs stored in \p X
 * The subset represent all words of given Hamming weight 
 */
void simon_compute_partial_ddt(std::unordered_map<uint32_t, std::vector<differential_t>>* T,
										 std::vector<uint32_t> DX, const uint32_t hw_max)
{
  std::vector<uint32_t>::iterator vec_iter;
  for(vec_iter = DX.begin(); vec_iter != DX.end(); vec_iter++) {
	 uint32_t dx = *vec_iter;
	 simon_ddt_add_row(T, dx, hw_max);
#if 1									  // DEBUG
	 std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator T_iter = T->find(dx);
	 printf("[%s:%d] dx %4X\r", __FILE__, __LINE__, dx);
	 fflush(stdout);
	 //	 printf("%4X: %d\n", dx, (uint32_t)T_iter->second->size());
	 assert(T_iter != T->end());
#endif
  }
}


/**
 * Compute full DDT \p T containing only the non-zero prob. entries
 */
void simon_compute_full_ddt(std::unordered_map<uint32_t, std::vector<differential_t>>* T)
{
  assert(WORD_SIZE <= 16);
#if(WORD_SIZE <= 16)
  uint32_t r1 = SIMON_LROT_CONST_S; 
  uint32_t r2 = SIMON_LROT_CONST_T;
  uint32_t r3 = SIMON_LROT_CONST_U;
  uint32_t DX_len = ALL_WORDS;

  for(uint32_t dx = 0; dx < DX_len; dx++) {
	 differential_t DY[ALL_WORDS] = {{0, 0, 0, 0.0}};
#if 0									  // DEBUG
	 printf("[%s:%d] dx %4X\r", __FILE__, __LINE__, dx);
	 fflush(stdout);
#endif
	 for(uint32_t x = 0; x < ALL_WORDS; x++) {
		uint32_t xx = x ^ dx;

		uint32_t y  = ( LROT(x, r1) &  LROT(x, r2)) ^  LROT(x, r3); 
		uint32_t yy = (LROT(xx, r1) & LROT(xx, r2)) ^ LROT(xx, r3); 
		uint32_t dy = y ^ yy;
		//		DY[dy]++;
		DY[dy].dx = dx;
		DY[dy].dy = dy;
		DY[dy].p = 0.0;
		DY[dy].npairs++;
	 }

	 std::sort(DY, DY + ALL_WORDS, simon_comp_differentials_npairs);

	 std::vector<differential_t> DX;
	 //	 std::vector<differential_t>* DX = (std::vector<differential_t> *)calloc(1, sizeof(std::vector<differential_t>));

	 uint32_t i = 0;
	 while(DY[i].npairs != 0) {
		DY[i].p = (double)DY[i].npairs / (double)ALL_WORDS;
		DX.push_back(DY[i]);
		i++;
	 }

	 std::pair<uint32_t, std::vector<differential_t>> new_pair (dx, DX);
	 T->insert(new_pair);
  }
#if 0									  // DEBUG
  std::unordered_map<uint32_t, std::vector<differential_t>*>::const_iterator T_iter;
  for(T_iter = T->begin(); T_iter != T->end(); T_iter++) {
	 std::vector<differential_t>::iterator DX_iter;
	 for(DX_iter = T_iter->second->begin(); DX_iter != T_iter->second->end(); DX_iter++) {
		uint32_t dx = DX_iter->dx;
		uint32_t dy = DX_iter->dy;
		double p = DX_iter->p;
		printf("T: %X %X %f\n", dx, dy, p);
	 }
  }
#endif
#endif  // #if(WORD_SIZE <= 16)
}

void simon_diff_update_max(const differential_t input_diff, const differential_t output_diff, differential_t* max_diff)
{
  const uint32_t dx = output_diff.dx;
  const uint32_t dy = output_diff.dy;
  const double p = output_diff.p;
  if(p > max_diff->p) {
#if 0									  // DEBUG
	 printf("[%s:%d] Update max p : (%4X %4X 2^%f) -> (%4X %4X 2^%f)\n", 
			  __FILE__, __LINE__, input_diff.dx, input_diff.dy, log2(input_diff.p), dx, dy, log2(p));
#endif
	 max_diff->p = p;
	 max_diff->dx = dx;
	 max_diff->dy = dy;
  } else {
	 uint32_t hw_sum = hw32(dx & MASK) + hw32(dy & MASK);
	 uint32_t hw_sum_max = hw32(max_diff->dx & MASK) + hw32(max_diff->dy & MASK);
	 if((p == max_diff->p) && (hw_sum < hw_sum_max)) { // if current has same prob. but smaller Hamming weight
#if 0									  // DEBUG
		printf("[%s:%d] Update max p*: (%4X %4X 2^%f) -> (%4X %4X 2^%f)\n", 
				 __FILE__, __LINE__, input_diff.dx, input_diff.dy, log2(input_diff.p), dx, dy, log2(p));
#endif
		max_diff->p = p;
		max_diff->dx = dx;
		max_diff->dy = dy;
	 }
  }
}

void simon_diff_get_max(std::unordered_map<std::string, differential_t *> H, differential_t* max_diff)
{
  differential_t dummy_input_diff = {0, 0, 0, 0.0};
  max_diff->dx = 0;
  max_diff->dy = 0;
  max_diff->npairs = 0;
  max_diff->p = 0.0;
  std::unordered_map<std::string, differential_t *>::const_iterator H_iter = H.begin();
  while(H_iter != H.end()) {
	 const uint32_t dx = (H_iter->second)->dx;
	 const uint32_t dy = (H_iter->second)->dy;
	 double p = (H_iter->second)->p;
	 const differential_t diff = {dx, dy, 0, p};
	 simon_diff_update_max(dummy_input_diff, diff, max_diff);
	 H_iter++;
  }
}

/**
 * Search for differentials for one round (round \p r) of Simon
 */
bool simon_diff_search_oneround(const uint32_t nrounds,
										  std::unordered_map<uint32_t, std::vector<differential_t>>* T,
										  std::unordered_map<uint32_t, differential_t>* H,
										  std::unordered_map<uint32_t, differential_t>* G,
										  //										  std::unordered_map<uint32_t, differential_t *>* G,
										  const differential_t input_diff,
										  differential_t* max_output_diff,
										  const uint32_t hw_max)
{
  assert(WORD_SIZE <= 16);
  bool b_hw = false;
#if(WORD_SIZE <= 16)
#if 0                           // DEBUG
  printf("[%s:%d] H size = %d\n", __FILE__, __LINE__, (uint32_t)H->size());
  assert(H->size() != 0);
  printf("[%s:%d] G size = %d\n", __FILE__, __LINE__, (uint32_t)G->size());
#endif     
  //  const double p_eps = 1.0 / (double)(1ULL << 4);
  //  uint32_t h_cnt = 0;
  std::unordered_map<uint32_t, differential_t>::const_iterator H_iter = H->begin();
  while(H_iter != H->end()) {

	 const uint32_t dx_in = (H_iter->second).dx;
	 const uint32_t dy_in = (H_iter->second).dy;
	 const double p_in = (H_iter->second).p;
	 const differential_t diff_in = {dx_in, dy_in, 0, p_in};

	 assert(hw32(dx_in & MASK) <= hw_max);
	 assert(hw32(dy_in & MASK) <= hw_max);

#if 0									  // DEBUG
	 h_cnt++;
	 printf("[%s:%d] H: %8X %8X 2^%f\n", __FILE__, __LINE__, dx_in, dy_in, log2(p_in));
	 //	 printf("[%s:%d] H: %8X %8X 2^%f [%d / %d]\r", __FILE__, __LINE__, dx_in, dy_in, log2(p_in), h_cnt, (uint32_t)H->size());
	 //	 fflush(stdout);
#endif
	 std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator ddt_iter = T->find(dx_in);
	 if(ddt_iter == T->end()) {
		simon_ddt_add_row(T, dx_in, hw_max);
		ddt_iter = T->find(dx_in);
#if 0									  // DEBUG
		printf("[%s:%d] T: add new row %8X -> len %d\n", __FILE__, __LINE__, dx_in, (uint32_t)ddt_iter->second.size());
#endif
		assert(0 == 1);			  // !!! We should not be here if we compute the full table
	 }
	 assert(ddt_iter != T->end());
#if 0	 								  // DEBUG
	 uint32_t ncol = T->count(dx_in);
	 if(ncol > 1) {
		printf("[%s:%d] Collision in T: %8X found %d times\n", __FILE__, __LINE__, dx_in, ncol);
	 }
	 assert(ncol <= 1);
#endif

	 std::vector<differential_t> DZ = (ddt_iter->second); // dz ^ (dx <<< 2)

	 //	 uint32_t dz_cnt = 0;
	 std::vector<differential_t>::iterator vec_iter;
	 for(vec_iter = DZ.begin(); vec_iter != DZ.end(); vec_iter++) {
		differential_t diff = *vec_iter;
		uint32_t dz = diff.dy;	  // = (dx_in <<< 2) ^ dz
		double p = diff.p;
		assert(p != 0.0);
		assert(dx_in == diff.dx);
#if 0									  // DEBUG1
		printf("[%s:%d] DZ: %8X -> %8X 2^%f\n", __FILE__, __LINE__, dx_in, dz, log2(p));
		dz_cnt++;
		//		printf("[%s:%d] H: [%d / %d 2^%4.2f], DZ: [%d / %d 2^%4.2f]\r", __FILE__, __LINE__, h_cnt, (uint32_t)H->size(), log2(H->size()), dz_cnt, (uint32_t)DZ.size(), log2(DZ.size()));
		//		fflush(stdout);
#endif
		const uint32_t dx_out = dz ^ dy_in;
		const uint32_t dy_out = dx_in;
		const double p_out = (p_in * p);
		const differential_t diff_out = {dx_out, dy_out, 0, p_out};

#if 0									  // DEBUG
		const uint32_t dx_out_old = dx_out;
#endif

		if(hw32(dx_out & MASK) <= hw_max) {
		//		if((hw32(dx_out & MASK) <= hw_max) && (p_out >= (max_output_diff->p * p_eps))) { // !
		  if(!b_hw) {
			 b_hw = true;
		  }
#if 0									  // DEBUG
		  const uint32_t dx_out_new = dx_out;
		  assert(dx_out_old == dx_out_new);
#endif
		  //		  std::string s_diff_out = differential_to_string(diff_out);
		  //		  std::unordered_map<std::string, differential_t *>::const_iterator G_iter = G->find(s_diff_out);
		  uint32_t n_diff_out = differential_to_num(diff_out);
		  std::unordered_map<uint32_t, differential_t>::iterator G_iter = G->find(n_diff_out);
		  //		  differential_t* diff_temp = (*G)[s_diff_out];
#if 1										// DEBUG
		  if(G_iter != G->end()) {  // diff already in G
			 assert((G_iter->second).dx == diff_out.dx);
			 assert((G_iter->second).dy == diff_out.dy);
			 assert((G_iter->second).dx == dx_out);
			 assert((G_iter->second).dy == dy_out);
			 assert((G_iter->second).dy == dx_in);
			 assert((G_iter->second).dy == diff_in.dx);
		  }
#endif
		  if((diff_out.dx != dx_out) || (diff_out.dy != dy_out)) {
			 printf("[%s:%d] ERROR! ", __FILE__, __LINE__);
			 printf("dx %4X != %4X, ", diff_out.dx, dx_out);
			 printf("dy %4X != %4X, ", diff_out.dy, dy_out);
			 printf("\n");
		  }
		  assert(diff_out.dx == dx_out);
		  assert(diff_out.dy == dy_out);

		  if(G_iter != G->end()) {  // diff already in G
#if 1										 // DEBUG

			 if(((G_iter->second).dx != dx_out) || ((G_iter->second).dy != dy_out)) {
				printf("[%s:%d] ERROR! ", __FILE__, __LINE__);
				printf("dx %4X != %4X, ", (G_iter->second).dx, dx_out);
				printf("dy %4X != %4X, ", (G_iter->second).dy, dy_out);
				assert((G_iter->second).dx == dx_out);
				assert((G_iter->second).dy == dy_out);
			 }
#endif
#if 0									  // DEBUG
			 double p_old = (G_iter->second).p;
#endif
			 (G_iter->second).p += diff_out.p;	  // update its probability
#if 0									  // DEBUG
			 double p_new = (G_iter->second).p;
#endif
#if 0									  // DEBUG
			 printf("[%s:%d] G: Found %8X %8X 2^%f -> 2^%f | #%d\n", 
					  __FILE__, __LINE__, dx_out, dy_out, log2(p_old), log2(p_new), (uint32_t)G->size());
#endif
			 differential_t new_diff = {(G_iter->second).dx, (G_iter->second).dy, 0,  (G_iter->second).p};
			 simon_diff_update_max(diff_in, new_diff, max_output_diff);
		  } else {

			 //			 differential_t* new_diff = (differential_t *)calloc(1, sizeof(differential_t));
			 differential_t new_diff = {0, 0, 0, 0.0};
			 new_diff.dx = diff_out.dx;
			 new_diff.dy = diff_out.dy;
			 new_diff.npairs = diff_out.npairs;
			 new_diff.p = diff_out.p;
			 //			 std::pair<std::string, differential_t*> new_pair (s_diff_out, new_diff);
			 std::pair<uint32_t, differential_t> new_pair (n_diff_out, new_diff);
			 G->insert(new_pair);
#if 0									  // DEBUG
			 printf("[%s:%d] G: Add new %8X %8X 2^%f | #%d\n", 
					  __FILE__, __LINE__, dx_out, dy_out, log2(p_out), G->size());
#endif
			 simon_diff_update_max(diff_in, new_diff, max_output_diff);

#if 1									  // DEBUG
			 G_iter = G->find(n_diff_out);
			 assert((G_iter->second).dx == dx_out);
			 assert((G_iter->second).dy == dy_out);
#endif
		  }
#if 1									  // DEBUG
		  uint32_t ncol = G->count(n_diff_out);
		  if(ncol > 1) {
			 printf("[%s:%d] Collision in G: %8X %8X 2^%f found %d times\n", 
					  __FILE__, __LINE__, dx_out, dy_out, log2(p_out), ncol);
		  }
		  assert(ncol <= 1);
#endif
		} else {
#if 0									  // DEBUG
		  printf("[%s:%d] HW bigger than max %4X %d > %d\n", __FILE__, __LINE__, dx_out, hw32(dx_out & MASK), hw_max);
#endif
		}
	 }
	 H_iter++;
  }
  if(!b_hw) {
	 printf("[%s:%d] All HW bigger than max %d\n", __FILE__, __LINE__, hw_max);
  }
  assert((G->size() > 0) == b_hw);
#if 0                           // DEBUG
  printf("[%s:%d] H size = %d\n", __FILE__, __LINE__, (uint32_t)H->size());
  assert(H->size() != 0);
  printf("[%s:%d] G size = %d b_hw = %d\n", __FILE__, __LINE__, (uint32_t)G->size(), b_hw);
  assert(G->size() != 0);
#endif    
#endif  // #if(WORD_SIZE <= 16)
  return b_hw; 
}

/**
 * Same as \ref simon_diff_search_oneround but without the debugging computations.
 * \note Assumes the DDT T is full (i.e. not partial or empty).
 */
bool simon_diff_search_oneround_fast(const uint32_t nrounds,
												 std::unordered_map<uint32_t, std::vector<differential_t>>* T,
												 std::unordered_map<uint32_t, differential_t>* H,
												 std::unordered_map<uint32_t, differential_t>* G,
												 const differential_t input_diff,
												 differential_t* max_output_diff,
												 const uint32_t hw_max,
												 uint64_t* cnt_iter_in)
{
  assert(WORD_SIZE <= 16);
  bool b_hw = false;
#if(WORD_SIZE <= 16)
  uint64_t cnt_iter = 0;
  std::unordered_map<uint32_t, differential_t>::const_iterator H_iter = H->begin();
  while(H_iter != H->end()) {

	 cnt_iter++;
	 const uint32_t dx_in = (H_iter->second).dx;
	 const uint32_t dy_in = (H_iter->second).dy;
	 const double p_in = (H_iter->second).p;
	 const differential_t diff_in = {dx_in, dy_in, 0, p_in};

	 std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator ddt_iter = T->find(dx_in);
	 std::vector<differential_t> DZ = (ddt_iter->second); // dz ^ (dx <<< 2)

	 std::vector<differential_t>::iterator vec_iter;
	 for(vec_iter = DZ.begin(); vec_iter != DZ.end(); vec_iter++) {

		cnt_iter++;
		differential_t diff = *vec_iter;
		uint32_t dz = diff.dy;	  // = (dx_in <<< 2) ^ dz
		double p = diff.p;

		const uint32_t dx_out = dz ^ dy_in;
		const uint32_t dy_out = dx_in;
		const double p_out = (p_in * p);
		const differential_t diff_out = {dx_out, dy_out, 0, p_out};

		if(hw32(dx_out & MASK) <= hw_max) {
		  if(!b_hw) {
			 b_hw = true;
		  }
		  uint32_t n_diff_out = differential_to_num(diff_out);
		  std::unordered_map<uint32_t, differential_t>::iterator G_iter = G->find(n_diff_out);

		  if(G_iter != G->end()) {  // diff already in G

			 (G_iter->second).p += diff_out.p;	  // update its probability

			 differential_t new_diff = {(G_iter->second).dx, (G_iter->second).dy, 0,  (G_iter->second).p};

			 simon_diff_update_max(diff_in, new_diff, max_output_diff);

		  } else {

			 differential_t new_diff = {0, 0, 0, 0.0};
			 new_diff.dx = diff_out.dx;
			 new_diff.dy = diff_out.dy;
			 new_diff.npairs = diff_out.npairs;
			 new_diff.p = diff_out.p;

			 std::pair<uint32_t, differential_t> new_pair (n_diff_out, new_diff);
			 G->insert(new_pair);

			 simon_diff_update_max(diff_in, new_diff, max_output_diff);

		  }
		}
	 }
	 H_iter++;
  }
  if(!b_hw) {
	 printf("[%s:%d] All HW bigger than max %d\n", __FILE__, __LINE__, hw_max);
  }
  *cnt_iter_in = cnt_iter;
#endif  // #if(WORD_SIZE <= 16)
  return b_hw;
}

/*
Simon32 12 round 2^-34 clustering

B[ 0] = 1.0
B[ 1] = 2^-4.000000
B[ 2] = 2^-4.000000
B[ 3] = 2^-6.000000
B[ 4] = 2^-8.000000
B[ 5] = 2^-12.000000
B[ 6] = 2^-14.000000
B[ 7] = 2^-18.000000
B[ 8] = 2^-20.000000
B[ 9] = 2^-26.000000
B[10] = 2^-30.000000
B[11] = 2^-34.000000
*/
void simon_diff_search(const uint32_t nrounds, 
							  const uint32_t dx_in, 
							  const uint32_t dy_in, 
							  const uint32_t hw_max,
							  std::unordered_map<uint32_t, std::vector<differential_t>>* T,
							  std::unordered_map<uint32_t, differential_t>* D, // all output diffs after D_round
							  const uint32_t D_round,
							  const char* logfile)
{
  differential_t best_diff_12r[2] = {{0, 0, 0, 0.0}, {0, 0, 0, 0.0}};

  assert(nrounds <= SIMON_NROUNDS);
#if 0									  // for experimental verification
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  key[0] = random32() & MASK;
  key[1] = random32() & MASK;
  key[2] = random32() & MASK;
  key[3] = random32() & MASK;
#endif
  double p_exp = 0.0;
#if 1									  // DEBUG
  printf("\n[%s:%s()%d] hw_max %d\n", __FILE__, __FUNCTION__, __LINE__, hw_max);
#endif
  std::unordered_map<uint32_t, differential_t> H;
  std::unordered_map<uint32_t, differential_t> G;

  //  differential_t input_diff  = {0x280, 0xA80, 0, 1.0}; // mydiff-1
  //  differential_t input_diff  = {0x400, 0x1900, 0, 1.0}; // mydiff-2
  //  differential_t input_diff  = {0x8000, 0x2202, 0, 1.0}; // mydiff-3
  //  differential_t input_diff = {0x0001, 0x0000, 0, 1.0}; // DTU
  assert((hw32(dx_in) <= hw_max) && (hw32(dy_in) <= hw_max));
  differential_t input_diff = {dx_in, dy_in, 0, 1.0};

  uint32_t n_diff = differential_to_num(input_diff);
  std::pair<uint32_t, differential_t> new_pair (n_diff, input_diff);
  H.insert(new_pair);

#if 1									  // DEBUG
  printf("\n [%s:%d] INPUT DIFF %8X %8X \n", __FILE__, __LINE__, input_diff.dx, input_diff.dy);
  FILE* fp = fopen(logfile, "a");
  fprintf(fp, "\n[%s:%d] INPUT DIFF %4X %4X\n", __FILE__, __LINE__, input_diff.dx, input_diff.dy);
  fclose(fp);
#endif
  for(uint32_t i = 0; i < nrounds; i++) {

#if 1									  // DEBUG
	 printf("\n--- [%s:%d] Round [%d / %d] (%4X %4X) : T size %d, H size %d 2^%4.2f ---\n", __FILE__, __LINE__, i+1, nrounds, input_diff.dx, input_diff.dy, (uint32_t)T->size(), (uint32_t)H.size(), log2(H.size()));
#endif
#if 0									  // Hash table statistics
	 std::cout << "entries_count = " << H.size() << " = 2^" << log2(H.size()) << std::endl;
	 std::cout << "bucket_count = " << H.bucket_count() << std::endl;
	 std::cout << "max_bucket_count = " << H.max_bucket_count() << " = 2^" << log2(H.max_bucket_count()) << std::endl;
	 std::cout << "load_factor = entries / buckets = " << H.load_factor() << " ( " << floor(H.load_factor() * 100) << "\% )" << std::endl;
	 std::cout << "max_load_factor = " << H.max_load_factor() << std::endl;
	 assert(H.load_factor() <= 1);
#endif
	 differential_t max_diff = {0, 0, 0, 0.0};

#if 0  // with debug info
	 bool b_hw = simon_diff_search_oneround(i+1, T, &H, &G, input_diff, &max_diff, hw_max);
#else	 // fast (no debug) + measure timinigs
	 timestamp_t start_time = get_timestamp();
	 uint64_t cnt_iter = 0;
	 bool b_hw = simon_diff_search_oneround_fast(i+1, T, &H, &G, input_diff, &max_diff, hw_max, &cnt_iter);
	 timestamp_t end_time = get_timestamp();

	 double total_time_sec = (double)(end_time - start_time) / 1000000.0L;
	 double total_time_ms = (double)(end_time - start_time) / 1000.0L;
	 double total_time_mu = (double)(end_time - start_time);
	 double total_time_min = total_time_sec / 60.0;
	 double C = total_time_sec / (double)cnt_iter;
	 printf("[%s:%d] %f min %f s %f ms %f mu\n", __FILE__, __LINE__, total_time_min, total_time_sec, total_time_ms, total_time_mu);
	 //	 printf("[%s:%d] cnt_iter %ld 2^%4.2f C %f 2^%f\n", __FILE__, __LINE__, cnt_iter, log2(cnt_iter), C, log2(C));
	 printf("[%s:%d] cnt_iter %lld 2^%4.2f C %f 2^%f\n", __FILE__, __LINE__, cnt_iter, log2(cnt_iter), C, log2(C));
#endif

	 uint64_t npairs = 0;
#if 0									  // DEBUG
	 if((i+1) >= 9) {			  // !!!
		npairs = (1ULL << 32);
		p_exp = simon_verify_differential(key, input_diff, max_diff, i+1, npairs); // full search over all 2^32 inputs
	 } else {						  // i <= 10
		npairs = (1ULL << 25);
		p_exp = simon_verify_differential_approx(key, input_diff, max_diff, i+1, npairs); // random inputs
	 }
#endif

	 if((i+1) == 12) {
		if(max_diff.p > best_diff_12r[1].p) {
		  best_diff_12r[0].dx = input_diff.dx;
		  best_diff_12r[0].dy = input_diff.dy;
		  best_diff_12r[0].npairs = input_diff.npairs;
		  best_diff_12r[0].p = input_diff.p;

		  best_diff_12r[1].dx = max_diff.dx;
		  best_diff_12r[1].dy = max_diff.dy;
		  best_diff_12r[1].npairs = max_diff.npairs;
		  best_diff_12r[1].p = max_diff.p;

		  printf("\n[%s:%s():%d] Update BEST 12R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __FUNCTION__, __LINE__,
					best_diff_12r[0].dx, best_diff_12r[0].dy, best_diff_12r[1].dx, best_diff_12r[1].dy, log2(best_diff_12r[1].p));

#if 0									  // print update to file
		  FILE* fp = fopen(logfile, "a");
		  fprintf(fp, "[%s:%s():%d] Update BEST 12R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __FUNCTION__, __LINE__,
					 best_diff_12r[0].dx, best_diff_12r[0].dy, best_diff_12r[1].dx, best_diff_12r[1].dy, log2(best_diff_12r[1].p));
		  fclose(fp);
#endif
		}
	 }
	 FILE* fp = fopen(logfile, "a");
	 if(b_hw == true) {
		fprintf(fp, "R[%2d] MAX: (%4X %4X) -> (%4X %4X) 2^%f\n", 
				  i, input_diff.dx, input_diff.dy, max_diff.dx, max_diff.dy, log2(max_diff.p));
	 } else {
		fprintf(fp, "R[%2d] MAX: (%4X %4X) -> No HW <= %d\n", 
				  i, input_diff.dx, input_diff.dy, hw_max);
	 }
	 fclose(fp);

	 printf("[%s:%d] MAX: %8X %8X 2^%f 2^%f (2^%2.0f CP) b_hw %d\n", 
			  __FILE__, __LINE__, max_diff.dx, max_diff.dy, log2(max_diff.p), log2(p_exp), log2(npairs), b_hw);
#if 0                           // DEBUG
	 printf("[%s:%d] H size = %d\n", __FILE__, __LINE__, (uint32_t)H.size());
	 assert(H.size() != 0);
	 printf("[%s:%d] G size = %d\n", __FILE__, __LINE__, (uint32_t)G.size());
	 assert(G.size() != 0);
#endif     

	 //	 printf("[%s:%d] CHECKPOINT!\n", __FILE__, __LINE__);
	 if(b_hw == 0) {
		FILE* fp = fopen(logfile, "a");
		fprintf(fp, "No HW <= %d. Exiting...\n", hw_max);
		fclose(fp);
		printf("R[%2d] No HW <= %d. Exiting...\n", i, hw_max);
		return;
	 }

	 if((i+1) == D_round) {
		(*D) = G;
	 }

	 H.clear();
	 H = G;
	 G.clear();
  }

#if 1									  // DEBUG
  printf("\n--- [%s:%d] Round [%d / %d] (%4X %4X) : T size %d, H size %d ---\n", __FILE__, __LINE__, nrounds, nrounds, input_diff.dx, input_diff.dy, (uint32_t)T->size(), (uint32_t)H.size());
#endif
#if 0									  // DEBUG
  differential_t max_diff = {0, 0, 0, 0.0};
  simon_diff_get_max(H, &max_diff);
  p_exp = simon_verify_differential_approx(key, input_diff, max_diff, nrounds, npairs);
  printf("[%s:%d] MAX: %8X %8X 2^%f 2^%f (2^%2.0f CP)\n", __FILE__, __LINE__, max_diff.dx, max_diff.dy, log2(max_diff.p), log2(p_exp), log2(npairs));
#endif

#if 1									  // DEBUG
  //	 printf("\n[%s:%s()%d] hw_max %d\n", __FILE__, __FUNCTION__, __LINE__, hw_max);
  printf("\n[%s:%s()%d] BEST 12R: (%4X %4X) -> (%4X %4X) 2^%f\n", __FILE__, __FUNCTION__, __LINE__, 
			best_diff_12r[0].dx, best_diff_12r[0].dy, best_diff_12r[1].dx, best_diff_12r[1].dy, log2(best_diff_12r[1].p));
  fp = fopen(logfile, "a");
  fprintf(fp, "[%s:%s()%d] BEST 12R: (%4X %4X) -> (%4X %4X) 2^%f\n\n", __FILE__, __FUNCTION__, __LINE__, 
			 best_diff_12r[0].dx, best_diff_12r[0].dy, best_diff_12r[1].dx, best_diff_12r[1].dy, log2(best_diff_12r[1].p));
  fclose(fp);
#endif
}

/**
 * Pre-compute the full DDT for Simon32 (16-bit words)
 * and store it in file
 */
void simon32_ddt_file_write(const char* filename,
									 std::unordered_map<uint32_t, std::vector<differential_t>>* T)
{
  assert(WORD_SIZE <= 16);
#if(WORD_SIZE <= 16)
  FILE* fp = fopen(filename, "w");

  uint32_t DX_len = ALL_WORDS;

  // fill the DDT
  std::vector<uint32_t> DX;
  for(uint32_t x = 0; x < DX_len; x++) {
	 DX.push_back(x);
  }
  assert(DX.size() == DX_len);
#if 0
  uint32_t hw = WORD_SIZE;
  simon_compute_partial_ddt(T, DX, hw);
#else
  simon_compute_full_ddt(T);
#endif

  std::unordered_map<uint32_t, std::vector<differential_t>>::const_iterator T_iter;
  for(T_iter = T->begin(); T_iter != T->end(); T_iter++) {
	 //	 std::vector<differential_t>::iterator DX_iter;
	 std::vector<differential_t> DX = T_iter->second;
	 std::vector<differential_t>::iterator DX_iter = DX.begin();
#if 1
	 //	 for(DX_iter = T_iter->second.begin(); DX_iter != T_iter->second.end(); DX_iter++) {
	 for(DX_iter = DX.begin(); DX_iter != DX.end(); DX_iter++) {
		uint32_t dx = DX_iter->dx;
		uint32_t dy = DX_iter->dy;
		double p = DX_iter->p;
		assert(dx == T_iter->first);
		fprintf(fp, "%X %X %f\n", dx, dy, p);
		printf("%X %X %f\n", dx, dy, p);
	 }
#endif
  }

  fclose(fp);
#endif  // #if(WORD_SIZE <= 16)
}

/**
 * Read a pre-compute full DDT for Simon32 (16-bit words)
 * from file and store it in a hash table
 */
void simon32_ddt_file_read(const char* filename, 
									std::unordered_map<uint32_t, std::vector<differential_t>>* T)
{
  FILE* fp = fopen(filename, "r");

  //  std::vector<differential_t> DZ;
  //  std::vector<differential_t>* DZ = (std::vector<differential_t> *)calloc(1, sizeof(std::vector<differential_t>));
  std::vector<differential_t> DZ;
  uint32_t dxx = 0;				  // last dx
  uint32_t dx = 0;
  uint32_t dy = 0;
  double p = 0.0;
  while(fscanf(fp, "%X %X %lf", &dx, &dy, &p) != EOF) {
	 if(dx != dxx) {
		std::pair<uint32_t, std::vector<differential_t>> new_pair (dxx, DZ);
		T->insert(new_pair);
		  //		DZ = (std::vector<differential_t> *)calloc(1, sizeof(std::vector<differential_t>)); // allocate new row
		  DZ.clear();
		dxx = dx;
	 }
	 differential_t diff = {dx, dy, 0, p};
	 DZ.push_back(diff);
#if 1									  // DEBUG
	 //	 printf("%X %X %f\n", dx, dy, p);
	 printf("%X %X %f\r", dx, dy, p);
	 fflush(stdout);
#endif
  }
		  //  printf("[%s:%d] Free last DZ\n", __FILE__, __LINE__);
		  //  free(DZ);
  fclose(fp);
}

/**
 * Generate a list of inputs with a given HW, none of
 * which is a rotated version of another i.e. 
 * they are rotation invariant
 */ 
void simon_gen_args_file_rot_invariant(const char* filename)
{
  uint32_t hw = 2;
  uint32_t n = WORD_SIZE;

  std::vector<uint32_t> X;
  std::vector<uint32_t> Y;
  std::unordered_map<uint32_t, differential_t> A;

  uint32_t cnt = gen_word_hw(n, hw, &X);
  std::sort(X.begin(), X.end());
  Y = X;

  std::vector<uint32_t>::iterator X_iter;
  std::vector<uint32_t>::iterator Y_iter;
  for(X_iter = X.begin(); X_iter != X.end(); X_iter++) {
	 for(Y_iter = Y.begin(); Y_iter != Y.end(); Y_iter++) {
		uint32_t dx = *X_iter;
		uint32_t dy = *Y_iter;
		if((dx == 0) && (dy == 0))
		  continue;

		differential_t new_diff = {dx, dy, 0, 0.0};
		uint32_t new_diff_key = differential_to_num(new_diff);

		std::pair<uint32_t, differential_t> new_pair (new_diff_key, new_diff);
		A.insert(new_pair);

	 }
  }
  assert(A.size() == ((cnt * cnt) - 1));

  std::vector<differential_t> V;

  uint32_t A_size_old = (uint32_t)A.size();
  std::unordered_map<uint32_t, differential_t>::iterator A_iter = A.begin();
  while(A_iter != A.end()) {
	 uint32_t dx = A_iter->second.dx;
	 uint32_t dy = A_iter->second.dy;
	 differential_t diff = {dx, dy, 0, 0.0};
	 V.push_back(diff);
#if 0									  // DEBUG
	 printf("[%s:%d] (%4X %4X):\n", __FILE__, __LINE__, dx, dy);
#endif
	 for(uint32_t i = 1; i < n; i++) {
		uint32_t dx_rot = LROT(dx, i);
		uint32_t dy_rot = LROT(dy, i);
		differential_t diff_rot = {dx_rot, dy_rot, 0, 0.0};
		uint32_t diff_rot_key = differential_to_num(diff_rot);
		uint32_t nerased = 0;
		if(!((dx_rot == dx) && (dy_rot == dy))) {
		  nerased = A.erase(diff_rot_key);
		}
		if(nerased) {
#if 0									  // DEBUG
		  printf("Erase %d: (%4X %4X)\n", nerased, dx_rot, dy_rot);
#endif
		}
	 }
	 A_iter++;
  }
  printf("[%s:%d] %d %d\n", __FILE__, __LINE__, (uint32_t)V.size(), (uint32_t)A.size());
  assert(V.size() == A.size());

  std::sort(V.begin(), V.end(), simon_comp_differentials_diffs);
  FILE* fp = fopen(filename, "w");
  std::vector<differential_t>::iterator V_iter;
  cnt = 0;
  for(V_iter = V.begin(); V_iter != V.end(); V_iter++) {
	 uint32_t dx = V_iter->dx;
	 uint32_t dy = V_iter->dy;
	 cnt++;
#if 0									  // DEBUG
	 printf("%5d: (%4X %4X)\n", cnt, dx, dy);
#endif
	 fprintf(fp, "%d %d\n", dx, dy);
  }
  fclose(fp);

  uint32_t A_size_new = (uint32_t)A.size();
  printf("[%s:%d] A size reduced: %d -> %d\n", __FILE__, __LINE__, A_size_old, A_size_new);
}

void simon_gen_args_file(const char* argfile)
{
  uint32_t hw = 2;
  uint32_t n = WORD_SIZE;

  std::vector<uint32_t> X;
  std::vector<uint32_t> Y;

  uint32_t cnt_1 = gen_word_hw(n, hw, &X);
#if 1									  // DEBUG
  uint32_t cnt_2 = gen_word_hw_all(n, hw);
  assert(cnt_1 == cnt_2);
#endif

  //  std::sort(X.begin(), X.end(), std::greater<int>());
  std::sort(X.begin(), X.end());

  Y = X;

  uint32_t max_cnt = 1000;//(1ULL << 31); // !!!
  std::vector<uint32_t>::iterator X_iter;
  std::vector<uint32_t>::iterator Y_iter;
  uint32_t cnt = 0;
  uint32_t num_tot = 0;

  char filename[0xFFFF] = {0};
  uint32_t file_cnt = 1;
  sprintf(filename, "%s-%d.txt", argfile, file_cnt);
  FILE* fp = fopen(filename, "w");

  for(X_iter = X.begin(); X_iter != X.end(); X_iter++) {
	 for(Y_iter = Y.begin(); Y_iter != Y.end(); Y_iter++) {
		uint32_t dx = *X_iter;
		uint32_t dy = *Y_iter;
		if((dx == 0) && (dy == 0))
		  continue;
		if(cnt > max_cnt) {
		  fclose(fp);
		  cnt = 0;
		  file_cnt++;
		  memset(filename, 0, 0xFFFF);
		  sprintf(filename, "%s-%d.txt", argfile, file_cnt);
		  fp = fopen(filename, "w");
		}
		cnt++;
		num_tot++;
		fprintf(fp, "%d %d\n", dx, dy);
#if 0									  // DEBUG
		printf("[%10d] %4X %4X\n", cnt, dx, dy);
#endif
		assert(hw32(dx) <= hw);
		assert(hw32(dy) <= hw);
	 }
  }
  fclose(fp);
  uint32_t all = ((uint32_t)X.size() * (uint32_t)Y.size()) - 1;
  printf("[%s:%d] Generated args file: num_inputs %d %d 2^%f\n", __FILE__, __LINE__, all, num_tot, log2(num_tot));
  assert(num_tot == all);
  //  printf("\n[%s:%d] %d %d %d %d\n", __FILE__, __LINE__, x_cnt, (uint32_t)X.size(), y_cnt, (uint32_t)Y.size()); 
}



/*
 * ---------------------------------------------------------------------
 * END Full search for differentials for Simon32 (16 bit words) limited
 *     to all words of max Hamming weight 5
 * ---------------------------------------------------------------------
 */ 
