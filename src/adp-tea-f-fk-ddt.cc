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
 * \file  adp-tea-f-fk-ddt.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Computing the full difference distribution table (DDT) for the F-function 
 *        of block cipher TEA by exaustive search over all inputs. Complexity \f$O(2^{2n})\f$.
 *
 * All functions in this file have exponential complexity in the word size. They are useful only 
 * for verifying other computations on small word sizes, typically \f$n \le 10\f$.
 *
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef TEA_H
#include "tea.hh"
#endif

/**
 * Sort every row by decreasing number of right pairs.
 * \param T a difference distribution table (DDT).
 */
void ddt_sort_rows(differential_t** T)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 std::sort(T[dx], T[dx] + ALL_WORDS);
  }
}

/** 
 * Compare two rows in a row-sorted DDT by their first (max) element.
 * Assumes that the elemnets in a row are sorted in descending order.
 * \param a row of differentials in a DDT.
 * \param b row of differentials in a DDT.
 */ 
bool comp_rows(differential_t* a, differential_t* b)
{
  bool b_less = (a[0].p > b[0].p);	  // higher probability first
  return b_less;
}

/** 
 * Sorts the rows of a difference distribution table (DDT) 2D 
 * by the probability of the elements in the first column --
 * highest probability first.

 * \param T a difference distribution table (DDT). 
 */ 
void ddt_sort_first_col(differential_t** T)
{
  std::sort(&T[0], (&T[0]) + ALL_WORDS, comp_rows);
}

/**
 * Convert a DDT to a list of differentials.
 *
 * \param DDT difference distribution table.
 * \param SDDT list of differentials.
 */
void ddt_to_list(uint32_t** DDT, differential_t* SDDT)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		uint64_t idx = (dx * ALL_WORDS) + dy;
		SDDT[idx].dx = dx;
		SDDT[idx].dy = dy;
		SDDT[idx].npairs = DDT[dx][dy];
		SDDT[idx].p = (double)DDT[dx][dy] / (double)(ALL_WORDS);
	 }
  }
}

/**
 * Convert a DDT to 2D array of differentials.
 *
 * \param DDT difference distribution table.
 * \param SDDT array differentials.
 */
void ddt_to_diff_struct(uint32_t** DDT, differential_t** SDDT)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		SDDT[dx][dy].dx = dx;
		SDDT[dx][dy].dy = dy;
		SDDT[dx][dy].npairs = DDT[dx][dy];
		SDDT[dx][dy].p = (double)DDT[dx][dy] / (double)(ALL_WORDS);
#if 1									  // EDBUG
		assert(DDT[dx][dy] <= ALL_WORDS);
		assert(SDDT[dx][dy].npairs <= ALL_WORDS);
		assert(SDDT[dx][dy].p <= 1.0);
#endif
	 }
  }
}

/**
 * Sort all elements of a DDT, represented as a 1D list of differentials,
 * in descending order by the number of right pairs.
 * \param SDDT DDT as a 1D list of differentials.
 */
void ddt_sort(differential_t* SDDT)
{
  std::sort(SDDT, SDDT + (ALL_WORDS * ALL_WORDS));
}

/**
 * Print the elements of a DDT.
 * \param RSDDT DDT as a 2D list of differentials.
 */
void print_rsddt(differential_t** RSDDT)
{
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		uint32_t dx = RSDDT[i][j].dx;
		uint32_t dy = RSDDT[i][j].dy;
		uint32_t rp = RSDDT[i][j].npairs;
		double p = RSDDT[i][j].p;
		printf("[%s:%d] %2d : %8X -> %8X | %5d | %f\n", __FILE__, __LINE__, i, dx, dy, rp, p);
	 }
  }
}

/**
 * Print the elements of a DDT.
 * \param SDDT DDT as a 1D list of differentials.
 */
void print_sddt(differential_t* SDDT)
{
  uint64_t N = (ALL_WORDS * ALL_WORDS);
  for(uint32_t i = 0; i < N; i++) {
	 uint32_t dx = SDDT[i].dx;
	 uint32_t dy = SDDT[i].dy;
	 uint32_t rp = SDDT[i].npairs;
	 double p = SDDT[i].p;
	 printf("[%s:%d] %5d: %8X -> %8X | %5d | %f\n", __FILE__, __LINE__, i, dx, dy, rp, p);
  }
}

/**  
 * Compute the ADD differential probability of the TEA F-function for a fixed key and
 * round constants (\f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$) 
 * by exhaustive searc over all inputs. Complexity \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$.
 */
double adp_f_exper_fixed_key_all(const uint32_t da, const uint32_t db, 
											const uint32_t k0, const uint32_t k1, const uint32_t delta,
											uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;// * ALL_WORDS * ALL_WORDS * ALL_WORDS;
  uint32_t cnt = 0;

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = tea_f(a1, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t b2 = tea_f(a2, k0, k1, delta, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);
	 if(dx == db) {
		cnt++;
	 } 
  }
  double p = (double)cnt / (double)N;
  return p;
}

/**  
 * For a fixed input difference to the TEA F-function compute 
 * the maximum probability output ADD difference
 * for a fixed key and round constant by exhaustive search over all inputs
 * and output differences. Complexity \f$O(2^{2n})\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns \f$\max_{dd} \mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$.
 * \see max_adp_f_ddt, max_adp_f_rsddt
 */
double max_adp_f_exper_fixed_key_all(const uint32_t da, uint32_t* db, 
												 const uint32_t k0, const uint32_t k1, const uint32_t delta,
												 uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t N = ALL_WORDS;
  uint32_t db_max = 0;
  uint32_t D[ALL_WORDS];

  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 D[i] = 0;
  }

  for(uint32_t a1 = 0; a1 < ALL_WORDS; a1++) {

	 uint32_t a2 = ADD(a1, da);

	 uint32_t b1 = tea_f(a1, k0, k1, delta, lsh_const, rsh_const);
	 uint32_t b2 = tea_f(a2, k0, k1, delta, lsh_const, rsh_const);

	 uint32_t dx = SUB(b2, b1);

	 D[dx]++;

  }

  double p_max = 0.0;
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 double p = (double)D[i] / (double)N;
	 if(p > p_max) {
		p_max = p;
		db_max = i;
	 }
  }
  *db = db_max;
  return p_max;
}

/**
 * Allocate memory for a DDT as a 2D array of differentials.
 * \returns a DDT as a 2D array of differentials.
 * \see rsddt_free
 */
differential_t** rsddt_alloc()
{
#if(WORD_SIZE <= 10)
  differential_t** T;
  T = (differential_t **)calloc(ALL_WORDS, sizeof(differential_t *));
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 T[i] = (differential_t *)calloc(ALL_WORDS, sizeof(differential_t));
  }
  return T;
#else
  return NULL;
#endif  // #if(WORD_SIZE <= 10)
}

/**
 * Free the memory reserved for a DDT as a 2D array of differentials.
 * \param T a DDT as a 2D array of differentials.
 * \see rsddt_alloc
 */
void rsddt_free(differential_t** T)
{
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 free(T[i]);
  }
  free(T);
}

/**
 * Allocate memory for a DDT as a 1D array of differentials.
 * \returns a DDT as a 1D array of differentials.
 * \see sddt_free
 */
differential_t* sddt_alloc()
{
  differential_t* ST;
  ST = (differential_t *)calloc((size_t)(ALL_WORDS * ALL_WORDS), sizeof(differential_t));
  return ST;
}

/**
 * Free the memory reserved for a DDT as a 1D array of differentials.
 * \param ST a DDT as a 1D array of differentials.
 * \see sddt_alloc
 */
void sddt_free(differential_t* ST)
{
  free(ST);
}

/**
 * Allocate memory for a DDT as a 2D array containingg number of rigt pairs.
 * \returns a DDT as a 2D array containing number of rigt pairs.
 * \see ddt_free
 */
uint32_t** ddt_alloc()
{
#if(WORD_SIZE <= 10)
  uint32_t** T;
  T = (uint32_t **)calloc(ALL_WORDS, sizeof(uint32_t *)); // !!!
#if 0																		 // DEBUG
  printf("sizeof(uint32_t) = %ld, sizeof(uint32_t *) = %ld\n", sizeof(uint32_t), sizeof(uint32_t *));
#endif
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 T[i] = (uint32_t *)calloc(ALL_WORDS, sizeof(uint32_t));
  }
  return T;
#else
  return NULL;
#endif  // #if(WORD_SIZE <= 10)
}

/**
 * Free the memory reserved for a DDT as a 2D array containingg number of rigt pairs.
 * \param T a DDT as a 2D array containing number of rigt pairs.
 * \see ddt_alloc
 */
void ddt_free(uint32_t** T)
{
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 free(T[i]);
  }
  free(T);
}

/**
 * Compute the full difference distribution table (DDT) for the F-function 
 * of block cipher TEA for a fixed key and round constant, 
 * by exaustive search over all input values and differences. Complexity \f$O(2^{2n})\f$.
 *
 * \param T a DDT as a 2D array containing number of right pairs..
 * \param k0 first round key.
 * \param k1 second round key.
 * \param delta round constant.
 * \param lsh_const LSH constant.
 * \param rsh_const RSH constant.
 * \returns full DDT for the TEA F-function.
 *
 */
void ddt_f(uint32_t** T, uint32_t k0, uint32_t k1, uint32_t delta, uint32_t lsh_const, uint32_t rsh_const)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t x1 = 0; x1 < ALL_WORDS; x1++) {

		uint32_t x2 = ADD(x1, dx);
		uint32_t y1 = tea_f(x1, k0, k1, delta, lsh_const, rsh_const);
		uint32_t y2 = tea_f(x2, k0, k1, delta, lsh_const, rsh_const);
		uint32_t dy = SUB(y2, y1);
		T[dx][dy]++;
#if 1									  // DEBUG
		assert(T[dx][dy] <= ALL_WORDS);
#endif
	 }
  }
}

/**
 * Print the entries of a DDT.
 * \param T DDT.
 */
void ddt_print(uint32_t** T)
{
  for(uint32_t dx = 0; dx < ALL_WORDS; dx++) {
	 for(uint32_t dy = 0; dy < ALL_WORDS; dy++) {
		uint32_t np = T[dx][dy];
#if 1
		printf("%2d ", np);
#else
		double p = (double)np / (double)(ALL_WORDS);
		printf("%f ", p);
#endif
		assert(np <= (ALL_WORDS));
	 }
	 printf("\n");
  }
}

/**
 * Compute the ADD differential probability of the TEA F-function 
 * from the full DDT, precomputed for a a fixed key and round constant.
 *
 * \param DDT DDT.
 * \param dx input difference.
 * \param dy output difference.
 * \returns DDT[da][db] = \f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$.
 * \see adp_f_exper_fixed_key_all
 */
double adp_f_ddt(uint32_t** DDT, uint32_t dx, uint32_t dy)
{
  uint32_t np = DDT[dx][dy];
  double p = (double)np / (double)(ALL_WORDS);
  return p;
}

/**
 * For a fixed input difference to the TEA F-function compute 
 * the maximum probability output ADD difference
 * from the full DDT, precomputed for a fixed key and round constant.
 * Complexity \f$O(1)\f$.
 *
 * \param DDT DDT.
 * \param dx input difference.
 * \param dy maximum probability output difference.
 * \returns \f$\max_{dd} \mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_adp_f_exper_fixed_key_all
 */
double max_adp_f_ddt(uint32_t** DDT, uint32_t dx, uint32_t* dy)
{
  uint32_t dy_max = 0;
  uint32_t np_max = 0;
  for(uint32_t i = 0; i < ALL_WORDS; i++) {
	 if(np_max < DDT[dx][i]) {
		np_max = DDT[dx][i];
		dy_max = i;
	 }
  }
  *dy = dy_max;
  double p = (double)np_max / (double)(ALL_WORDS);
  return p;
}

/**
 * For a fixed input difference to the TEA F-function compute 
 * the maximum probability output ADD difference from the full DDT 
 * represented as a 2D array of differentials. In this 
 * DDT the differentials in every row are sorted by decreasing probability.
 * Complexity \f$O(1)\f$.
 *
 * \param TS a DDT in which the differentials in every row are sorted by 
 *        decreasing number of probability.
 * \param dx input difference.
 * \param dy maximum probability output difference.
 * \returns TS[dx][0] = \f$\max_{dd} \mathrm{adp}^{F}(k_0, k_1, \delta |~ dx \rightarrow dy)\f$.
 * \see max_adp_f_ddt, max_adp_f_exper_fixed_key_all
 */
double max_adp_f_rsddt(differential_t** TS, uint32_t dx, uint32_t* dy)
{
  // max is the first elemenst (index 0)
  uint32_t dy_max = TS[dx][0].dy;
  uint32_t np_max = TS[dx][0].npairs;
  *dy = dy_max;
#if 0									  // DEBUG
  if(np_max > ALL_WORDS) {
	 printf("[%s:%d] %d %lld\n", __FILE__, __LINE__, np_max, ALL_WORDS);
  }
#endif
  assert(np_max <= ALL_WORDS);
  double p = (double)np_max / (double)(ALL_WORDS);
#if 0									  // DEBUG
  if(p > 1.0) {
	 printf("[%s:%d] %d %lld %f\n", __FILE__, __LINE__, np_max, ALL_WORDS, p);
  }
#endif
  assert((p >= 0.0) && (p <= 1.0));
  return p;
}

// --- extended DDT (XDDT) -- separate ddt for each delta ---

/**
 * Allocate memory for a an array of \ref NDELTA DDTs. Each DDT represents a 2D array containing
 * numbers of rigt right pairs and generated for a fixed value of the \f$\delta\f$ constant of the TEA F-function.
 * \returns array of DDTs: each DDT represents a 2D array containing number of right pairs.
 */
uint32_t*** xddt_alloc()
{
#if(WORD_SIZE <= 10)
  uint32_t*** T;
  T = (uint32_t ***)calloc(NDELTA, sizeof(uint32_t **)); // !!!
  for(uint32_t i = 0; i < NDELTA; i++) {
	 T[i] = (uint32_t **)calloc(ALL_WORDS, sizeof(uint32_t *)); // !!!
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		T[i][j] = (uint32_t *)calloc(ALL_WORDS, sizeof(uint32_t));
	 }
  }
  return T;
#else
  return NULL;
#endif  // #if(WORD_SIZE <= 10)
}

/**
 * Free the memory reserved from a previous call to xddt_alloc()
 * \param T an array of DDTs: each DDT is a 2D array containing number of right pairs.
 */
void xddt_free(uint32_t*** T)
{
  for(uint32_t i = 0; i < NDELTA; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		free(T[i][j]);
	 }
	 free(T[i]);
  }
  free(T);
}

/**
 * Allocate memory for a an array of \ref NDELTA DDTs. Each DDT represents a 2D array of differentials,
 * generated for a fixed value of the \f$\delta\f$ constant of the TEA F-function.
 * \returns array of DDTs: each DDT represents a 2D array of differentials.
 */
differential_t*** xrsddt_alloc()
{
#if(WORD_SIZE <= 10)
  differential_t*** T;
  T = (differential_t ***)calloc(NDELTA, sizeof(differential_t **));
  for(uint32_t i = 0; i < NDELTA; i++) {
	 T[i] = (differential_t **)calloc(ALL_WORDS, sizeof(differential_t *));
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		T[i][j] = (differential_t *)calloc(ALL_WORDS, sizeof(differential_t));
	 }
  }
  return T;
#else
  return NULL;
#endif  // #if(WORD_SIZE <= 10)
}

/**
 * Free the memory reserved from a previous call to xrsddt_alloc()
 * \param T an array of DDTs: each DDT is a 2D array of differentials.
 */
void xrsddt_free(differential_t*** T)
{
  for(uint32_t i = 0; i < NDELTA; i++) {
	 for(uint32_t j = 0; j < ALL_WORDS; j++) {
		free(T[i][j]);
	 }
	 free(T[i]);
  }
  free(T);
}

/**
 * Allocate memory for a an array of \ref NDELTA DDTs. Each DDT represents a 1D list of differentials,
 * generated for a fixed value of the \f$\delta\f$ constant of the TEA F-function.
 * \returns array of DDTs: each DDT represents a 1D list of differentials,
 */
differential_t** xsddt_alloc()
{
  differential_t** ST;
  ST = (differential_t **)calloc(NDELTA, sizeof(differential_t *));
  for(uint32_t i = 0; i < NDELTA; i++) {
	 ST[i] = (differential_t *)calloc((size_t)(ALL_WORDS * ALL_WORDS), sizeof(differential_t));
  }
  return ST;
}

/**
 * Free the memory reserved from a previous call to xrsddt_free()
 * \param ST an array of DDTs: each DDT is a 1D list of differentials.
 */
void xsddt_free(differential_t** ST)
{
  for(uint32_t i = 0; i < NDELTA; i++) {
	 free(ST[i]);
  }
  free(ST);
}
