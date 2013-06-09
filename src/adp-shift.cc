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
 * \file  adp-shift.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The ADD differential probability of left shift (LSH): \f$\mathrm{adp}^{\ll}\f$ 
 *        and right shift (RSH): \f$\mathrm{adp}^{\gg}\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_SHIFT_H
#include "adp-shift.hh"
#endif

// --- ADP_LSH ---

/** 
 * The ADD differential probability of \f$({\ll})\f$ (LSH) computed
 * experimentally over all inputs. Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param l shift constant.
 * \returns \f$\mathrm{adp}^{\ll}(l |~ da \rightarrow db)\f$.
 * \see adp_lsh
 */ 
double adp_lsh_exper(uint32_t da, uint32_t db, int l)
{
  assert(l < WORD_SIZE);
  uint64_t cnt = 0;

  uint64_t n = 1ULL << WORD_SIZE;

  for(uint32_t i = 0; i < n; i++) {
	 uint32_t a = i;
	 uint32_t b = (a << l) & MASK;
	 uint32_t aa = (a + da) & MASK;
	 uint32_t bb = (aa << l) & MASK;
	 uint32_t delta = ((bb - b) + (1ULL << WORD_SIZE))  % (1ULL << WORD_SIZE);

	 assert(aa <= MASK);
	 assert(delta <= MASK);

	 if(delta == db)
		cnt++;
  }
  double p = (double)cnt / (double)n;

  return p;
}

/** 
 * The ADD differential probability of \f$({\ll})\f$ (LSH). Complexity: \f$O(1)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param l shift constant.
 * \returns \f$\mathrm{adp}^{\ll}(l |~ da \rightarrow db)\f$.
 * \see adp_lsh_exper
 */ 
double adp_lsh(uint32_t da, uint32_t db, int l)
{
  double p = 0.0;
  uint32_t delta = (da << l) & MASK;
  if(delta == db)
	 p = 1.0;
  //  printf("%8X\n", delta);
  return p;
}

// --- ADP_RSH ---

/** 
 * The ADD differential probability of \f$({\gg})\f$ (RSH) computed
 * experimentally over all inputs. Complexity: \f$O(2^n)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param r shift constant.
 * \returns \f$\mathrm{adp}^{\gg}(r |~ da \rightarrow db)\f$.
 * \see adp_rsh
 */ 
double adp_rsh_exper(const uint32_t da, const uint32_t db, const int r)
{
  assert(r < WORD_SIZE);
  uint64_t cnt = 0;

  uint64_t n = 1ULL << WORD_SIZE;

  for(uint32_t i = 0; i < n; i++) {
	 uint32_t a = i;
	 uint32_t aa = (a + da) % MOD;

	 assert(((aa - a + MOD) % MOD) == da);

	 uint32_t b = (a >> r);
	 uint32_t bb = (aa >> r);

	 uint32_t delta = ((bb - b) + MOD) % MOD;

#if 1									  // DEBUG
	 uint32_t da_l = da >> r; // (n - r) MSBs
	 uint32_t da_r = da & ~(0xffffffff << r); // r LSBs

	 uint32_t t = (da_l * (1UL << r) + da_r);
	 assert(t == da);

	 uint32_t cr = 1;
	 uint32_t cl = (1UL << (WORD_SIZE - r)); // 2^{n-r}

	 //	 printf("cl = %d, cr = %d\n", cl, cr);
	 uint32_t dx_0 = ((da_l + 0 - 0) + MOD) % MOD;
	 uint32_t dx_1 = ((da_l + 0 - cl) + MOD) % MOD;
	 uint32_t dx_2 = ((da_l + cr - 0) + MOD) % MOD;
	 uint32_t dx_3 = ((da_l + cr - cl) + MOD) % MOD;

	 assert((delta == dx_0) || (delta == dx_1) || (delta == dx_2) || (delta == dx_3));
#endif

	 if(delta == db) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)n;

  return p;
}

/**
 * Compute the set of possible output differences dx after a right shift by r
 * \param da input difference.
 * \param r shift constant.
 * \param dx the set of all 4 possible output differences.
 */ 
void adp_rsh_odiffs(uint32_t dx[4], const uint32_t da, int r)
{
  uint32_t cr = 1;
  uint32_t cl = (1UL << (WORD_SIZE - r));
  uint32_t da_l = RSH(da, r);
  dx[0] = ((da_l + 0 - 0) + MOD) % MOD;
  dx[1] = ((da_l + 0 - cl) + MOD) % MOD;
  dx[2] = ((da_l + cr - 0) + MOD) % MOD;
  dx[3] = ((da_l + cr - cl) + MOD) % MOD;
}

/* ADP-RSH probabilities
\begin{equation}
\mathrm{adp}^{\gg r}(\alpha \rightarrow \beta) =
\begin{cases}
2^{-n} (2^{n - r} - \alpha_{\mathrm{L}}) (2^{r} - \alpha_{\mathrm{R}})\enspace, & \beta = (\alpha \gg r)\enspace,\\
2^{-n} \alpha_{\mathrm{L}}(2^{r} - \alpha_{\mathrm{R}})\enspace, & \beta = (\alpha \gg r) - 2^{n - r}\enspace,\\
2^{-n} \alpha_{\mathrm{R}} (2^{n - r} - \alpha_{\mathrm{L}} - 1)\enspace, & \beta = (\alpha \gg r) + 1\enspace,\\
2^{-n} (\alpha_{\mathrm{L}} + 1) \alpha_{\mathrm{R}}\enspace, & \beta = (\alpha \gg r) - 2^{n - r} + 1\enspace.
\end{cases}\enspace,\label{eq:adp-rsh}
\end{equation}
*/

/** 
 * The ADD differential probability of \f$({\gg})\f$ (RSH). Complexity: \f$O(1)\f$.
 *
 * \param da input difference.
 * \param db output difference.
 * \param r shift constant.
 * \returns \f$\mathrm{adp}^{\gg}(r |~ da \rightarrow db)\f$.
 * \see adp_rsh_exper
 *
 * \note \f$db \in \{(da \gg 5), (da \gg 5) + 1, (da \gg 5) - 2^{n-5}, (da \gg 5) - 2^{n-5} + 1\}\f$.
 * 
 */ 
double adp_rsh(uint32_t da, uint32_t db, int r)
{
  uint32_t n = WORD_SIZE;
  double p = 0.0;
  double probs[4] = {0.0, 0.0, 0.0, 0.0};

  uint64_t all = (1ULL << n);		  // all

  uint32_t da_l = da >> r; // (n - r) MSBs
  uint32_t da_r = da & ~(0xffffffff << r); // r LSBs

#if 1
  uint32_t t = (da_l * (1UL << r) + da_r);
  assert(t == da);
#endif

  uint32_t cr = 1;
  uint64_t cl = (1ULL << (WORD_SIZE - r)); // 2^{n-r}

  //  printf("cl = %d, cr = %d\n", cl, cr);

  uint32_t dx[4] = {0, 0, 0, 0};

  dx[0] = ((da_l + 0 - 0) + MOD) % MOD;
  dx[1] = ((da_l + 0 - cl) + MOD) % MOD;
  dx[2] = ((da_l + cr - 0) + MOD) % MOD;
  dx[3] = ((da_l + cr - cl) + MOD) % MOD;

#if 0									  // fixes a bug? - check!
  if(r == 0)
	 return 1.0;
#endif

#if 0
  if((db != dx[0]) && (db != dx[1]) && (db != dx[2]) && (db != dx[3])) {
	 p = 0.0;
  } else 
#endif
	 {

		uint64_t al[4], ar[4];

		assert(n == WORD_SIZE);

		// cl = 0, cr = 0
		al[0] = (1ULL << (n - r)) - da_l;
		ar[0] = (1ULL << r) - da_r;

		// cl = 1, cr = 0
		al[1] = da_l;
		ar[1] = (1ULL << r) - da_r;

		// cl = 0, cr = 1
		al[2] = (1ULL << (n - r)) - da_l - 1;
		ar[2] = da_r;

		// cl = 1, cr = 1
		al[3] = da_l + 1;
		ar[3] = da_r;

		//	 	 printf("al = %d, ar = %d, al * ar = %d, all = %d\n", al, ar, al * ar, all);
		double sump = 0.0;
		for(int i = 0; i < 4; i++) {

		  double nom = 0.0;

		  nom = (double)(al[i] * ar[i]);

		  //		printf("nom = %f, all = %lx\n", nom, all);
		  assert(all != 0);
		  probs[i] = (double)(nom) / (double)(all);
		  assert(al[i] >= 0);
		  assert(ar[i] >= 0);
		  assert((probs[i] >= 0) && (probs[i] <= 1.0));

		  if(db == dx[i])
			 p += probs[i];

		  sump += probs[i];

		}
#if 1
		if(sump != 1.0) {
		  printf("[%s:%d] WARNING! sum != 1.0 = %31.30f\n", __FILE__, __LINE__, sump);
		}
#endif

		assert(sump == 1.0);

	 }
  //  p = probs[0];

  assert((p >= 0.0) && (p <= 1.0));

  return p;
}

