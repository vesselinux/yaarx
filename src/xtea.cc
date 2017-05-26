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
 * \file  xtea.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Common functions used in the analysis of block cipher XTEA.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XTEA_H
#include "xtea.hh"
#endif

/**
 * Round-reduced version of block cipher XTEA. Reference: https://en.wikipedia.org/wiki/XTEA.
 *
 * \param nrounds number of rounds (1 \f$\le\f$ \p nrounds \f$\le\f$ 64).
 * \param v plaintext.
 * \param k secret key.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 *
 */
void xtea_r(uint32_t nrounds, uint32_t v[2], uint32_t const k[4], uint32_t lsh_const, uint32_t rsh_const) 
{
  uint32_t num_rounds = 32;
  uint32_t v0=v[0], v1=v[1], sum=0, delta=DELTA_INIT;
  uint32_t R = nrounds - 1;							 // counts from 0 !!
  for(uint32_t i=0; i < num_rounds; i++) {
#if 0									  // DEBUG
	 printf("[%s:%s():%d] K[%d] %8X %8X\n", __FILE__, __FUNCTION__, __LINE__, sum & 3, k[sum & 3], sum & MASK);
#endif
	 uint32_t key = k[sum & 3];
	 uint32_t lv1 = LSH(v1, lsh_const);
	 uint32_t rv1 = RSH(v1, rsh_const);
	 uint32_t new_v0 = ADD((lv1 ^ rv1), v1) ^ (ADD(sum, key));
	 new_v0 = ADD(v0, new_v0);
	 v0 += ((((v1 << lsh_const) ^ (v1 >> rsh_const)) + v1) & MASK) ^ ((sum + k[sum & 3]) & MASK);
	 v0 &= MASK;
	 if(v0 != new_v0) {
		printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, v0, new_v0);
	 }
	 assert(v0 == new_v0);
	 if(R == (2*i)) {
		break;
	 }
	 sum += delta;
	 //	 sum = ADD(sum, delta);
#if 0									  // DEBUG
	 printf("[%s:%s():%d] K[%d] %8X %8X\n", __FILE__, __FUNCTION__, __LINE__, (sum>>11) & 3, k[(sum>>11) & 3], sum & MASK);
#endif
	 key = k[(sum>>11) & 3];
	 uint32_t lv0 = LSH(v0, lsh_const);
	 uint32_t rv0 = RSH(v0, rsh_const);
	 uint32_t new_v1 = ADD((lv0 ^ rv0), v0) ^ (ADD(sum, key));
	 new_v1 = ADD(v1, new_v1);
	 v1 += (((v0 << lsh_const) ^ (v0 >> rsh_const)) + v0) ^ (sum + k[(sum>>11) & 3]);
	 v1 &= MASK;
	 if(v1 != new_v1) {
		printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, v1, new_v1);
	 }
	 assert(v1 == new_v1);
	 if(R == (2*i + 1)) {
		break;
	 }
  }
  v[0]=v0; v[1]=v1;
}

/**
 * The F-function of block cipher XTEA:
 *	\f$ F(x)  = ((((x \ll 4) \oplus (x \gg 5)) + x) \oplus (k + \delta)\f$.
 *
 * \param x input to  \f$F\f$.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \return \f$F(x)\f$
 */ 
uint32_t xtea_f(uint32_t x, uint32_t k, uint32_t delta, 
					 uint32_t lsh_const, uint32_t rsh_const)
{
  uint32_t x_lsh = LSH(x, lsh_const);
  uint32_t x_rsh = RSH(x, rsh_const);

  //  v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
  uint32_t y = ADD((x_lsh ^ x_rsh), x) ^ ADD(delta, k);

  return y;
}

/**
 * The F-function of block cipher XTEA (\ref xtea_f) computed on
 * the first \p i least-significant (LS) bits.
 *
 * \param mask_i \p i bit LSB mask.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \param x_in input to  \f$F\f$.
 * \param k round key.
 * \param delta round constant.
 * \return \f$F(x)~ \mathrm{mod}~ 2^i\f$
 *
 * \attention the initial value \p x_in must be minimum 
 *            (\p rsh_const + 1) bits long so that it can be shifted 
 *            right by \p rsh_const positions.
 *
 * \see xtea_f_lxr_i()
 */ 
uint32_t xtea_f_i(const uint32_t mask_i, 
						const uint32_t lsh_const, const uint32_t rsh_const,
						const uint32_t x_in, const uint32_t k, const uint32_t delta)
{
  uint32_t x = x_in;
  uint32_t x_lsh = LSH(x, lsh_const) & mask_i;
  uint32_t x_rsh = RSH(x, rsh_const) & mask_i;

  //  v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
  uint32_t y = (ADD((x_lsh ^ x_rsh), x) ^ ADD(delta, k)) & mask_i;
  return y;
}

/**
 * The F-function of block cipher XTEA including the modular addition with 
 * the input to the previous Fesitel round. It is denoted by \f$F'\f$ and is defined as:
 *
 *	\f$ F'(xx, x)  = xx + F(x)\f$, 
 *
 * where \f$F(x)\f$ is the XTEA F-function (\ref xtea_f).
 *
 * \param x first input to \f$F'\f$.
 * \param xx second input to \f$F'\f$.
 * \param k round key.
 * \param delta round constant.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \return \f$F(x, xx)\f$
 */ 
uint32_t xtea_f2(uint32_t xx, uint32_t x, uint32_t k, uint32_t delta, 
					  uint32_t lsh_const, uint32_t rsh_const)
{
  //  v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
  uint32_t y = xtea_f(x, k, delta, lsh_const, rsh_const);
  y = ADD(y, xx);
  return y;
}

/**
 * The F'-function of block cipher XTEA (\ref xtea_f2) computed on
 * the first \p i least-significant (LS) bits.
 *
 * \param mask_i \p i bit LSB mask.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \param x_in first input to \f$F'\f$.
 * \param xx_in second input to \f$F'\f$.
 * \param k round key.
 * \param delta round constant.
 * \return \f$F'(x,xx)~ \mathrm{mod}~ 2^i\f$
 *
 * \attention the initial values \p x_in and \p xx_in must be minimum 
 *            (\p rsh_const + 1) bits long so that it can be shifted 
 *            right by \p rsh_const positions.
 *
 * \see xtea_f_i()
 */ 
uint32_t xtea_f2_i(const uint32_t mask_i, 
						 const uint32_t lsh_const, const uint32_t rsh_const,
						 const uint32_t xx_in, const uint32_t x_in, 
						 const uint32_t k, const uint32_t delta)
{
  //  v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
  uint32_t y = xtea_f_i(mask_i, lsh_const, rsh_const, x_in, k, delta);
  y = ADD(y, xx_in) & mask_i;
  return y;
}

/**
 * This function represents a sub-component of the XTEA F-function
 * denoted by \f$f_{\mathrm{LXR}}\f$ and defined as:
 *	 \f$ f_{\mathrm{LXR}}(x) = (((x \ll 4) \oplus (x \gg 5)) \f$.
 *
 * \note With \f$f_{\mathrm{LXR}}\f$, the F-function of XTEA (\ref xtea_f) is expressed as:
 *	      \f$ F(x)  = (f_{\mathrm{LXR}}(x) + x) \oplus (k + \delta)\f$.
 *
 * \param x input to  \f$f_{\mathrm{LXR}}\f$.
 * \param lsh_const LSH constant (default is 4).
 * \param rsh_const RSH constant (default is 5).
 * \return \f$f_{\mathrm{LXR}}(x)\f$
 */ 
uint32_t xtea_f_lxr(uint32_t x, uint32_t lsh_const, uint32_t rsh_const)
{
  uint32_t x_lsh = LSH(x, lsh_const);
  uint32_t x_rsh = RSH(x, rsh_const);
  uint32_t y = x_lsh ^ x_rsh;
  return y;
}

/**
 * The component \f$f_{\mathrm{LXR}}\f$ of the XTEA F-function (\ref xtea_f_lxr) 
 * computed on the first \p i least-significant (LS) bits.
 *
 * \param mask_i \p i bit LSB mask.
 * \param lsh_const \ref LSH constant (default is 4).
 * \param rsh_const \ref RSH constant (default is 5).
 * \param x_in first input to \f$f_{\mathrm{LXR}}\f$.
 * \return \f$f_{\mathrm{LXR}}(x)~ \mathrm{mod}~ 2^i\f$
 *
 * \attention the initial value \p x_in must be minimum 
 *            (\p rsh_const + 1) bits long so that it can be shifted 
 *            right by \p rsh_const positions.
 *
 * \see xtea_f_i()
 */ 
uint32_t xtea_f_lxr_i(const uint32_t mask_i, 
							 const uint32_t lsh_const, const uint32_t rsh_const, const uint32_t x_in)
{
  uint32_t x = x_in;
  uint32_t x_lsh = LSH(x, lsh_const) & mask_i;
  uint32_t x_rsh = RSH(x, rsh_const) & mask_i;

  uint32_t y = (x_lsh ^ x_rsh) & mask_i;

  return y;
}

/**
 * Compute all round keys and round constants of block cipher XTEA.
 *
 * \param key initial key.
 * \param round_key all round keys.
 * \param round_delta all round constants \f$\delta\f$ of XTEA.
 */
void xtea_all_round_keys_and_deltas(uint32_t key[4], uint32_t round_key[64], uint32_t round_delta[64]) 
{
  uint32_t num_rounds = 32;
  uint32_t delta_init = DELTA_INIT;
  uint32_t sum = 0;
  for(uint32_t i=0; i < num_rounds; i++) {
	 // even
	 uint32_t j = (2*i);
	 assert(j < 64);
	 uint32_t k0_idx = (sum & 3);
	 round_key[j] = key[k0_idx] & MASK;
	 round_delta[j] = sum & MASK;

	 // odd
	 j = (2*i) + 1;
	 assert(j < 64);
	 sum += delta_init;
	 uint32_t k1_idx = ((sum>>11) & 3);
	 round_key[j] = key[k1_idx] & MASK;
	 round_delta[j] = sum & MASK;
  }
}

/**
 * Experimentally verify the probability of a XOR differential for 1
 * round of XTEA, for a fixed key and round constant,
 * over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_idx index of the round (not used).
 * \param key cryptographic key of XTEA.
 * \param delta round constant.
 * \param daa first input difference to XTEA \f$F'\f$ function (\ref xtea_f2).
 * \param da second input difference to XTEA \f$F'\f$ function (\ref xtea_f2).
 * \param db output difference from \f$F'\f$.
 */
double xtea_one_round_xor_differential_exper(uint64_t npairs, int round_idx, 
															uint32_t key, uint32_t delta,
															uint32_t daa, uint32_t da, uint32_t db)
{
#if 0
  printf("[%s:%s:%d] %lld\n", __FILE__, __FUNCTION__, __LINE__, g_cnt_fexper);
#endif
  uint64_t cnt  = 0;

#if 0									  // DEBUG_THRES
  printf("[%s:%d] delta %8X | key %8X\n", __FILE__, __LINE__, delta, key);
#endif

  // Encrypt many chosen-plaintext pairs {aa1, aa2}
  for(uint64_t i = 0; i < npairs; i++) {

	 uint32_t aa1 = random32() & MASK;
	 uint32_t aa2 = XOR(aa1, daa);

	 // Encrypt many chosen-plaintext pairs {a1, a2}
	 for(uint64_t j = 0; j < npairs; j++) {
		//	 uint32_t a1[2] = {random32() & MASK, random32() & MASK}; 
		//	 uint32_t a2[2] = {ADD(a1[0], da[0]), ADD(a1[1], da[1])};
		uint32_t a1 = random32() & MASK;
		uint32_t a2 = XOR(a1, da);
		uint32_t v1, lv1, rv1, new_v0;

		// encrypt a1
		//	 v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
		v1 = a1;
		lv1 = LSH(v1, TEA_LSH_CONST);
		rv1 = RSH(v1, TEA_RSH_CONST);
		new_v0 = ADD((lv1 ^ rv1), v1) ^ (ADD(delta, key));
		new_v0 = ADD(aa1, new_v0); // !
		uint32_t b1 = new_v0;;

		// encrypt a2
		v1 = a2;
		lv1 = LSH(v1, TEA_LSH_CONST);
		rv1 = RSH(v1, TEA_RSH_CONST);
		new_v0 = ADD((lv1 ^ rv1), v1) ^ (ADD(delta, key));
		new_v0 = ADD(aa2, new_v0); // !
		uint32_t b2 = new_v0;

		// output difference
		uint32_t dx = XOR(b2, b1);

		if(dx == db) {
		  cnt++;
#if 0									  // DEBUG_THRES
		  printf("[%lld] Match\n", cnt);
#endif
		}
	 }
  }
  double p = (double)cnt / (double)(npairs * npairs);
#if 0									  // DEBUG_THRES
  printf("p = %f = 2^%3.2f\n", p, log2(p)); 
#endif
  return p;
}

/**
 * Experimentally verify the probability of an ADD differential for 1
 * round of XTEA, for a fixed key and round constant,
 * over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_idx index of the round (not used).
 * \param key cryptographic key of XTEA.
 * \param delta round constant.
 * \param da input difference to XTEA \f$F\f$ function (\ref xtea_f).
 * \param db output difference from \f$F\f$.
 */
double xtea_one_round_add_differential_exper(uint64_t npairs, int round_idx, 
															uint32_t key, uint32_t delta,
															uint32_t da, uint32_t db)
{
#if 0
  printf("[%s:%s:%d] %lld\n", __FILE__, __FUNCTION__, __LINE__, g_cnt_fexper);
  g_cnt_fexper++;
#endif
  uint64_t cnt  = 0;

#if 0									  // DEBUG_THRES
  printf("[%s:%d] delta %8X | key %8X\n", __FILE__, __LINE__, delta, key);
#endif

  // Encrypt many chosen-plaintext pairs {a1, a2}
  for(uint64_t j = 0; j < npairs; j++) {
	 //	 uint32_t a1[2] = {random32() & MASK, random32() & MASK}; 
	 //	 uint32_t a2[2] = {ADD(a1[0], da[0]), ADD(a1[1], da[1])};
	 uint32_t a1 = random32() & MASK;
	 uint32_t a2 = ADD(a1, da);
	 uint32_t v1, lv1, rv1, new_v0;

	 // encrypt a1
	 //	 v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
	 v1 = a1;
	 lv1 = LSH(v1, TEA_LSH_CONST);
	 rv1 = RSH(v1, TEA_RSH_CONST);
	 new_v0 = ADD((lv1 ^ rv1), v1) ^ (ADD(delta, key));
	 uint32_t b1 = new_v0;;

	 // encrypt a2
	 v1 = a2;
	 lv1 = LSH(v1, TEA_LSH_CONST);
	 rv1 = RSH(v1, TEA_RSH_CONST);
	 new_v0 = ADD((lv1 ^ rv1), v1) ^ (ADD(delta, key));
	 uint32_t b2 = new_v0;

	 // output difference
	 uint32_t dx = SUB(b2, b1);

	 if(dx == db) {
		cnt++;
#if 0									  // DEBUG_THRES
		printf("[%lld] Match\n", cnt);
#endif
	 }
  }
  double p = (double)cnt / (double)(npairs);
#if 0									  // DEBUG_THRES
  printf("p = %f = 2^%3.2f\n", p, log2(p)); 
#endif
  return p;
}

/**
 * Experimentally verify the probability of an \p r round XOR differential
 * for XTEA, for a fixed key, over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param r number of rounds (1 \f$\le\f$ \p nrounds \f$\le\f$ 64).
 * \param key cryptographic key of XTEA.
 * \param da input state to round \p 1.
 * \param db output state after round \p r.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 */
double xtea_xor_differential_exper_v2(uint64_t npairs, int r, 
												  uint32_t key[4], uint32_t da[2], uint32_t db[2],
												  uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t cnt  = 0;

  if((r % 2) == 1) { 	 // ! swapped for odd rounds
	 uint32_t temp = db[0];
	 db[0] = db[1];
	 db[1] = temp;
  }
  uint32_t k[4] = {key[0], key[1], key[2], key[3]}; // !!!

  for(uint64_t j = 0; j < npairs; j++) {
	 uint32_t a1[2] = {random32() & MASK, random32() & MASK}; 
	 uint32_t a2[2] = {XOR(a1[0], da[0]), XOR(a1[1], da[1])};

	 // Encrypt the pair {a1, a2}
	 xtea_r(r, a1, k, lsh_const, rsh_const);
	 xtea_r(r, a2, k, lsh_const, rsh_const);

	 uint32_t b1[2] = {a1[0], a1[1]};
	 uint32_t b2[2] = {a2[0], a2[1]};
	 // output difference
	 uint32_t dx[2] = {XOR(b2[0], b1[0]), XOR(b2[1], b1[1])};

	 if((dx[0] == db[0]) && (dx[1] == db[1])) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(npairs);
  return p;
}

/**
 * Experimentally verify the probability of an \p r round ADD differential
 * for XTEA, for a fixed key, over a number of chosen plaintexts.
 *
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param r number of rounds (1 \f$\le\f$ \p nrounds \f$\le\f$ 64).
 * \param key cryptographic key of XTEA.
 * \param da input state to round \p 1.
 * \param db output state after round \p r.
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 */
double xtea_add_differential_exper_v2(uint64_t npairs, int r, 
												  uint32_t key[4], uint32_t da[2], uint32_t db[2],
												  uint32_t lsh_const, uint32_t rsh_const)
{
  uint64_t cnt  = 0;

  if((r % 2) == 1) { 	 // ! swapped for odd rounds
	 uint32_t temp = db[0];
	 db[0] = db[1];
	 db[1] = temp;
  }
  uint32_t k[4] = {key[0], key[1], key[2], key[3]};

  for(uint64_t j = 0; j < npairs; j++) {
	 uint32_t a1[2] = {random32() & MASK, random32() & MASK}; 
	 uint32_t a2[2] = {ADD(a1[0], da[0]), ADD(a1[1], da[1])};

	 // Encrypt the pair {a1, a2}
	 xtea_r(r, a1, k, lsh_const, rsh_const);
	 xtea_r(r, a2, k, lsh_const, rsh_const);

	 uint32_t b1[2] = {a1[0], a1[1]};
	 uint32_t b2[2] = {a2[0], a2[1]};
	 // output difference
	 uint32_t dx[2] = {SUB(b2[0], b1[0]), SUB(b2[1], b1[1])};

	 if((dx[0] == db[0]) && (dx[1] == db[1])) {
		cnt++;
	 }
  }
  double p = (double)cnt / (double)(npairs);
  return p;
}

/**
 * Given an XOR trail for \f$N\f$ rounds of XTEA, experimentally verify
 * the probabilities of the corresponding \f$N\f$ differentials:
 *
 *       - Differential for 1 round: round 0. 
 *       - Differential for 2 rounds: rounds \f$0,1\f$. 
 *       - Differential for 3 rounds: rounds \f$0,1,2\f$. 
 *       - \f$\ldots\f$
 *       - Differential for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
 * 
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param key cryptographic key of XTEA.
 * \param dxx_init first input difference to XTEA \f$F'\f$ function (\ref xtea_f2) for round \f$r = 0\f$.
 * \param trail differential trail for \p nrounds.
 */
uint32_t xtea_xor_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t lsh_const, uint32_t rsh_const,
												  uint32_t key[4], uint32_t dxx_init, differential_t trail[NROUNDS]) 
{
  printf("[%s:%d] Verify P of differential (2^%f CPs):\n", __FILE__, __LINE__, log2(npairs));
  uint32_t warn_cnt = 0;
  double p1 = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t da[2], db[2];;

	 da[1] = trail[0].dx;
	 da[0] = dxx_init;

	 db[0] = trail[i].dx;
	 db[1] = trail[i].dy;

	 p1 *= trail[i].p;

	 int r = i + 1;				  // number of rounds
	 double p2 = xtea_xor_differential_exper_v2(npairs, r, key, da, db, lsh_const, rsh_const);
	 printf("THE %2d: %f (2^%f)\n", i, p1, log2(p1));
	 printf("EXP %2d: %f (2^%f) (%8X, %8X) <- (%8X, %8X)\n\n", i, p2, log2(p2), db[0], db[1], da[0], da[1]);
	 if(p2 == 0.0) {
		warn_cnt++;
#if 0
		printf("WARNING: [%s:%d] Zero probability p_the = 2^%4.2f . Estimatedd over 2^%2.0f CPs.\n\n", __FILE__, __LINE__, log2(p1), log2(npairs));
#endif
	 }
  }
  return warn_cnt;
}

/**
 * Given an ADD trail for \f$N\f$ rounds of XTEA, experimentally verify
 * the probabilities of the corresponding \f$N\f$ differentials:
 *
 *       - Differential for 1 round: round 0. 
 *       - Differential for 2 rounds: rounds \f$0,1\f$. 
 *       - Differential for 3 rounds: rounds \f$0,1,2\f$. 
 *       - \f$\ldots\f$
 *       - Differential for \f$N\f$ rounds: rounds \f$0,1,2,\ldots,(N-1)\f$. 
 * 
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param lsh_const \ref LSH constant (\ref TEA_LSH_CONST).
 * \param rsh_const \ref RSH constant (\ref TEA_RSH_CONST).
 * \param key cryptographic key of XTEA.
 * \param trail differential trail for \p nrounds.
 */
uint32_t xtea_add_verify_differential(uint32_t nrounds, uint32_t npairs, uint32_t lsh_const, uint32_t rsh_const,
												  uint32_t key[4], differential_t trail[NROUNDS]) 
{
  printf("[%s:%d] Verify P of differential (2^%f CPs):\n", __FILE__, __LINE__, log2(npairs));
  uint32_t warn_cnt = 0;
  double p1 = 1.0;
  for(uint32_t i = 0; i < nrounds; i++) {

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

	 p1 *= trail[i].p;

	 int r = i + 1;				  // number of rounds
	 double p2 = xtea_add_differential_exper_v2(npairs, r, key, da, db, lsh_const, rsh_const);
	 printf("THE %2d: %f (2^%f)\n", i, p1, log2(p1));
	 printf("EXP %2d: %f (2^%f) (%8X, %8X) <- (%8X, %8X)\n\n", i, p2, log2(p2), db[0], db[1], da[0], da[1]);

	 if(p2 == 0.0) {
		printf("WARNING: [%s:%d] Zero probability p_the = 2^%4.2f . Estimatedd over 2^%2.0f CPs.\n\n", __FILE__, __LINE__, log2(p1), log2(NPAIRS));
	 }
  }
  return warn_cnt;
}

/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round XOR trail for XTEA is composed.
 *
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_key all round keys.
 * \param round_delta all round constants \f$\delta\f$ of XTEA.
 * \param dxx_init first input difference to XTEA \f$F'\f$ function (\ref xtea_f2) for round \f$r = 0\f$.
 * \param trail differential trail for \p nrounds.
 */
uint32_t xtea_xor_verify_trail(uint32_t nrounds, uint32_t npairs, 
										 uint32_t round_key[64], uint32_t round_delta[64],
										 uint32_t dxx_init, differential_t trail[NROUNDS]) 
{
  printf("[%s:%d] Verify P for one round (2^%f CPs):\n", __FILE__, __LINE__, log2(npairs));
  uint32_t warn_cnt = 0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 uint32_t dxx = dxx_init;
	 if(i > 0) {
		dxx = trail[i - 1].dx;
	 }
	 uint32_t dx = trail[i].dx;
	 uint32_t dyy = trail[i].dy;
	 uint32_t npairs = (1UL << 10);
	 double p_exp = xtea_one_round_xor_differential_exper(npairs, i, round_key[i], round_delta[i], dxx, dx, dyy);

	 printf("THE %2d: %8X %8X | %f (2^%f) %8X <- %8X %8X\n", i, round_key[i], round_delta[i], trail[i].p, log2(trail[i].p), dyy, dxx, dx);
	 printf("EXP %2d: %8X %8X | %f (2^%f) %8X <- %8X %8X\n\n", i, round_key[i], round_delta[i], p_exp, log2(p_exp), dyy, dxx, dx);

	 if(p_exp == 0.0) {
		warn_cnt++;
		printf("WARNING: [%s:%d] Zero probability p_the = 2^%4.2f . Estimated over 2^%2.0f CPs.\n\n", __FILE__, __LINE__, log2(trail[i].p), log2(npairs));
	 }
  }
  return warn_cnt;
}

/**
 * Experimentally verify the probability of all 1-round differentials
 * from which an N round ADD trail for XTEA is composed.
 *
 * \param nrounds number of rounds covered by the trail (\ref NROUNDS).
 * \param npairs number of chosen plaintext pairs (\ref NPAIRS).
 * \param round_key all round keys.
 * \param round_delta all round constants \f$\delta\f$ of XTEA.
 * \param trail differential trail for \p nrounds.
 */
uint32_t xtea_add_verify_trail(uint32_t nrounds, uint32_t npairs, 
										 uint32_t round_key[64], uint32_t round_delta[64],
										 differential_t trail[NROUNDS]) 
{
  printf("[%s:%d] Verify P for one round (2^%f CPs):\n", __FILE__, __LINE__, log2(npairs));
  uint32_t warn_cnt = 0;
  for(uint32_t i = 0; i < nrounds; i++) {

	 double p_exp = xtea_one_round_add_differential_exper(npairs, i, round_key[i], round_delta[i], trail[i].dx, trail[i].dy);

	 printf("THE %2d: %8X %8X | %f (2^%f) %8X <- %8X\n", i, round_key[i], round_delta[i], trail[i].p, log2(trail[i].p), trail[i].dy, trail[i].dx);
	 printf("EXP %2d: %8X %8X | %f (2^%f) %8X <- %8X\n\n", i, round_key[i], round_delta[i], p_exp, log2(p_exp), trail[i].dy, trail[i].dx);

	 if(p_exp == 0.0) {
		warn_cnt++;
		printf("WARNING: [%s:%d] Zero probability p_the = 2^%4.2f . Estimated over 2^%2.0f CPs.\n\n", __FILE__, __LINE__, log2(trail[i].p), log2(npairs));
	 }
  }
  return warn_cnt;
}
