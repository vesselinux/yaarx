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
 * \file  xdp-and.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief The XOR differential probability of AND \f$\mathrm{xdp}^{\wedge}(da,db \rightarrow db)\f$.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_AND_H
#include "xdp-and.hh"
#endif

/**
 * The XOR DP of Boolean AND: compute matrices using S-function.
 */
void xdp_and_sf(uint32_t A[2][2][2])
{
  uint32_t ninputs = 2;
  uint32_t ndiffs = (1U << ninputs);
  uint32_t nvals = (1U << ninputs);

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
#if 0									  // DEBUG
	 printf("[%s:%d] da db %d %d\n", __FILE__, __LINE__, da, db);
#endif
	 for(uint32_t j = 0; j < nvals; j++) {
		uint32_t x = (j >> 0) & 1;
		uint32_t y = (j >> 1) & 1;
		uint32_t z = x & y;

		uint32_t xx = x ^ da;
		uint32_t yy = y ^ db;
		uint32_t zz = xx & yy;

		uint32_t dc = z ^ zz;

		A[da][db][dc]++;
#if 1									  // DEBUG
		printf("A%d%d%d: %d %d | %d \n", da, db, dc, x, y, A[da][db][dc]);
#endif
	 }
  }
}

/**
 * The XOR DP of Boolean AND: compute matrices using closed Boolean function (BF):
 *
 * adp-and(da,db->dc) = 2^{-2n} ( 4 (~da_i & ~db_i & ~dc_i) + 2 (~(~da_i & ~db_i)) )
 */
void xdp_and_bf(uint32_t A[2][2][2])
{
  uint32_t ndiffs = (1U << 3);

  for(uint32_t i = 0; i < ndiffs; i++) {
	 uint32_t da = (i >> 0) & 1;
	 uint32_t db = (i >> 1) & 1;
	 uint32_t dc = (i >> 2) & 1;

	 uint32_t not_da = (~da) & 1;
	 uint32_t not_db = (~db) & 1;
	 uint32_t not_dc = (~dc) & 1;

	 uint32_t f = (4 * (not_da & not_db & not_dc)) + (2 * (~(not_da & not_db) & 1));

	 A[da][db][dc] += f;
  }
}

//  * A000[ 4] A001[ 0] A010[ 2] A011[ 2] A100[ 2] A101[ 2] A110[ 2] A111[ 2]
/**
 * The XOR DP of Boolean AND: efficient computation using pre-computed matrices
 */
double xdp_and(uint32_t A[2][2][2], uint32_t da, uint32_t db, uint32_t dc)
{
  assert(WORD_SIZE < 64);
  double p = 0.0;
#if(WORD_SIZE < 64)
  uint32_t cnt = 1;
  for(int pos = 0; pos < WORD_SIZE; pos++) {
	 uint32_t i = (da >> pos) & 1;
	 uint32_t j = (db >> pos) & 1;
	 uint32_t k = (dc >> pos) & 1;
	 cnt *= A[i][j][k];
  }
#if 0									  // DEBUG
  printf("[%s:%d] cnt %d\n", __FILE__, __LINE__, cnt);
#endif
  p = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
#endif // #if(WORD_SIZE < 64)
  return p;
}

bool xdp_and_is_nonzero(uint32_t da, uint32_t db, uint32_t dc)
{
  bool is_possible = (((~da & MASK) & (~db & MASK) & dc) == 0); // (da,db,dc) = (0,0,1)
  return is_possible;
}

/**
 * The XOR DP of Boolean AND: experimental computation.
 */
double xdp_and_exper(uint32_t da, uint32_t db, uint32_t dc)
{
  assert(WORD_SIZE <= 10);
  double p = 0.0;
#if (WORD_SIZE <= 10)
  uint32_t cnt = 0;
  for(uint32_t x = 0; x < ALL_WORDS; x++) {
	 for(uint32_t y = 0; y < ALL_WORDS; y++) {
		uint32_t xx = x ^ da;
		uint32_t yy = y ^ db;
		uint32_t z = x & y;
		uint32_t zz = xx & yy;
		uint32_t dz = z ^ zz;
		if(dz == dc) {
		  cnt++;
		}
	 }
  }
  p = (double)cnt / (double)(ALL_WORDS * ALL_WORDS);
#endif // #if (WORD_SIZE <= 10)
  return p;
}

bool xdp_and_is_zero(uint32_t da, uint32_t db, uint32_t dc)
{
  uint32_t c = ((da ^ db ^ dc) & (~(da | db))) & MASK;
  bool b_xdp_and_iszero = !(c == 0);
  return b_xdp_and_iszero;
}

// closed formula
int xdp_and_closed(uint32_t da, uint32_t db, uint32_t dc)
{
  int res = LOG0;
  //  if(!xdp_and_is_nonzero(da, db, dc)) {
  if(xdp_and_is_zero(da, db, dc)) {
	 return res;
  }
  res = -hamming_weight((da | db) & MASK);
  return res;
}

