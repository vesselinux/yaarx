/*
 *    Copyright (c) 2012-2014 Luxembourg University,
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
 * \file  add-approx.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \brief XOR-linear approximations of modular addition.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

// {--- ADD approximations ---

WORD_T add_bitwise(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 WORD_T z_i = 0;
	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 z_i = x_i ^ y_i ^ s_i;
	 z |= (z_i << i);
	 WORD_T s_next = (x_i & y_i) | (s_i & (x_i ^ y_i));
	 //	 WORD_T s_next = (x_i & y_i) | (x_i & s_i) | (y_i & s_i);
	 s_i = s_next;
  }
  return z;
}


WORD_T add_approx_o1(const WORD_T x, const WORD_T y)
{
  WORD_T z = XOR(x, y);
  return z;
}

WORD_T add_approx_o2_fast(const WORD_T x, const WORD_T y)
{
  WORD_T z = (x ^ y) ^ LSH((x & y), 1);
  return z;
}

WORD_T add_approx_o2(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 WORD_T z_i = 0;
	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 z_i = x_i ^ y_i ^ s_i;
	 z |= (z_i << i);
	 WORD_T s_next = (x_i & y_i);
	 s_i = s_next;
  }
#if 1 // DEBUG
  WORD_T zz = add_approx_o2_fast(x, y);
  assert(z == zz);
#endif
  return z;
}

WORD_T add_approx_o3(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = (x_i & y_i); // s[1]
	 }
	 if(i >= 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1;
		WORD_T y_i_1 = (y >> (i - 1)) & 1;
		s_next = (x_i & y_i) | (x_i & x_i_1 & y_i_1) | (y_i & x_i_1 & y_i_1); // s[i+1]
	 }

	 s_i = s_next;
	 z |= (z_i << i);

  }

  return z;
}

WORD_T add_approx_o4(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = (x_i & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1); // s[i]

		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]

#if 1 // DEBUG
		WORD_T s_next_tmp = (x_i & y_i) | (x_i & x_i_1 & y_i_1) | (y_i & x_i_1 & y_i_1); // s[i+1]
		assert(s_next == s_next_tmp);
#endif
	 }
	 if(i >= 2) {
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]

		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T add_approx_o5(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = (x_i & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1); // s[i]
		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
#if 1 // DEBUG
		WORD_T s_next_tmp = (x_i & y_i) | (x_i & x_i_1 & y_i_1) | (y_i & x_i_1 & y_i_1); // s[i+1]
		assert(s_next == s_next_tmp);
#endif
	 }
	 if(i == 2) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2); // s[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]
		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 if(i >= 3) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = (x_i_3 & y_i_3); // s[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2) | (x_i_2 & s_i_2) | (y_i_2 & s_i_2); // s[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]
		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T add_approx_o6(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = (x_i & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1); // s[i]
		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
#if 1 // DEBUG
		WORD_T s_next_tmp = (x_i & y_i) | (x_i & x_i_1 & y_i_1) | (y_i & x_i_1 & y_i_1); // s[i+1]
		assert(s_next == s_next_tmp);
#endif
	 }
	 if(i == 2) {
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]

		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 if(i == 3) {
		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = (x_i_3 & y_i_3); // s[i-2]

		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2) | (x_i_2 & s_i_2) | (y_i_2 & s_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]

		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 if(i >= 4) {
		WORD_T x_i_4 = (x >> (i - 4)) & 1; // x[i-4]
		WORD_T y_i_4 = (y >> (i - 4)) & 1; // y[i-4]
		WORD_T s_i_3 = (x_i_4 & y_i_4); // s[i-3]

		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = (x_i_3 & y_i_3) | (x_i_3 & s_i_3) | (y_i_3 & s_i_3); // s[i-2]

		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = (x_i_2 & y_i_2) | (x_i_2 & s_i_2) | (y_i_2 & s_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = (x_i_1 & y_i_1) | (x_i_1 & s_i_1) | (y_i_1 & s_i_1); // s[i]

		s_next = (x_i & y_i) | (x_i & s_i_0) | (y_i & s_i_0); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T add_approx(const WORD_T x, const WORD_T y, const uint32_t order)
{
  assert((order >= 0) && (order <= 6));
  WORD_T z = 0;
  switch(order) {
  case 0:
	 z = ADD(x, y);
	 break;
  case 1:
	 z = add_approx_o1(x, y);
	 break;
  case 2:
	 z = add_approx_o2(x, y);
	 break;
  case 3:
	 z = add_approx_o3(x, y);
	 break;
  case 4:
	 z = add_approx_o4(x, y);
	 break;
  case 5:
	 z = add_approx_o5(x, y);
	 break;
  case 6:
	 z = add_approx_o6(x, y);
	 break;
  default: /* Optional */
	 printf("[%s:%d] Invalid order! Must be from 0 to 6. Terminating...\n", __FILE__, __LINE__);
	 assert((order >= 0) && (order <= 6));
  }
  return z;
}

WORD_T add_approx_any_order(const WORD_T x, const WORD_T y, const uint32_t order)
{
  WORD_T z = 0;
#if(WORD_SIZE <= 32)
  assert(order >= 2);
  assert(order <= WORD_SIZE);
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits

  z = (x + y) & mask_lsb;
  for(uint32_t i = (order - 1); i < WORD_SIZE; i++) {
	 uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
	 WORD_T z_i = ((((x & mask_stride) + (y & mask_stride)) & mask_stride) >> i) & 1;
	 z |= (z_i << i);
  }
#endif // #if(WORD_SIZE <= 32)
  return z;
}

/**
 * Block approximation of addition
 */
WORD_T add_block_approx(const WORD_T x, const WORD_T y, const uint32_t block_size)
{
  WORD_T z = 0;
#if(WORD_SIZE <= 32)
#if 0 // DEBUG
  printf("[%s:%d] Enter %s() x %8X y %8X block_size %2d\n", 
			__FILE__, __LINE__, __FUNCTION__, x, y, block_size);
#endif // #if 1 // DEBUG
  assert(block_size > 0);
  assert(block_size <= WORD_SIZE);
  uint32_t mask_block = (0xffffffff >> (32 - block_size)); 
#if 0 // DEBUG
  printf("[%s:%d] mask_block %8X\n", __FILE__, __LINE__, mask_block);
#endif // #if 1 // DEBUG
  uint32_t i = 0;
  while((i + block_size) <= WORD_SIZE) {
#if 0 // DEBUG
	 printf("[%s:%d] i %2d Enter\n", __FILE__, __LINE__, i);
#endif // #if 1 // DEBUG
	 WORD_T x_block = (x >> i) & mask_block;
	 WORD_T y_block = (y >> i) & mask_block;
	 WORD_T z_block = (x_block + y_block) & mask_block;
	 z |= (z_block << i);
#if 0 // DEBUG
	 printf("[%s:%d] %8X %8X %8X\n", __FILE__, __LINE__, x_block, y_block, z_block);
#endif // #if 1 // DEBUG
	 i += block_size;
#if 0 // DEBUG
	 printf("[%s:%d] i %2d Exit\n", __FILE__, __LINE__, i);
#endif // #if 1 // DEBUG
  }
  if(((i + block_size) > WORD_SIZE) && (i < WORD_SIZE)) {
#if 0 // DEBUG
	 printf("[%s:%d] i %2d Enter\n", __FILE__, __LINE__, i);
#endif // #if 1 // DEBUG
	 uint32_t mask_msb = 0xffffffff >> (32 - (WORD_SIZE - i));
#if 0 // DEBUG
	 printf("[%s:%d] mask_msb %8X = 0xffffffff >> %2d\n", __FILE__, __LINE__, mask_msb, (32 - (WORD_SIZE - i)));
	 printf("[%s:%d] i %2d + block_size %2d = %2d\n", __FILE__, __LINE__, i, block_size, (i + block_size));
#endif // #if 1 // DEBUG
	 WORD_T x_block = (x >> i) & mask_msb;
	 WORD_T y_block = (y >> i) & mask_msb;
	 WORD_T z_block = (x_block + y_block) & mask_msb;
	 z |= (z_block << i);
#if 0 // DEBUG
	 printf("[%s:%d] %8X %8X %8X\n", __FILE__, __LINE__, x_block, y_block, z_block);
#endif // #if 1 // DEBUG
	 assert((x >> i) <= mask_msb);
	 assert((y >> i) <= mask_msb);
  }
#if 0 // DEBUG
  printf("[%s:%d] Return z %8X\n", __FILE__, __LINE__, z);
#endif // #if 1 // DEBUG
#endif // #if(WORD_SIZE <= 32)
  return z;
}

double xdp_add_approx_exper(const WORD_T da, const WORD_T db, const WORD_T dc, uint32_t order)
{
  double p = 0.0;
  assert(WORD_SIZE <= 32);
#if(WORD_SIZE <= 32)
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;
  WORD_T all = N * N;				  // all input pairs

  for(WORD_T a1 = 0; a1 < N; a1++) {
	 WORD_T a2 = (a1 ^ da) & MASK;
	 for(WORD_T b1 = 0; b1 < N; b1++) {
		WORD_T b2 = (b1 ^ db) & MASK;

		WORD_T c1 = add_approx(a1, b1, order);
		WORD_T c2 = add_approx(a2, b2, order);

		WORD_T dx = (c1 ^ c2) & MASK;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc) {
		  cnt++;
		}
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

void xdp_add_approx_rec_i(const uint32_t i, const uint32_t order,
								  const WORD_T dx, const WORD_T dy, const WORD_T dz,
								  const WORD_T x, const WORD_T y, uint64_t* cnt_xy)
{
  assert(WORD_SIZE <= 32);
#if(WORD_SIZE <= 32)
  if(i == WORD_SIZE) {
	 (*cnt_xy)++;
	 return;
  }

  //  uint32_t mask_order = (0xffffffff >> (32 - (order - 1)));
  uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
  for(uint32_t x_i = 0; x_i < 2; x_i++) {
	 for(uint32_t y_i = 0; y_i < 2; y_i++) {
		WORD_T new_x = ((x_i << i) | x) & mask_stride; 
		WORD_T new_y = ((y_i << i) | y) & mask_stride; 
		WORD_T new_xx = (new_x ^ dx) & mask_stride;
		WORD_T new_yy = (new_y ^ dy) & mask_stride;

		//		printf("[%s:%d] %8X %8X %8X %8X | %8X\n", __FILE__, __LINE__, new_x, new_y, new_xx, new_yy, diff_stride);
		WORD_T diff_stride = (((new_x & mask_stride) + (new_y & mask_stride)) ^ 
								  ((new_xx & mask_stride) + (new_yy & mask_stride))) & mask_stride;
		//		bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
		bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
		if(b_match) {
		  xdp_add_approx_rec_i(i+1, order, dx, dy, dz, new_x, new_y, cnt_xy);
		}
	 }
  }
#endif // #if(WORD_SIZE <= 32)
}

double xdp_add_approx_rec(const WORD_T dx, const WORD_T dy, const WORD_T dz, uint32_t order)
{
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  //  printf("[%s:%d] Enter %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(order >= 2);
  assert(order <= WORD_SIZE);

  uint32_t N = (1U << (order - 1)); // x[i-1:0]
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits
  uint64_t cnt_xy = 0;

  //  printf("[%s:%d] order % 2d mask_lsb %8X\n", __FILE__, __LINE__, order, mask_lsb);
  for(WORD_T x = 0; x < N; x++) {
	 for(WORD_T y = 0; y < N; y++) {
		//		printf("[%s:%d] %d %d\n", __FILE__, __LINE__, x, y);
		WORD_T xx = (x ^ dx) & mask_lsb;
		WORD_T yy = (y ^ dy) & mask_lsb;
		WORD_T diff_lsb = (((x + y) & mask_lsb) ^ ((xx + yy) & mask_lsb)) & mask_lsb;
		bool b_match_lsb = (diff_lsb == (dz & mask_lsb));
		if(b_match_lsb) {
		  uint32_t i = order - 1; // next bit index to be assigned
		  xdp_add_approx_rec_i(i, order, dx, dy, dz, x, y, &cnt_xy);
		}
	 }
  }
  uint64_t all = (ALL_WORDS * ALL_WORDS);
  p = (double)cnt_xy / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

// fixed x
double xdp_add_fixed_x_approx_exper(const WORD_T a1, const WORD_T a2,  const WORD_T db, const WORD_T dc, uint32_t order)
{
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  uint32_t cnt = 0;
  uint64_t all = ALL_WORDS;

  for(WORD_T b1 = 0; b1 < ALL_WORDS; b1++) {
	 WORD_T b2 = (b1 ^ db) & MASK;

	 WORD_T c1 = add_approx(a1, b1, order);
	 WORD_T c2 = add_approx(a2, b2, order);

	 WORD_T dx = (c1 ^ c2) & MASK;
	 assert((dx >= 0) && (dx < MOD));
	 if(dx == dc) {
		cnt++;
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

void xdp_add_fixed_x_approx_rec_i(const uint32_t i, const uint32_t order,
											 const WORD_T dy, const WORD_T dz, const WORD_T x, const WORD_T xx, 
											 const WORD_T y, uint64_t* cnt_y)
{
  assert(WORD_SIZE <= 32);
#if(WORD_SIZE <= 32)
  if(i == WORD_SIZE) {
	 (*cnt_y)++;
	 return;
  }

  //  uint32_t mask_order = (0xffffffff >> (32 - (order - 1)));
  uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
  for(uint32_t y_i = 0; y_i < 2; y_i++) {
	 WORD_T new_x = x & mask_stride; 
	 WORD_T new_xx = xx & mask_stride;
	 WORD_T new_y = ((y_i << i) | y) & mask_stride; 
	 WORD_T new_yy = (new_y ^ dy) & mask_stride;

	 //		printf("[%s:%d] %8X %8X %8X %8X | %8X\n", __FILE__, __LINE__, new_x, new_y, new_xx, new_yy, diff_stride);
	 WORD_T diff_stride = ((new_x + new_y) ^ (new_xx + new_yy)) & mask_stride;
	 //		bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
	 bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
	 if(b_match) {
		xdp_add_fixed_x_approx_rec_i(i+1, order, dy, dz, x, xx, new_y, cnt_y);
	 }
  }
#endif // #if(WORD_SIZE <= 32)
}

double xdp_add_fixed_x_approx_rec(const WORD_T x, const WORD_T xx, const WORD_T dy, const WORD_T dz, uint32_t order)
{
  //  printf("[%s:%d] Enter %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  assert(order >= 2);
  assert(order <= WORD_SIZE);

  uint32_t N = (1U << (order - 1)); // x[i-1:0]
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits
  uint64_t cnt_y = 0;

  //  printf("[%s:%d] order % 2d mask_lsb %8X\n", __FILE__, __LINE__, order, mask_lsb);
  for(WORD_T y = 0; y < N; y++) {
	 //		printf("[%s:%d] %d %d\n", __FILE__, __LINE__, x, y);
	 WORD_T yy = (y ^ dy) & mask_lsb;
	 WORD_T diff_lsb = (((x + y) & mask_lsb) ^ ((xx + yy) & mask_lsb)) & mask_lsb;
	 bool b_match_lsb = (diff_lsb == (dz & mask_lsb));
	 if(b_match_lsb) {
		uint32_t i = order - 1; // next bit index to be assigned
		xdp_add_fixed_x_approx_rec_i(i, order, dy, dz, x, xx, y, &cnt_y);
	 }
  }
  uint64_t all = ALL_WORDS;
  p = (double)cnt_y / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

// --- ADD approximations ---}

// {--- SUB approximations ---

/**
 * See: http://en.wikipedia.org/wiki/Subtractor
 */
WORD_T sub_bitwise(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 WORD_T z_i = 0;
	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 z_i = x_i ^ y_i ^ s_i;
	 z |= (z_i << i);
	 WORD_T s_next = ((~x_i) & y_i) | (s_i & (~(x_i ^ y_i)));
	 //	 WORD_T s_next = ((~x_i) & y_i) | (s_i & ~((~x_i) & y_i) & (~((x_i & ~(y_i)))));
	 s_i = s_next;
  }
  return z;
}

WORD_T sub_approx_o1(const WORD_T x, const WORD_T y)
{
  WORD_T z = XOR(x, y);
  return z;
}

WORD_T sub_approx_o2_fast(const WORD_T x, const WORD_T y)
{
  WORD_T z = (x ^ y) ^ LSH(((~x) & y), 1);
  return z;
}

WORD_T sub_approx_o2(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 WORD_T z_i = 0;
	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 z_i = x_i ^ y_i ^ s_i;
	 z |= (z_i << i);
	 WORD_T s_next = ((~x_i) & y_i);
	 s_i = s_next;
  }
#if 1 // DEBUG
  WORD_T zz = sub_approx_o2_fast(x, y);
  assert(z == zz);
#endif
  return z;
}

WORD_T sub_approx_o3(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = ((~x_i) & y_i); // s[1]
	 }
	 if(i >= 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1;
		WORD_T y_i_1 = (y >> (i - 1)) & 1;
		WORD_T s_i_0 = ((~x_i_1) & y_i_1); // s[i]
		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }

	 s_i = s_next;
	 z |= (z_i << i);

  }

  return z;
}

WORD_T sub_approx_o4(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = ((~x_i) & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i >= 2) {
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T sub_approx_o5(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = ((~x_i) & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i == 2) {
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2); // s[i-1]
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]
		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i >= 3) {
		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = ((~x_i_3) & y_i_3); // s[i-2]

		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2) | (s_i_2 & (~(x_i_2 ^ y_i_2))); // s[i]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T sub_approx_o6(const WORD_T x, const WORD_T y)
{
  WORD_T z = 0;
  WORD_T s_i = 0; // s[i]

  for(uint32_t i = 0; i < WORD_SIZE; i++) {

	 WORD_T x_i = (x >> i) & 1;
	 WORD_T y_i = (y >> i) & 1;
	 WORD_T z_i = x_i ^ y_i ^ s_i;
	 WORD_T s_next = 0;
	 if(i == 0) {
		s_next = ((~x_i) & y_i); // s[1]
	 }
	 if(i == 1) {
		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i == 2) {
		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i == 3) {
		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = ((~x_i_3) & y_i_3); // s[i-2]

		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2) | (s_i_2 & (~(x_i_2 ^ y_i_2))); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 if(i >= 4) {
		WORD_T x_i_4 = (x >> (i - 4)) & 1; // x[i-4]
		WORD_T y_i_4 = (y >> (i - 4)) & 1; // y[i-4]
		WORD_T s_i_3 = ((~x_i_4) & y_i_4); // s[i-3]

		WORD_T x_i_3 = (x >> (i - 3)) & 1; // x[i-3]
		WORD_T y_i_3 = (y >> (i - 3)) & 1; // y[i-3]
		WORD_T s_i_2 = ((~x_i_3) & y_i_3) | (s_i_3 & (~(x_i_3 ^ y_i_3))); // s[i-2]

		WORD_T x_i_2 = (x >> (i - 2)) & 1; // x[i-2]
		WORD_T y_i_2 = (y >> (i - 2)) & 1; // y[i-2]
		WORD_T s_i_1 = ((~x_i_2) & y_i_2) | (s_i_2 & (~(x_i_2 ^ y_i_2))); // s[i-1]

		WORD_T x_i_1 = (x >> (i - 1)) & 1; // x[i-1]
		WORD_T y_i_1 = (y >> (i - 1)) & 1; // y[i-1]
		WORD_T s_i_0 = ((~x_i_1) & y_i_1) | (s_i_1 & (~(x_i_1 ^ y_i_1))); // s[i]

		s_next = ((~x_i) & y_i) | (s_i_0 & (~(x_i ^ y_i))); // s[i+1]
	 }
	 s_i = s_next;
	 z |= (z_i << i);
  }

  return z;
}

WORD_T sub_approx(const WORD_T x, const WORD_T y, const uint32_t order)
{
  assert((order >= 0) && (order <= 6));
  WORD_T z = 0;
  switch(order) {
  case 0:
	 z = SUB(x, y); // no approximation
	 break;
  case 1:
	 z = sub_approx_o1(x, y); // 1 bit: i (= XOR)
	 break;
  case 2:
	 z = sub_approx_o2(x, y); // 2 bits: i, i-1
	 break;
  case 3:
	 z = sub_approx_o3(x, y); // 3 bits: i, i-1, i-2
	 break;
  case 4:
	 z = sub_approx_o4(x, y);
	 break;
  case 5:
	 z = sub_approx_o5(x, y);
	 break;
  case 6:
	 z = sub_approx_o6(x, y);
	 break;
  default: /* Optional */
	 printf("[%s:%d] Invalid order! Must be from 0 to 6. Terminating...\n", __FILE__, __LINE__);
	 assert((order >= 0) && (order <= 6));
  }
  return z;
}

WORD_T sub_approx_any_order(const WORD_T x, const WORD_T y, const uint32_t order)
{
  WORD_T z = 0;
#if(WORD_SIZE <= 32)
  assert(order >= 2);
  assert(order <= WORD_SIZE);
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits

  z = (x - y) & mask_lsb; // z[order - 1 : 0]
  for(uint32_t i = (order - 1); i < WORD_SIZE; i++) {
	 uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
	 WORD_T z_i = ((((x & mask_stride) - (y & mask_stride)) & mask_stride) >> i) & 1;
	 z |= (z_i << i);
  }
#endif // #if(WORD_SIZE <= 32)
  return z;
}

/**
 * Another way to compute SUB approximtaion that is equivalent to \p
 * sub_approx_any_order.
 *
 * \see sub_approx_any_order
 */
WORD_T sub_approx_any_order_equiv(const WORD_T x_in, const WORD_T y_in, const uint32_t order_in)
{
  assert(order_in >= 1);
  assert(order_in <= WORD_SIZE);
  WORD_T z_out = 0;
#if(WORD_SIZE <= 32)
  for(uint32_t i = 0; i < WORD_SIZE; i++) {
	 uint32_t order = 0;
	 uint32_t i_lo = 0;
	 if(i < order_in) {
		i_lo = 0;
		order = i + 1;
	 } else { // i >= order_in
		i_lo = (i - order_in + 1);
		order = order_in;
	 }
	 uint32_t mask_order = (0xffffffff >> (32 - order)); 

	 WORD_T x = (x_in >> i_lo) & mask_order;
	 WORD_T y = (y_in >> i_lo) & mask_order;
	 WORD_T z = (x - y) & mask_order; // (x - y) mod 2^{order}
	 WORD_T z_i = (z >> (order - 1)) & 1;
	 z_out |= (z_i << i);

#if 0 // DEBUG
	 printf("[%s:%d] i %2d i_lo %2d order %8X mask_order %8X ", __FILE__, __LINE__, 
			  i, i_lo, order, mask_order);
	 printf("x %8X y %8X z %8X z_i %d z_out %8X\n", x, y, z, z_i, z_out);
#endif // #if 0 // DEBUG
  }
#endif // #if(WORD_SIZE <= 32)
  return z_out;
}

double xdp_sub_approx_exper(const WORD_T da, const WORD_T db, const WORD_T dc, uint32_t order)
{
  double p = 0.0;
  assert(WORD_SIZE <= 32);
#if(WORD_SIZE <= 32)
  uint64_t N = (1ULL << WORD_SIZE);
  uint32_t cnt = 0;
  WORD_T all = N * N;				  // all input pairs

  for(WORD_T a1 = 0; a1 < N; a1++) {
	 WORD_T a2 = (a1 ^ da) & MASK;
	 for(WORD_T b1 = 0; b1 < N; b1++) {
		WORD_T b2 = (b1 ^ db) & MASK;

		WORD_T c1 = sub_approx(a1, b1, order);
		WORD_T c2 = sub_approx(a2, b2, order);

		WORD_T dx = (c1 ^ c2) & MASK;
		assert((dx >= 0) && (dx < MOD));
		if(dx == dc) {
		  cnt++;
		}
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

void xdp_sub_approx_rec_i(const uint32_t i, const uint32_t order,
								  const WORD_T dx, const WORD_T dy, const WORD_T dz,
								  const WORD_T x, const WORD_T y, uint64_t* cnt_xy)
{
#if(WORD_SIZE <= 32)
  if(i == WORD_SIZE) {
	 (*cnt_xy)++;
	 return;
  }

  //  uint32_t mask_order = (0xffffffff >> (32 - (order - 1)));
  uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
  for(uint32_t x_i = 0; x_i < 2; x_i++) {
	 for(uint32_t y_i = 0; y_i < 2; y_i++) {
		WORD_T new_x = ((x_i << i) | x) & mask_stride; 
		WORD_T new_y = ((y_i << i) | y) & mask_stride; 
		WORD_T new_xx = (new_x ^ dx) & mask_stride;
		WORD_T new_yy = (new_y ^ dy) & mask_stride;

		//		printf("[%s:%d] %8X %8X %8X %8X | %8X\n", __FILE__, __LINE__, new_x, new_y, new_xx, new_yy, diff_stride);
		WORD_T diff_stride = (((new_x & mask_stride) - (new_y & mask_stride)) ^ 
								  ((new_xx & mask_stride) - (new_yy & mask_stride))) & mask_stride;
		bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
		if(b_match) {
		  xdp_sub_approx_rec_i(i+1, order, dx, dy, dz, new_x, new_y, cnt_xy);
		}
	 }
  }
#endif // #if(WORD_SIZE <= 32)
}

double xdp_sub_approx_rec(const WORD_T dx, const WORD_T dy, const WORD_T dz, uint32_t order)
{
  //  printf("[%s:%d] Enter %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  assert(order >= 2);
  assert(order <= WORD_SIZE);

  uint32_t N = (1U << (order - 1)); // x[i-1:0]
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits
  uint64_t cnt_xy = 0;

  //  printf("[%s:%d] order % 2d mask_lsb %8X\n", __FILE__, __LINE__, order, mask_lsb);
  for(WORD_T x = 0; x < N; x++) {
	 for(WORD_T y = 0; y < N; y++) {
		//		printf("[%s:%d] %d %d\n", __FILE__, __LINE__, x, y);
		WORD_T xx = (x ^ dx) & mask_lsb;
		WORD_T yy = (y ^ dy) & mask_lsb;
		WORD_T diff_lsb = (((x - y) & mask_lsb) ^ ((xx - yy) & mask_lsb)) & mask_lsb;
		bool b_match_lsb = (diff_lsb == (dz & mask_lsb));
		if(b_match_lsb) {
		  uint32_t i = order - 1; // next bit index to be assigned
		  xdp_sub_approx_rec_i(i, order, dx, dy, dz, x, y, &cnt_xy);
		}
	 }
  }
  uint64_t all = (ALL_WORDS * ALL_WORDS);
  p = (double)cnt_xy / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

// fixed x
double xdp_sub_fixed_x_approx_exper(const WORD_T a1, const WORD_T a2,  const WORD_T db, const WORD_T dc, uint32_t order)
{
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  uint32_t cnt = 0;
  uint64_t all = ALL_WORDS;

  for(WORD_T b1 = 0; b1 < ALL_WORDS; b1++) {
	 WORD_T b2 = (b1 ^ db) & MASK;

	 WORD_T c1 = sub_approx(a1, b1, order);
	 WORD_T c2 = sub_approx(a2, b2, order);

	 WORD_T dx = (c1 ^ c2) & MASK;
	 assert((dx >= 0) && (dx < MOD));
	 if(dx == dc) {
		cnt++;
	 }
  }
  p = (double)cnt / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

void xdp_sub_fixed_x_approx_rec_i(const uint32_t i, const uint32_t order,
											 const WORD_T dy, const WORD_T dz, const WORD_T x, const WORD_T xx, 
											 const WORD_T y, uint64_t* cnt_y)
{
#if(WORD_SIZE <= 32)
  if(i == WORD_SIZE) {
	 (*cnt_y)++;
	 return;
  }

  //  uint32_t mask_order = (0xffffffff >> (32 - (order - 1)));
  uint32_t mask_stride = (0xffffffff >> (32 - order)) << (i + 1 - order); 
  for(uint32_t y_i = 0; y_i < 2; y_i++) {
	 WORD_T new_x = x & mask_stride; 
	 WORD_T new_xx = xx & mask_stride;
	 WORD_T new_y = ((y_i << i) | y) & mask_stride; 
	 WORD_T new_yy = (new_y ^ dy) & mask_stride;

	 //		printf("[%s:%d] %8X %8X %8X %8X | %8X\n", __FILE__, __LINE__, new_x, new_y, new_xx, new_yy, diff_stride);
	 WORD_T diff_stride = ((new_x - new_y) ^ (new_xx - new_yy)) & mask_stride;
	 //		bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
	 bool b_match = (((diff_stride >> i) & 1) == ((dz >> i) & 1)); // diff[i] ?= dz[i]
	 if(b_match) {
		xdp_sub_fixed_x_approx_rec_i(i+1, order, dy, dz, x, xx, new_y, cnt_y);
	 }
  }
#endif // #if(WORD_SIZE <= 32)
}

double xdp_sub_fixed_x_approx_rec(const WORD_T x, const WORD_T xx, const WORD_T dy, const WORD_T dz, uint32_t order)
{
  assert(WORD_SIZE <= 32);
  double p = 0.0;
#if(WORD_SIZE <= 32)
  //  printf("[%s:%d] Enter %s() ...\n", __FILE__, __LINE__, __FUNCTION__);
  assert(order >= 2);
  assert(order <= WORD_SIZE);

  uint32_t N = (1U << (order - 1)); // x[i-1:0]
  uint32_t mask_lsb = (0xffffffff >> (32 - (order - 1))); // mask order-1 LS bits
  uint64_t cnt_y = 0;

  //  printf("[%s:%d] order % 2d mask_lsb %8X\n", __FILE__, __LINE__, order, mask_lsb);
  for(WORD_T y = 0; y < N; y++) {
	 //		printf("[%s:%d] %d %d\n", __FILE__, __LINE__, x, y);
	 WORD_T yy = (y ^ dy) & mask_lsb;
	 WORD_T diff_lsb = (((x - y) & mask_lsb) ^ ((xx - yy) & mask_lsb)) & mask_lsb;
	 bool b_match_lsb = (diff_lsb == (dz & mask_lsb));
	 if(b_match_lsb) {
		uint32_t i = order - 1; // next bit index to be assigned
		xdp_sub_fixed_x_approx_rec_i(i, order, dy, dz, x, xx, y, &cnt_y);
	 }
  }
  uint64_t all = ALL_WORDS;
  p = (double)cnt_y / (double)all;
#endif // #if(WORD_SIZE <= 32)
  return p;
}

// --- SUB approximations ---}


