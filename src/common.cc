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
 * \file  common.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Common functions used accross all YAARX programs.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif

/**
 * Generate a random 32-bit value.
 */
uint32_t random32()
{
  return(random() ^ (random() << 16));
}

/** 
 * Hamming weight of a byte.
 */
uint32_t hw8(uint32_t x)
{
     int i;
     int w=0;
     for(i=0; i<8; i++) 
          w+=((x>>i) & 1);
     return w;
}

/** 
 * Hamming weight of a 32-bit word.
 */
uint32_t hw32(uint32_t x)
{
     int i;
     int w=0;
     for(i=3; i>=0; i--) {
          w+=hw8((x >> i*8) & 0xff);
     }
     return w;
}

/**
 * Returns true if the argument is an even number.
 */
bool is_even(uint32_t i)
{
  bool b_ret = true;
  if((i%2) == 1)
	 b_ret = false;
  return b_ret;
}

/**
 * Generate a random sparse n-bit difference with Hamming weight hw.
 */ 
uint32_t gen_sparse(uint32_t hw, uint32_t n)
{
  //  uint32_t mask = ~(0xffffffff << n);
  uint32_t x = 0;

  // at hw random positions i_pos set the bit x[i_pos] to 1
  for(uint32_t i = 0; i < hw; i++) {
	 uint32_t i_pos = random32() % n;
	 x = (1 << i_pos) | x;
  }
  return x;
}

/** 
 * Print a value in binary.
 */
void print_binary(uint32_t n)
{
  for(int i = 8; i >= WORD_SIZE; i--) {
	 printf(" ");
  }
  for(int i = WORD_SIZE - 1; i >= 0; i--) {
	 int msb = (n >> i) & 1;
	 printf("%d", msb); 
  }
}

/**
 * Compare two differentials by probability.
 */
bool operator<(differential_t x, differential_t y)
{
  if(x.p > y.p)					  // ! must be strictly >
	 return true;
  return false;
}

/**
 * Evaluate if two differentials are identical.
 * Returns TRUE if they are.
 */
bool operator==(differential_t a, differential_t b)
{
  bool b_ret = false;
  if((a.p == b.p) && (a.dx == b.dx) && (a.dy == b.dy)) {
	 b_ret = true;
  }
  return b_ret;
}

/**
 * Print the list of 2d differentials stored represented as an STL set
 * and ordered by index idx = ((2^n dx) + dy), where n is the word size.
 */
void print_set(const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy)
{
  uint32_t cnt_elms = 0;
  std::set<differential_t, struct_comp_diff_dx_dy>::iterator set_iter;
  for(set_iter = diff_set_dx_dy.begin(); set_iter != diff_set_dx_dy.end(); set_iter++, cnt_elms++) {
		uint32_t dx = set_iter->dx;
		uint32_t dy = set_iter->dy;
		double p = set_iter->p;
		printf("[%s:%d] %4d: %8X %8X %f (2^%f)\n", __FILE__, __LINE__, cnt_elms, dx, dy, p, log2(p));
  }
}

/**
 * Print the list of 2d differentials stored represented as an STL multiset
 * and ordered by probability.
 */
void print_mset(const std::multiset<differential_t, struct_comp_diff_p> diff_mset_p)
{
  uint32_t cnt_elms = 0;
  std::set<differential_t, struct_comp_diff_p>::iterator set_iter;
  for(set_iter = diff_mset_p.begin(); set_iter != diff_mset_p.end(); set_iter++, cnt_elms++) {
		uint32_t dx = set_iter->dx;
		uint32_t dy = set_iter->dy;
		double p = set_iter->p;
		printf("[%s:%d] %4d: %8X %8X %f\n", __FILE__, __LINE__, cnt_elms, dx, dy, p);
  }
}

