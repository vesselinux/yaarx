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
 * \file  speck.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for speck.cc: \copybrief speck.cc .
 */ 
#ifndef SPECK_H
#define SPECK_H

#define SPECK_MAX_NKEY_WORDS 4
#define SPECK_KEY_LEN_BITS 128
#define SPECK_MAX_NROUNDS 34
#define SPECK_RIGHT_ROT_CONST 8
#define SPECK_LEFT_ROT_CONST 3
#define SPECK_RIGHT_ROT_CONST_16BITS 7
#define SPECK_LEFT_ROT_CONST_16BITS 2
//#define SPECK_P_THRES (1.0 / (double)(1UL << 3))// for WORD_SIZE 16
#define SPECK_P_THRES (1.0 / (double)(1UL << 16))//(1.0 / (double)(1UL << 5)) // (1.0 / (double)(1UL << 7)) <------ Speck32
#define SPECK_MAX_DIFF_CNT (1ULL << 22) //(1ULL << 22)//(1ULL << 16)
#define SPECK_NPAIRS (1ULL << 24)
#define SPECK_BEST_TRAIL_LOG2P -58//-40//-58
#define SPECK_MAX_HW 16//9//7//9//16//9//5//5//16//7//9//6//6//7//9//9//9//4
#define SPECK_CLUSTER_MAX_HW 9//9//7//9//7//9//7//9//7//9//9//5
#define SPECK_BACK_TO_HWAY 0
#define SPECK_GREEDY_SEARCH 0//1 <--------
#define SPECK_NDIFFS 2
#define SPECK_EPS (double)(1.0 / (double)(1ULL << 15)) // (double)(1ULL << 15))
#define SPECK_DEBUG 0
#define SPECK_TRAIL_LEN_MAX 14
#define SPECK_BEST_TRAILS_LATEX_FILE "speck-trails.tex"
#if (WORD_SIZE == 24)
#define SPECK_48 1				  // apply special search only for the version SPECK48
#define SPECK_P_THRES (1.0 / (double)(1UL << 7))
#else
#define SPECK_48 0
#define SPECK_P_THRES (1.0 / (double)(1UL << 5))
#endif // #if (WORD_SIZE == 24)
#define SPECK_USE_PRECOMPUTED_BOUNDS 0//1 // use precomputed bounds

#define SPECK_TRAIL_LEN 20
#define SPECK_LOG_FILE "speck.log"

//#define SPECK_PDDT_MAX_HW 7

struct speck_diff_equal_to
  : std::binary_function<std::array<differential_t, SPECK_NDIFFS>, std::array<differential_t, SPECK_NDIFFS>, bool>
{
  bool operator()(std::array<differential_t, SPECK_NDIFFS> const& a,
						std::array<differential_t, SPECK_NDIFFS> const& b) const
  {
	 assert(a.size() == SPECK_NDIFFS);
	 assert(b.size() == SPECK_NDIFFS);

	 bool b_equal = true;
	 uint32_t i = 0;
	 if(a.size() == b.size()) {
		while((i != a.size()) && (i != b.size()) && (b_equal == true)) {
			 b_equal = ((a[i].dx == b[i].dx) && (a[i].dy == b[i].dy));
			 i++;
		  }
	 } else {
		b_equal = false;
	 }
#if 1		 // DEBUG
	 if(b_equal) {
		assert(i == a.size()); 
		assert(i == b.size());
	 };
#endif
	 //	 return boost::algorithm::iequals(x, y, std::locale());
	 return b_equal;
  }
};

struct speck_diff_hash
  : std::unary_function<std::array<differential_t, SPECK_NDIFFS>, std::size_t>
{
  std::size_t operator()(std::array<differential_t, SPECK_NDIFFS> const& a) const
  {
	 assert(a.size() == SPECK_NDIFFS);
	 std::size_t seed = 0;

	 for(uint32_t i = 0; i < a.size(); i++) {
		boost::hash_combine(seed, a[i].dx);
		boost::hash_combine(seed, a[i].dy);
	 }
	 return seed;
  }
};

struct speck_trail_equal_to
  : std::binary_function<std::array<differential_t, NROUNDS>, std::array<differential_t, NROUNDS>, bool>
{
  bool operator()(std::array<differential_t, NROUNDS> const& a,
						std::array<differential_t, NROUNDS> const& b) const
  {
	 assert(a.size() == NROUNDS);
	 assert(b.size() == NROUNDS);

	 bool b_equal = true;
	 uint32_t i = 0;
	 if(a.size() == b.size()) {
		while((i != a.size()) && (i != b.size()) && (b_equal == true)) {
			 b_equal = ((a[i].dx == b[i].dx) && (a[i].dy == b[i].dy));
			 i++;
		  }
	 } else {
		b_equal = false;
	 }
#if 1		 // DEBUG
	 if(b_equal) {
		assert(i == a.size()); 
		assert(i == b.size());
	 };
#endif
	 //	 return boost::algorithm::iequals(x, y, std::locale());
	 return b_equal;
  }
};

struct speck_trail_hash
  : std::unary_function<std::array<differential_t, NROUNDS>, std::size_t>
{
  std::size_t operator()(std::array<differential_t, NROUNDS> const& a) const
  {
	 assert(a.size() == NROUNDS);
	 std::size_t seed = 0;

	 for(uint32_t i = 0; i < a.size(); i++) {
		boost::hash_combine(seed, a[i].dx);
		boost::hash_combine(seed, a[i].dy);
	 }
	 return seed;
  }
};

uint32_t speck_compute_nkeywords(uint32_t word_size, uint32_t key_size);
uint32_t speck_get_keysize(uint32_t word_size);
void speck_get_rot_const(uint32_t word_size, uint32_t* alpha, uint32_t* beta);
uint32_t speck_compute_nrounds(uint32_t word_size, uint32_t nkey_words);
void speck_key_expansion(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds, uint32_t nkey_words,
								 uint32_t alpha, uint32_t beta);
void speck_encrypt(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t alpha, uint32_t beta,
						 WORD_T* x_in, WORD_T* y_in);
void speck_decrypt(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t alpha, uint32_t beta,
						 WORD_T* x_in, WORD_T* y_in);
#endif  // #ifndef SPECK_H
