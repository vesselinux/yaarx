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
 * \file  common.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for common.cc. \copybrief common.cc.
 */ 
#ifndef COMMON_H
#define COMMON_H

// Global file #include-s
#ifndef IOSTREAM_H
#define IOSTREAM_H /**< C++ iostream */
#include <iostream>
#endif
#ifndef CASSERT_H
#define CASSERT_H	 /**< C++ cassert */
#include <cassert>
#endif
#ifndef MATH_H
#define MATH_H /**< math.h */
#include <math.h>
#endif
#ifndef STRING_H
#define STRING_H /**< string.h */
#include <string.h>
#endif
#ifndef GSL_BLAS_H
#define GSL_BLAS_H /**< GSL gsl/gsl_blas.h */
#include <gsl/gsl_blas.h>
#endif
#ifndef STL_ALGORITHM_H
#define STL_ALGORITHM_H
#include <algorithm> /**< STL algorithm */
#endif
#ifndef STL_VECTOR_H
#define STL_VECTOR_H /**< STL vector */
#include <vector>  
#endif
#ifndef STL_SET_H
#define STL_SET_H	/**< STL set */
#include <set>  
#endif
#ifndef GMP_H
#define GMP_H
#include <gmp.h>
#endif
#ifndef GMPXX_H
#define GMPXX_H
#include <gmpxx.h>
#endif

// Macros
#ifndef WORD_SIZE
#define WORD_SIZE 32			  /**< Word size in  bits. */
#endif
#ifndef ALL_WORDS
#define ALL_WORDS (1ULL << WORD_SIZE) /**< Total number of words of size WORD_SIZE. */
#endif
#ifndef MASK
#define MASK (0xffffffff >> (32 - WORD_SIZE)) /**< A mask for the WORD_SIZE LS bits of a 32-bit word. */
#endif
#ifndef MOD
#define MOD (1ULL << WORD_SIZE) /**< The value 2^{WORD_SIZE}. */
#endif
#ifndef TEA_LSH_CONST
#define TEA_LSH_CONST 4//9//4 /**< Left shift constant of TEA/XTEA. */
#endif
#ifndef TEA_RSH_CONST
#define TEA_RSH_CONST 5//14//5 /**< Right shift constant of TEA/XTEA. */
#endif
#ifndef DELTA_INIT
#define DELTA_INIT 0x9e3779b9	 /**< Initial round constant \f$\delta\f$ of TEA/XTEA. */
#endif
#ifndef NPAIRS
#define NPAIRS (1ULL << 15) /**< Number of chosen plaintext pairs used in experimentally verifying differential probabilities. */
#endif
#ifndef NROUNDS
#define NROUNDS 20//20//32//20//13//20//9 /**< Number of rounds in reduced-round versions of block ciphers TEA and XTEA. */
#endif
#ifndef NDELTA
#define NDELTA (NROUNDS / 2) /**< Number round  constants in TEA/XTEA. */
#endif

#ifndef XOR
#define XOR(x,y) ((x ^ y) & MASK) /**< The XOR operation on words of size \ref WORD_SIZE */
#endif
#ifndef ADD
#define ADD(x,y) ((x + y) & MASK) /**< The ADD operation on words of size \ref WORD_SIZE */
#endif
#ifndef SUB
#define SUB(x,y) ((uint32_t)(x - y + MOD) & MASK) /**< The modular subtraction (SUB) operation on words of size \ref WORD_SIZE */
#endif
#ifndef LSH
#define LSH(x,r) ((x << r) & MASK) /**< Left bit shift by r positions on word x of size \ref WORD_SIZE */
#endif
#ifndef RSH
#define RSH(x,r) ((x >> r) & MASK) /**< Right bit shift by r positions on word x of size \ref WORD_SIZE */
#endif
#ifndef LROT
#define LROT(x,r) (((x << r) | (x >> (WORD_SIZE - r))) & MASK) /**< Rotate \p x by \p r positions to the left; \p x is of size \ref WORD_SIZE */
#endif
#ifndef RROT
#define RROT(x,r) (((x >> r) | (x << (WORD_SIZE - r))) & MASK) /**< Rotate \p x by \p r positions to the right; \p x is of size \ref WORD_SIZE */
#endif
#ifndef MUL
#define MUL(x,y) ((x * y) & MASK) // mod 2^n
//#define MUL(x,y) ((x * y) % (MOD + 1)) // mod (2^n + 1)
#endif

/**
 * The ARX operation on \ref WORD_SIZE bit words: 
 * \f$\mathrm{ARX}(r,x,y,z) = (((x + y) <\ll r) \oplus z)\f$. 
 */
#ifndef ARX
#define ARX(r,x,y,z) XOR(z,LROT(ADD(x,y),r)) 
#endif

/** 
 *  DEBUG flags for test files.
 */
#define DEBUG_XDP_ADD_TESTS 0
#define DEBUG_MAX_XDP_ADD_TESTS 0
#define DEBUG_ADP_XOR_TESTS 0
#define DEBUG_ADP_XOR3_TESTS 0
#define DEBUG_MAX_ADP_XOR_TESTS 0
#define DEBUG_ADP_XOR_FI_TESTS 0
#define DEBUG_MAX_ADP_XOR_FI_TESTS 0
#define DEBUG_MAX_ADP_XOR3_TESTS 0
#define DEBUG_MAX_ADP_XOR3_SET_TESTS 0
#define DEBUG_ADP_RSH_XOR_TESTS 0
#define DEBUG_ADP_SHIFT_TESTS 0
#define DEBUG_EADP_TEA_F_TESTS 0
#define DEBUG_ADP_TEA_F_FK_TESTS 0
#define DEBUG_XDP_TEA_F_FK_TESTS 0
#define DEBUG_XDP_XTEA_F_FK_TESTS 0
#define DEBUG_ADP_XTEA_F_FK_TESTS 0

/** 
 *  DEBUG flags for source files.
 */
#define DEBUG_ADP_RSH_XOR 0
#define DEBUG_ADP_TEA_F_FK 0
#define DEBUG_XDP_TEA_F_FK 0

/**
 * A difference structure.
 */
typedef struct {
  uint32_t dx; /**< A difference. */
  double p;		/**< Probability with which dx holds. */
} difference_t;

/**
 * A differential composed of three differences.
 * For example, da and db can be input differences to XOR
 * and dc can be the corresponding output difference.
 * The differential holds with probability p.
 */
typedef struct {
  uint32_t da;	/**< Input difference. */
  uint32_t db; /**< Input difference. */
  uint32_t dc; /**< Output difference. */
  double p; /**< Probability of the differential. */
} differential_3d_t;

/**
  * A differential composed of two differences.
  */
typedef struct {
  uint32_t dx; /**< Input difference. */
  uint32_t dy; /**< Input difference. */
  uint32_t npairs; /**< Number of right pairs. */
  double p;	/**< Probability of the differential. */
} differential_t;

/**
  * Comparing 3d differentials by probability.
  */
struct struct_comp_diff_3d_p : public std::binary_function<differential_3d_t, differential_3d_t, bool>
{
  bool operator()(differential_3d_t a, differential_3d_t b) const
  {
	 bool b_more = (a.p > b.p);	  // higher probability first
	 return b_more;
  }
};

/**
  * Comparing 2d differentials by probability.
  */
struct struct_comp_diff_p : public std::binary_function<differential_t, differential_t, bool>
{
  bool operator()(differential_t a, differential_t b) const
  {
	 bool b_more = (a.p > b.p);	  // higher probability first
	 return b_more;
  }
};

/** 
  * Compare two differentials a,b by the magnitute of the indexes a_idx, b_idx:
  * lower indices are listed first. For example,
  * the indices of the differentials a(dx,dy,p) and b(dx,dy,p) are
  * a_idx = (a.dx 2^{n} + a.dy) = (a.dx | a.dy) and  b_idx = (b.dx 2^{n} + b.dy) = (b.dx | b.dy)
  * where n is the word size and '|' denotes concatenation. Thus a_idx and b_idx are compared.
  */ 
struct struct_comp_diff_dx_dy : public std::binary_function<differential_t, differential_t, bool>
{
  inline bool operator()(differential_t a, differential_t b)
  {
	 bool b_less = true;
	 if(a.dx != b.dx) {
		b_less = (a.dx < b.dx);
	 } else {
		b_less = (a.dy < b.dy);
	 }
	 return b_less;
  }
};

// Function declarations
uint32_t random32();

uint32_t hw8(uint32_t x);

uint32_t hw32(uint32_t x);

bool is_even(uint32_t i);

uint32_t gen_sparse(uint32_t hw, uint32_t n);

void print_binary(uint32_t n);

bool operator==(differential_t a, differential_t b);

bool operator<(differential_t x, differential_t y);

void print_set(const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy);

void print_mset(const std::multiset<differential_t, struct_comp_diff_p> diff_mset_p);

#endif  // #ifndef COMMON_H
