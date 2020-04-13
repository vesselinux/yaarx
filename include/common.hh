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
#ifndef SSTREAM_H
#define SSTREAM_H	 /**< C++ sstream */
#include <sstream>
#endif
#ifndef SYS_TIME_H
#define SYS_TIME_H	 /**< C time header */
#include <sys/time.h> // gettimeofday
#endif
#ifndef MAP_H
#define MAP_H	 /**< C++ map */
#include <map>
#endif
#ifndef QUEUE_H
#define QUEUE_H	 /**< C++ queue */
#include <queue>
#endif
#ifndef UNORDERED_MAP_H
#define UNORDERED_MAP_H	 /**< C++ unordered_map */
#include <unordered_map>
#endif
#ifndef BOOST_FUNCTIONAL_HASH_H
#define BOOST_FUNCTIONAL_HASH_H	 /**< C++ STL Boost hash */
#include <boost/functional/hash.hpp>
#endif
#ifndef BOOST_ALGORITHM_STRING_PREDICATE_H
#define BOOST_ALGORITHM_STRING_PREDICATE_H	 /**< C++ STL Boost algorithm */
#include <boost/algorithm/string/predicate.hpp>
#endif
#ifndef BOOST_UNORDERED_MAP_H
#define BOOST_UNORDERED_MAP_H	 /**< C++ STL Boost unordered map */
#include <boost/unordered_map.hpp>
#endif
#ifndef MATH_H
#define MATH_H /**< math.h */
#include <math.h>
#endif
#ifndef STRING_H
#define STRING_H /**< string.h */
#include <string.h>
#endif
#ifndef IOMANIP_H
#define IOMANIP_H	/**< C++ iomanip */
#include <iomanip>				  // setfill setw
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
#ifndef STL_ARRAY_H
#define STL_ARRAY_H /**< STL array */
#include <array>
#endif
#ifndef STL_SET_H
#define STL_SET_H	/**< STL set */
#include <set>  
#endif
#ifndef GMP_H
#define GMP_H
#include <gmp.h> /** GMP library */
#endif
#ifndef GMPXX_H
#define GMPXX_H
#include <gmpxx.h> /** GMPXX library */
#endif
#ifndef CHRONO_H
#define CHRONO_H
#include <chrono>
#endif
//#ifndef GVC_H
//#define GVC_H
//#include <gvc.h> /**< GraphViz library */
//#endif

// Macros
#define NROUNDS_MAX 100 /**< Max. number of rounds */
#ifndef WORD_SIZE
#define WORD_SIZE 32//16//32//64//32//64//32//8//4//32//16//8//16//32//4//32//8//32//7//4//7//3//4//5//6//32//64//8//64//32 /**< Word size in  bits. */
#endif
#ifndef NROUNDS
#define NROUNDS 5//6//5//20 /**< Number of rounds in reduced-round versions of target ciphers. */
#endif
#ifndef ALL_WORDS
#define ALL_WORDS (1ULL << WORD_SIZE) /**< Total number of words of size WORD_SIZE. */
#endif
#ifndef MASK
#if(WORD_SIZE <= 32)
#define MASK (0xffffffffUL >> (32 - WORD_SIZE)) /**< A mask for the WORD_SIZE LS bits of a 32-bit word. */
#define MASK_NO_MSB (0xffffffffUL >> (32 - (WORD_SIZE - 1)))
#else // #if(WORD_SIZE > 32)
#define MASK (0xffffffffffffffffULL >> (64 - WORD_SIZE)) /**< A mask for the WORD_SIZE LS bits of a 32-bit word. */
#define MASK_NO_MSB (0xffffffffffffffffULL >> (64 - (WORD_SIZE - 1)))
#endif // #if(WORD_SIZE <= 32)
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
#ifndef NDELTA
#define NDELTA (NROUNDS / 2) /**< Number round  constants in TEA/XTEA. */
#endif

#ifndef WORD_T // abstract word type
#if (WORD_SIZE <= 32)
#define WORD_T uint32_t
#else
#define WORD_T uint64_t
#endif // #if (WORD_SIZE <= 32)
#endif // #ifndef WORD
#ifndef WORD_MAX_T // max word type on the target system
#define WORD_MAX_T long long unsigned int // = uint64_t
#endif // #ifdef WORD_MAX_T

#define LOG0 -10000

#ifndef XOR
#define XOR(x,y) ((x ^ y) & (WORD_T)MASK) /**< The XOR operation on words of size \ref WORD_SIZE */
#endif
#ifndef ADD
#define ADD(x,y) ((x + y) & (WORD_T)MASK) /**< The ADD operation on words of size \ref WORD_SIZE */
#endif
#ifndef SUB
#if(WORD_SIZE < 64)
#define SUB(x,y) ((WORD_T)(x - y + MOD) & (WORD_T)MASK) /**< The modular subtraction (SUB) operation on words of size \ref WORD_SIZE */
#else // #if(WORD_SIZE == 64)
#define SUB(x,y) ((WORD_T)(x - y)) /**< The modular subtraction (SUB) operation on words of size 64-bit */
#endif // #if(WORD_SIZE < 64)
#endif // #ifndef SUB
//#ifndef SUBMODN
//#define SUBMODN(a,b,n) (((a - b) + n)  % (n)) /**< subtraction modulo n: (a - b) mod n */
//#endif // #ifndef SUBMODN
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
#define DEBUG_XDP_ADD_TESTS 1
#define DEBUG_MAX_XDP_ADD_TESTS 0
#define DEBUG_ADP_XOR_TESTS 1
#define DEBUG_ADP_XOR3_TESTS 0
#define DEBUG_MAX_ADP_XOR_TESTS 1//0
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

//uint32_t hw32(const uint32_t x);
uint32_t hamming_weight(const WORD_T w);

/** 
 * Hamming weight of a WORD-bit word (efficient).
 */
static inline int builtin_hamming_weight(const WORD_T w)
{
	return __builtin_popcountll(w);
}

/**
 * A difference structure.
 */
typedef struct {
  WORD_T dx; /**< A difference. */
  double p;		/**< Probability with which dx holds. */
} difference_t;

/**
 * A differential composed of three differences.
 * For example, da and db can be input differences to XOR
 * and dc can be the corresponding output difference.
 * The differential holds with probability p.
 */
typedef struct {
  WORD_T dx;	/**< Input difference. */
  WORD_T dy; /**< Input difference. */
  WORD_T dz; /**< Output difference. */
  double p; /**< Probability of the differential. */
  int log2p; /**< Log base 2 of the probability p: log2p = log2(p)*/
} differential_3d_t;

/**
  * A differential composed of two differences.
  */
typedef struct {
  WORD_T dx; /**< Input difference. */
  WORD_T dy; /**< Output difference. */
  WORD_T npairs; /**< Number of right pairs. */
  double p;	/**< Probability of the differential. */
} differential_t;

/**
 * A set of values:
 *   - If \p fixed[i] = 0, then the i-th bit of the value is fixed to \p val[i].
 *   - If \p fixed[i] = 1, then \p val[i] can be either 0 and 1 i.e. \p val[i] = * .
 */
struct set_t
{
  WORD_T val;
  WORD_T fixed; /**< 0 means fixed; 1 means not fixed. */
};

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
  * Compare two differentials a,b by the magnitute of the indexes a_idx, b_idx:
  * lower indices are listed first. For example,
  * the indices of the differentials a(dx,dy,p) and b(dx,dy,p) are
  * a_idx = (a.dx 2^{2n} + a.dy 2^{n} + a.dz) = (a.dx | a.dy | a.dz) and  
  * b_idx = (b.dx 2^{2n} + b.dy 2^{n} + b.dz) = (b.dx | b.dy | b.dz)
  * where n is the word size and '|' denotes concatenation. Thus a_idx and b_idx are compared.
  */ 
struct struct_comp_diff_3d_dx_dy_dz : public std::binary_function<differential_3d_t, differential_3d_t, bool>
{
  inline bool operator()(differential_3d_t a, differential_3d_t b)
  {
	 bool b_less = true;

	 if(a.dx != b.dx) {
		b_less = (a.dx < b.dx);
	 } else {
		if(a.dy != b.dy) {
		  b_less = (a.dy < b.dy);
		} else {
		  b_less = (a.dz < b.dz);
		}
	 }
	 return b_less;
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
  * Comparing 2d differentials by Hamming weight of DX !!!
  */
struct struct_comp_diff_hw : public std::binary_function<differential_t, differential_t, bool>
{
  bool operator()(differential_t a, differential_t b) const
  {
	 uint32_t hw_a = hamming_weight(a.dx);// + hamming_weight(a.dy); 
	 uint32_t hw_b = hamming_weight(b.dx);// + hamming_weight(b.dy); 
	 bool b_more = (hw_a < hw_b);	  // higher HW last
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

typedef unsigned long long timestamp_t;

timestamp_t get_timestamp();

// Function declarations
//uint32_t random32();
//uint64_t random64();
WORD_T xrandom();
uint32_t hw8(const uint32_t x);
WORD_T parity(const WORD_T x);
bool is_even(uint32_t i);
WORD_T gen_sparse(uint32_t hw, uint32_t n);
//void print_binary(const WORD_T n);
//void print_binary(const WORD_T n, const uint32_t word_size);
void print_binary(const uint64_t n);
void print_binary(const uint64_t n, const uint32_t word_size);
bool operator==(differential_t a, differential_t b);
bool operator<(differential_t x, differential_t y);
bool operator<(difference_t x, difference_t y);
void print_set(const std::set<differential_t, struct_comp_diff_dx_dy> diff_set_dx_dy);
void print_mset(const std::multiset<differential_t, struct_comp_diff_p> diff_mset_p);
bool sort_comp_diff_3d_p(differential_3d_t a, differential_3d_t b);
void yaarx_alloc_matrices_3d(WORD_T**** A, uint32_t A_len);
void yaarx_free_matrices_3d(WORD_T*** A, uint32_t A_len);
void yaarx_alloc_matrices_3d(gsl_matrix* A[2][2][2], uint32_t A_len);
void yaarx_free_matrices_3d(gsl_matrix* A[2][2][2], uint32_t A_len);
void yaarx_alloc_matrices_2d(WORD_T*** A, uint32_t A_rows, uint32_t A_cols);
void yaarx_free_matrices_2d(WORD_T** A, uint32_t A_rows, uint32_t A_cols);
void yaarx_alloc_matrices_4d(WORD_T***** A, uint32_t A_dim);
void yaarx_free_matrices_4d(WORD_T**** A, uint32_t A_dim);

#endif  // #ifndef COMMON_H
