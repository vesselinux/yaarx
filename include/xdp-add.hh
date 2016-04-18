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
 * \file  xdp-add.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-add.cc: \copybrief xdp-add.cc.
 */ 
#ifndef XDP_ADD_H
#define XDP_ADD_H

#ifndef XDP_ADD_MSIZE
#define XDP_ADD_MSIZE 4 /**< Number of state values in the \f$\mathrm{xdp}^{+}\f$ S-function. */
#endif
#ifndef XDP_ADD_NMATRIX
#define XDP_ADD_NMATRIX 8 /**< Number of \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif
#ifndef XDP_ADD_NINPUTS
#define XDP_ADD_NINPUTS 2 /**< Number of inputs to the XOR operation. */
#endif
#ifndef XDP_ADD_ISTATE
#define XDP_ADD_ISTATE 0 /**< Initial state for computing the \f$\mathrm{xdp}^{+}\f$ S-function. */
#endif
#ifndef XDP_ADD_COLSUM
#define XDP_ADD_COLSUM 4 /**< Sum of non-zero elements in one column of the \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif
#ifndef XDP_ADD_NORM
#define XDP_ADD_NORM 1.0 /(double)XDP_ADD_COLSUM /**< Normalization factor for the \f$\mathrm{xdp}^{+}\f$ matrices. */
#endif

void xdp_add_alloc_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_free_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_normalize_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_print_matrices(gsl_matrix* A[2][2][2]);

void xdp_add_print_matrices_sage(gsl_matrix* A[2][2][2]);

void xdp_add_sf(gsl_matrix* A[2][2][2]);

double xdp_add(gsl_matrix* A[2][2][2], WORD_T da, WORD_T db, WORD_T dc);

double xdp_add_exper(const WORD_T da, const WORD_T db, const WORD_T dc);

WORD_T aop(WORD_T x, WORD_T n_in);

WORD_T cap(WORD_T x, WORD_T y);

bool is_eq(WORD_T x, WORD_T y, WORD_T z);

WORD_T eq(const WORD_T x, const WORD_T y, const WORD_T z);

WORD_T eq(const WORD_T x, const WORD_T y, const WORD_T z, const uint32_t word_size);

bool xdp_add_is_nonzero(WORD_T da, WORD_T db, WORD_T dc);

//double xdp_add_lm(WORD_T da, WORD_T db, WORD_T dc);

//double xdp_add_lm(WORD_T da, WORD_T db, WORD_T dc, uint32_t word_size);

/**
 * The XOR differential probability of ADD (\f$\mathrm{xdp}^{+}\f$),
 * as proposed in [Algorithm 2, Lipmaa, Moriai, FSE 2001]. \b Complexity: \f$O(n)\f$.
 *
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \return \f$p = \mathrm{xdp}^{+}(da, db \rightarrow dc)\f$
 * \see xdp_add
 *
 * Credits: Yann Le Corre for optimizations
 */
inline double xdp_add_lm(WORD_T da, WORD_T db, WORD_T dc)
{
#if 0 // DEBUG
  printf("[%s:%d] %s() %llX %llX %llX\n", __FILE__, __LINE__, __FUNCTION__, 
			(WORD_MAX_T)da, (WORD_MAX_T)db, (WORD_MAX_T)dc);
#endif// #if 0 // DEBUG
  double p = 0.0;
#if(WORD_SIZE <= 32) // mask without the MSB
  WORD_T mask_no_msb = (0xffffffffUL >> (32 - (WORD_SIZE - 1)));
  WORD_T eq_d = eq(da, db, dc);
  WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x00000001UL) & MASK;
#else // #if(WORD_SIZE <= 32)
  //  WORD_T mask_no_msb = (0xffffffffffffffffUL >> (64 - (WORD_SIZE - 1))); <- ULL
  WORD_T mask_no_msb = (0xffffffffffffffffULL >> (64 - (WORD_SIZE - 1)));
  WORD_T eq_d = eq(da, db, dc);
  WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x0000000000000001ULL) & MASK;
#endif // #if(WORD_SIZE <= 32)
  //  bool b_is_possible = ((eq((da << 1), (db << 1), (dc << 1)) & (da ^ db ^ dc ^ (da << 1))) == 0);
  bool b_is_possible = ((eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1))) == 0);
  if(b_is_possible) {
	 //	 WORD_T neq = ~eq(da, db, dc); // positions at which da,db and dc are not equal
	 WORD_T neq = ~eq_d; // positions at which da,db and dc are not equal
#if 1 // standard HW
	 uint32_t w = hamming_weight(neq & mask_no_msb);
#else // assembly instruction for HW (-mpopcnt)
	 uint32_t w = __builtin_popcount(neq & mask_no_msb);
#endif // #if 0 // standard HW
	 //	 p = (double)1.0 / (double)pow(2,w);
	 if (w == 64) { // this should almost never happen so we don't care if it is slow
		p = pow(2, -64);
	 } else {
		p = (double) 1.0 / (double)(1ULL << w); // efficient pow(2, w)
	 }
#if 0 // DEBUG
	 printf("\nneq = ");
	 print_binary(neq);
	 printf("\n");
	 printf("[%s:%d] w mask neq %d %llX %lld %lld\n", __FILE__, __LINE__, 
			  w, (WORD_MAX_T)mask, (WORD_MAX_T)neq, (WORD_MAX_T)(neq & mask_no_msb));
#endif // #if 1 // DEBUG
  }
  //  printf("[%s:%d] Exit %s()\n", __FILE__, __LINE__, __FUNCTION__);
  return p;
}

/**
 * Same as \ref xdp_add_lm but taking the word size as an input parameter --
 * used to compute the prob. of partial differentials
 *
 * Credits: Yann Le Corre for optimizations
 */
inline double xdp_add_lm(WORD_T da, WORD_T db, WORD_T dc, uint32_t word_size)
{
  double p = 0.0;
  if(word_size > 1) {
#if 0 // BUG?
	 WORD_MAX_T mask = (~0ULL >> (64 - word_size)); // full mask (word_size bits)
#endif
	 //#if(word_size <= 32) // mask without the MSB <--- BUG! must be WORD_SIZE
#if(WORD_SIZE <= 32) // mask without the MSB
	 //	 WORD_T mask = ~(0xffffffffUL << WORD_SIZE); // <--- BUG!!
	 WORD_T mask = ~(0xffffffffUL << word_size);
	 //	 WORD_T mask_no_msb = (mask >> 1);//(0xffffffffUL >> (32 - (word_size - 1)));
	 WORD_T eq_d = eq(da, db, dc);
	 WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x00000001) & mask;
#else // #if(word_size <= 32)
	 WORD_T mask = ~(0xffffffffffffffffULL << word_size);
	 //	 WORD_T mask_no_msb = (mask >> 1);//(0xffffffffffffffffULL >> (64 - (word_size - 1)));
	 WORD_T eq_d = eq(da, db, dc);
	 WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x0000000000000001ULL) & mask;
#endif // #if(WORD_SIZE <= 32)
	 // bool b_is_possible = ((eq((da << 1), (db << 1), (dc << 1), word_size) & (da ^ db ^ dc ^ (da << 1))) == 0);

	 //	 printf("[%s:%d] word_size %d mask %llX mask_no_msb %X\n", __FILE__, __LINE__, word_size, mask, mask_no_msb);

	 bool b_is_possible = ((eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1))) == 0);
	 if(b_is_possible) {
		// WORD_T neq = ~eq(da, db, dc, word_size); // positions at which da,db and dc are not equal
		WORD_T neq = ~eq_d; // positions at which da,db and dc are not equal
#if 1 // standard HW
		//		uint32_t w = hamming_weight(neq & mask_no_msb);
		uint32_t w = hamming_weight(neq & (mask >> 1));
#else // assembly instruction for HW (-mpopcnt)
		uint32_t w = __builtin_popcount(neq & mask_no_msb);
#endif // #if 0 // standard HW
		//		p = (double)1.0 / (double)pow(2,w);
		if (w == 64) { // this should almost never happen so we don't care if it is slow
		  p = pow(2, -64);
		} else {
		  p = (double) 1.0 / (double)(1ULL << w); // efficient pow(2, w)
		}

	 }
  } else {
	 if((da ^ db) == dc) {
		p = 1.0;
	 } else {
		p = 0.0;
	 }
  }
  return p;
}

/**
 * The log base 2 of the XOR differential probability of ADD
 * (\f$\mathrm{xdp}^{+}\f$), as proposed in [Algorithm 2, Lipmaa,
 * Moriai, FSE 2001]. \b Complexity: \f$O(n)\f$.
 *
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \return \f$p = \log_2(\mathrm{xdp}^{+}(da, db \rightarrow dc))\f$
 * \see xdp_add_lm
 *
 * Credits: Yann Le Corre
 */
inline int xdp_add_lm_log2(WORD_T da, WORD_T db, WORD_T dc)
{
	int p;

#if(WORD_SIZE <= 32)
	const WORD_T mask = (0xffffffffUL >> (32 - (WORD_SIZE - 1)));
#else // #if(WORD_SIZE <= 32)
	const WORD_T mask = (0xffffffffffffffffULL >> (64 - (WORD_SIZE - 1)));
#endif // #if(WORD_SIZE <= 32)

	WORD_T eq_d = eq (da, db, dc);
#if (WORD_SIZE <= 32)
	WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x00000001UL) & MASK;
#else
	WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x0000000000000001ULL) & MASK;
#endif
	bool b_is_possible = ((eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1))) == 0);
	if (b_is_possible)
	{
		WORD_T neq = ~eq_d;		// positions at which da,db and dc are not equal
		//		uint32_t w = __builtin_popcount (neq & mask); // <- not work for word_size > 32
		//		uint32_t w = __builtin_popcountll (neq & mask); // <- WORKS for word_size > 32
		uint32_t w = hamming_weight(neq & mask);
		if (w == 64)
		{
			p = -64;
		}
		else
		{
			p = -w;
		}
	}
	else
	{
		p = LOG0;
	}
	return p;
}

/**
 * Same as \ref xdp_add_lm_log2 but taking the word size as in input parameter --
 * used to compute the prob. of partial differentials
 * Credits: Yann Le Corre
 * \see xdp_add_lm, xdp_add_lm_log2
 */
inline int xdp_add_lm_log2(WORD_T da, WORD_T db, WORD_T dc, uint32_t word_size)
{
	int p;
	if (word_size > 1)
	{
#if (WORD_SIZE <= 32)
		WORD_T mask =  ~(0xffffffffUL << word_size);
#else
		WORD_T mask =  ~(0xffffffffffffffffULL << word_size);
#endif

		WORD_T eq_d = eq(da, db, dc);
		//		WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x00000001) & mask;
#if (WORD_SIZE <= 32)
		WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x00000001UL) & mask;
#else
		WORD_T eq_d_sl_1 = ((eq_d << 1) | 0x0000000000000001ULL) & mask;
#endif
		bool b_is_possible = ((eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1))) == 0);
		if (b_is_possible)
		{
			WORD_T neq = ~eq_d & (mask >> 1);	// positions at which da,db and dc are not equal
			//			uint32_t w = __builtin_popcount(neq); // <- not work for word_size > 32
			//		uint32_t w = __builtin_popcountll (neq & mask); // <- WORKS for word_size > 32
			uint32_t w = hamming_weight(neq);
			if (w == 64)
			{
				p = -64;
			}
			else
			{
				p = -w;
			}
		}
		else
		{
			p = LOG0;
		}
	}
	else
	{
	  if (((da & 1) ^ (db & 1)) == (dc & 1)) // lsb
		{
			p = 0;
		}
		else
		{
			p = LOG0; // prob = 0!
		}
	}
	return p;
}


/**
 * For three \f$n\f$-bit input words \f$x,y,z\f$
 * compute an \f$n\f$-bit output word \f$e\f$ such that 
 * \f$e[i] = 1 \iff x[i] = y[i] = z[i]\f$ and
 * \f$e[i] = 0\f$ otherwise; \f$0 \le i < n\f$.
 *
 * \param x first input word
 * \param y second input word.
 * \param z third input word.
 * \return \f$e : e[i] = 1 \iff x[i] = y[i] = z[i],~ 0 \le i < n\f$.
 *
 * \note credits: Yann Le Corre
 */
static inline WORD_T eq_opt(const WORD_T x, const WORD_T y, const WORD_T z)
{
	WORD_T e = ~((x ^ y) | (x ^ z)) & MASK;
	return e;
}

/**
 * The XOR differential probability of ADD (\f$\mathrm{xdp}^{+}\f$),
 * as proposed in [Algorithm 2, Lipmaa, Moriai, FSE 2001]. \b Complexity: \f$O(n)\f$.
 *
 * \param da first input difference.
 * \param db second input difference.
 * \param dc output difference.
 * \return \f$p = \mathrm{xdp}^{+}(da, db \rightarrow dc)\f$
 * \see xdp_add
 *
 * Credits: Yann Le Corre for optimizations
 */
static inline int xdp_add_lm_log2_opt(WORD_T da, WORD_T db, WORD_T dc)
{
	const WORD_T eq_d = eq_opt(da, db, dc);
	const WORD_T eq_d_sl_1 = ((eq_d << 1) | (WORD_T)1) & MASK;
	const WORD_T b_is_possible_if_zero = (eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1)));
	if (b_is_possible_if_zero == 0)
	{
		const WORD_T neq = ~eq_d & MASK_NO_MSB; /* positions at which da,db and dc are not equal */
		const int w = builtin_hamming_weight(neq);
		return -w;
	}
	else
	{
		return LOG0;
	}
}

/**
 * Same as \ref xdp_add_lm_log2_opt but taking the word size as an input parameter --
 * used to compute the prob. of partial differentials
 *
 * Credits: Yann Le Corre for optimizations
 */
static inline int xdp_add_lm_log2_opt(WORD_T da, WORD_T db, WORD_T dc, uint32_t word_size)
{
	int p;
	if (word_size > 1)
	{
#if (WORD_SIZE <= 32)
		const WORD_T mask =  ~(0xffffffffUL << word_size);
#else
		const WORD_T mask =  ~(0xffffffffffffffffULL << word_size);
#endif
		const WORD_T eq_d = eq_opt(da, db, dc);
		const WORD_T eq_d_sl_1 = ((eq_d << 1) | (WORD_T)1) & mask;
		const WORD_T b_is_possible_if_zero = (eq_d_sl_1 & (da ^ db ^ dc ^ (da << 1)));
		if (b_is_possible_if_zero == 0)
		{
			const WORD_T neq = ~eq_d & (mask >> 1); /* positions at which da,db and dc are not equal */
			p = -builtin_hamming_weight(neq);
		}
		else
		{
			p = LOG0;
		}
	}
	else
	{
		if (((da ^ db ^dc) & (WORD_T)1) == 0)
		{
			p = 0;
		}
		else
		{
			p = LOG0;
		}
	}
	return p;
}

#endif  // #ifndef XDP_ADD_H
