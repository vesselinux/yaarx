/*
 * This file is part of the Toolkit for the Differential Cryptanalysis
 * of ARX-based Cryptographic Constructions.
 *
 * (c) 2010 Nicky Mouha, Vesselin Velichkov,
 *          Christophe De Canni`{e}re and Bart Preneel
 */
/**
 * \file  dp-matrix-minimize.hh
 * \author N. Mouha, V. Velichkov, C. De Canni`{e}re and B. Preneel
 * \date 2010
 * \brief Minimize the size of a given set of transition probability matrices by detecting equivalent states.
 */ 
#ifndef DP_MATRIX_MINIMIZE_H
#define DP_MATRIX_MINIMIZE_H

#ifndef COMMON_H
#include "common.hh"
#endif

template <uint32_t M, uint32_t C>
bool is_vec_equal(const uint32_t q[M][C], const uint32_t c[M][C][C], const uint32_t i) 
{
  for (uint32_t k = 0; k < M; ++k)
	 for (uint32_t j = 0; j < C; ++j)
		if (q[k][j] != c[k][i][j])
		  return false;

  return true;
}

template <uint32_t M, uint32_t C>
uint32_t find_state(const uint32_t q[M][C], const uint32_t c[M][C][C], const uint32_t n) 
{
  for (uint32_t i = 0; i < n; ++i)
	 if (is_vec_equal<M>(q, c, i))
		return i;

  return n;
}

template <uint32_t M, uint32_t N, uint32_t C>
uint32_t combine_equiv(const uint32_t m[M][N][N], uint32_t c[M][C][C]) 
{
  uint32_t r[2][N] = {{0}};
  uint32_t* s = r[0];
  uint32_t* t = r[1];
  uint32_t n = 0;

  while (true) {
    const uint32_t p = n;
    n = 0;

    for (uint32_t i = 0; i < N; ++i) {
      uint32_t q[M][C] = {{0}};

      for (uint32_t k = 0; k < M; ++k) {
        for (uint32_t j = 0; j < N; ++j) {
          q[k][s[j]] += m[k][i][j];
		  }
		}

      t[i] = find_state<M>(q, c, n);

      if (t[i] == n) {
        assert(n < C);

        for (uint32_t k = 0; k < M; ++k) {
          for (uint32_t j = 0; j < C; ++j) { 
            c[k][n][j] = q[k][j];
			 }
		  }

        ++n;
      }
    }

    if (n == p) {
      return n;
	 }

    std::swap(s, t);
  }
}
#endif  // #ifndef DP_MATRIX_MINIMIZE_H
