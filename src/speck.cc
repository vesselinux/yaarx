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
 * \file  speck.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Analysis of block cipher Speck [ePrint 2013/404].
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif

/**
 * Compute the number of key words depending on the word size
 *
 * \param word_size word size
 * \param key_size key size in bits
 */
uint32_t speck_compute_nkeywords(uint32_t word_size, uint32_t key_size)
{
  if(word_size == 16) {
	 assert((key_size == 64));
  }
  if(word_size == 24) {
	 assert((key_size == 72) || (key_size == 96));
  }
  if(word_size == 32) {
	 assert((key_size == 96) || (key_size == 128));
  }
  if(word_size == 48) {
	 assert((key_size == 96) || (key_size == 144));
  }
  if(word_size == 64) {
	 assert((key_size == 128) || (key_size == 192) || (key_size == 256));
  }
  uint32_t m = key_size / word_size;
  return m;
}

/**
 * Get the size of the key in bits depending on the word size
 *
 * \param word_size word size in bits
 */
uint32_t speck_get_keysize(uint32_t word_size)
{
  uint32_t m = 0;
  switch(word_size) {
  case 16:
	 m = 64;
	 break;
  case 24:
	 m = 96;
	 break;
  case 32:
	 m = 96;
	 //	 m = 128;
	 break;
  case 48:
	 m = 144;
	 break;
  case 64:
	 m = 256;
	 break;
  default:
	 break;
  }
  return m;
}

/**
 * Get the rotation constants.
 */
void speck_get_rot_const(uint32_t word_size, uint32_t* alpha, uint32_t* beta)
{
  if(word_size == 16) {
	 *alpha = SPECK_RIGHT_ROT_CONST_16BITS;
	 *beta = SPECK_LEFT_ROT_CONST_16BITS;
  } else {
	 *alpha = SPECK_RIGHT_ROT_CONST;
	 *beta = SPECK_LEFT_ROT_CONST;
  }
}

/**
 * Compute the number of rounds for Speck and the index of the z-sequence
 * \param word_size word size
 * \param nkey_words number of key words
 * \return number of rounds
 */
uint32_t speck_compute_nrounds(uint32_t word_size, uint32_t nkey_words)
{
  uint32_t nrounds = 0;

  switch(word_size) {
  case 16:
	 nrounds = 22;
	 break;
  case 24:
	 if(nkey_words == 3) {
		nrounds = 22;
	 }
	 if(nkey_words == 4) {
		nrounds = 23;
	 }
	 break;
  case 32:
	 if(nkey_words == 3) {
		nrounds = 26;
	 }
	 if(nkey_words == 4) {
		nrounds = 27;
	 }
	 break;
  case 48:
	 if(nkey_words == 2) {
		nrounds = 28;
	 }
	 if(nkey_words == 3) {
		nrounds = 29;
	 }
	 break;
  case 64:
	 if(nkey_words == 2) {
		nrounds = 32;
	 }
	 if(nkey_words == 3) {
		nrounds = 33;
	 }
	 if(nkey_words == 4) {
		nrounds = 34;
	 }
	 break;
  default:
	 break;
  }
  return nrounds;
}

/**
 * Speck key expansion procedure.
 * \param key original key (with enough space for the expanded key)
 * \param nrounds number of rounds
 * \param nkey_words number of key words
 * \param alpha right rotation constant
 * \param beta left rotation constant
 */
void speck_key_expansion(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds, uint32_t nkey_words,
								 uint32_t alpha, uint32_t beta)
{
  uint32_t T = nrounds;
  uint32_t m = nkey_words;
  WORD_T L[SPECK_MAX_NROUNDS] = {0};

  for(uint32_t i = 1; i < m; i++) { // l[m-2], ..., l[0]
	 L[i - 1] = key[i];
  }

  for(uint32_t i = 0; i < (T - 1); i++) {
	 L[i + m - 1] = ADD(key[i], RROT(L[i], alpha)) ^ i;
	 key[i + 1] = LROT(key[i], beta) ^ L[i + m - 1];
  }
}

/**
 * Speck encryption procedure.
 * \param key expanded key
 * \param nrounds number of rounds
 * \param alpha right rotation constant
 * \param beta left rotation constant
 * \param x_in first plaintext word
 * \param y_in second plaintext word
 */
void speck_encrypt(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t alpha, uint32_t beta,
						 WORD_T* x_in, WORD_T* y_in)
{
  WORD_T T = nrounds;
  WORD_T x = *x_in;
  WORD_T y = *y_in;

  for(WORD_T i = 0; i < T; i++) {
#if 0									  // DEBUG
	 printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, i, x, y);
#endif
	 x = ADD(RROT(x, alpha), y) ^ key[i];
	 y = LROT(y, beta) ^ x;
  }
#if 0									  // DEBUG
  printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, T, x, y);
#endif
  *x_in = x;
  *y_in = y;
}

void speck_decrypt(WORD_T key[SPECK_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t alpha, uint32_t beta,
						 WORD_T* x_in, WORD_T* y_in)
{
  WORD_T T = nrounds;
  WORD_T x = *x_in;
  WORD_T y = *y_in;

  for(WORD_T i = 0; i < T; i++) {
#if 0									  // DEBUG
	 printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, i, x, y);
#endif
	 y = RROT((y ^ x), beta);
	 x = LROT(SUB((x ^ key[T - i - 1]), y), alpha); // apply keys in reverse order
  }
#if 0									  // DEBUG
  printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, T, x, y);
#endif
  *x_in = x;
  *y_in = y;
}

// --- TESTS ---

#if(WORD_SIZE == 16)
/*
Speck32/64
Key: 1918 1110 0908 0100
Plaintext: 6574 694c
Ciphertext: a868 42f2
*/
uint32_t tv_key[4] = {0x0100, 0x0908, 0x1110, 0x1918};
uint32_t tv_pt[2] = {0x6574, 0x694c}; // {x, y}
uint32_t tv_ct[2] = {0xa868, 0x42f2};
#endif

#if 0//(WORD_SIZE == 32)
/*
Speck64/128
Key: 1b1a1918 13121110 0b0a0908 03020100
Plaintext: 3b726574 7475432d
Ciphertext: 8c6fa548 454e028b
*/
uint32_t tv_key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
uint32_t tv_pt[2] = {0x3b726574, 0x7475432d}; // {x, y}
uint32_t tv_ct[2] = {0x8c6fa548, 0x454e028b};
#endif

#if(WORD_SIZE == 32)
/*
Speck64/96
Key: 13121110 0b0a0908 03020100
Plaintext: 74614620 736e6165
Ciphertext: 9f7952ec 4175946c
*/
uint32_t tv_key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
uint32_t tv_pt[2] = {0x74614620, 0x736e6165}; // {x, y}
uint32_t tv_ct[2] = {0x9f7952ec, 0x4175946c};
#endif

// check test vectors
#if ((WORD_SIZE == 16) || (WORD_SIZE == 32))
void test_speck_encrypt_tv()
{

  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = speck_get_keysize(word_size);
#if 1									  // DEBUG
  printf("[%s:%d] word_size %d\n", __FILE__, __LINE__, word_size);
  printf("[%s:%d] key_size %d\n", __FILE__, __LINE__, key_size);
#endif
  uint32_t nkey_words = speck_compute_nkeywords(word_size, key_size);
#if 1									  // DEBUG
  printf("[%s:%d] nkey_words %d\n", __FILE__, __LINE__, nkey_words);
#endif
  uint32_t nrounds = speck_compute_nrounds(word_size, nkey_words);
#if 1									  // DEBUG
  printf("[%s:%d] nrounds %d\n", __FILE__, __LINE__, nrounds);
#endif
  uint32_t key[SPECK_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < nkey_words; i++) { // init key
	 key[i] = tv_key[i];//random32() & MASK;
  }
  uint32_t alpha = 0;
  uint32_t beta = 0;
  speck_get_rot_const(word_size, &alpha, &beta);
#if 1									  // DEBUG
  printf("[%s:%d] Rot const: %d %d\n", __FILE__, __LINE__, alpha, beta);
#endif
#if 1									  // DEBUG
  printf("[%s:%d] Before key expansion:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%8X ", key[i]);
  }
  printf("\n");
#endif
  speck_key_expansion(key, nrounds, nkey_words, alpha, beta);
#if 1									  // DEBUG
  printf("[%s:%d] After key expansion:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%8X ", key[i]);
  }
  printf("\n");
#endif
  uint32_t x = tv_pt[0];
  uint32_t y = tv_pt[1];
#if 1									  // DEBUG
  printf("[%s:%d] Before encryption: %8X %8X\n", __FILE__, __LINE__, x, y);
#endif
  speck_encrypt(key, nrounds, alpha, beta, &x, &y);
#if 1									  // DEBUG
  printf("[%s:%d]  After encryption: %8X %8X (%8X %8X)\n", __FILE__, __LINE__, x, y, tv_ct[0], tv_ct[1]);
#endif
  assert(x == tv_ct[0]);
  assert(y == tv_ct[1]);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);

#if 1									  // DEBUG
  printf("[%s:%d] Before decryption: %8X %8X\n", __FILE__, __LINE__, x, y);
#endif
  speck_decrypt(key, nrounds, alpha, beta, &x, &y);
#if 1									  // DEBUG
  printf("[%s:%d]  After decryption: %8X %8X (%8X %8X)\n", __FILE__, __LINE__, x, y, tv_pt[0], tv_pt[1]);
#endif
}
#endif  // #if ((WORD_SIZE == 16) || (WORD_SIZE == 32))


/**
 * Main function.
 */
#if 0
int main()
{
  printf("#--- [%s:%d] Tests, WORD_SIZE  = %d, MASK = %8X\n", __FILE__, __LINE__, WORD_SIZE, MASK);
  srandom(time(NULL));
  test_speck_encrypt_tv();
  return 0;
}
#endif
