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
 * \file  simon.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Analysis of block cipher Simon [ePrint 2013/404].
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef XDP_ROT_AND_H
#include "xdp-rot-and.hh"
#endif
#ifndef SIMON_H
#include "simon.hh"
#endif

/**
 * Pre-computed z_j sequences (o <= j < 5) used in the key schedule of Simon.
 */
uint32_t g_simon_zseq[5][62] =  {
  // z_0
  {1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,  // 31
	1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0},
  // z_1
  {1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,
	1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0},
  // z_2
  {1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,
	0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1},
  // z_3
  {1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,
	0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1},
  // z_4
  {1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,
	0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1}
};

/**
 * Compute the number of key words depending on the word size
 *
 * \param word_size word size
 * \param key_size key size in bits
 */
uint32_t simon_compute_nkeywords(uint32_t word_size, uint32_t key_size)
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
uint32_t simon_get_keysize(uint32_t word_size)
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
	 m = 128;
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
 * Compute the number of rounds for Simon and the index of the z-sequence
 * \param word_size word size
 * \param nkey_words number of key words
 * \param zseq_j index of the z-sequence \ref g_simon_zseq
 * \return number of rounds
 */
uint32_t simon_compute_nrounds(uint32_t word_size, uint32_t nkey_words, uint32_t* zseq_j)
{
  uint32_t nrounds = 0;
  *zseq_j = 6;					  // invalid value (for error-check)

  switch(word_size) {
  case 16:
	 nrounds = 32;
	 *zseq_j = 0;
	 break;
  case 24:
	 nrounds = 36;
	 if(nkey_words == 3) {
		*zseq_j = 0;
	 }
	 if(nkey_words == 4) {
		*zseq_j = 1;
	 }
	 break;
  case 32:
	 if(nkey_words == 3) {
		nrounds = 42;
		*zseq_j = 2;
	 }
	 if(nkey_words == 4) {
		nrounds = 44;
		*zseq_j = 3;
	 }
	 break;
  case 48:
	 if(nkey_words == 2) {
		nrounds = 52;
		*zseq_j = 2;
	 }
	 if(nkey_words == 3) {
		nrounds = 54;
		*zseq_j = 3;
	 }
	 break;
  case 64:
	 if(nkey_words == 2) {
		nrounds = 68;
		*zseq_j = 2;
	 }
	 if(nkey_words == 3) {
		nrounds = 69;
		*zseq_j = 3;
	 }
	 if(nkey_words == 4) {
		nrounds = 72;
		*zseq_j = 4;
	 }
	 break;
  default:
	 break;
  }
  return nrounds;
}

/**
 * Simon key expansion procedure.
 * \param key original key (with enough space for the expanded key)
 * \param Z the z-sequence (\eref g_simon_zseq) 
 * \param zseq_j index of the z-seqence
 * \param nrounds number of rounds
 * \param nkey_words number of key words
 */
void simon_key_expansion(uint32_t key[SIMON_MAX_NROUNDS], uint32_t Z[5][62], uint32_t zseq_j,
								 uint32_t nrounds, uint32_t nkey_words)
{
  uint32_t T = nrounds;
  uint32_t m = nkey_words;
  uint32_t r1 = 3;				  // rot const
  uint32_t r2 = 1;				  // rot const
  uint32_t xconst = 3;
  uint32_t j = zseq_j;

  assert(m <= T);
  assert(key[m] == 0);
  assert(j < 5);
 
 for(uint32_t i = m; i < T; i++) {
	 uint32_t tmp = RROT(key[i - 1], r1);
	 if(m == 4) {
		tmp ^= key[i - 3];		  // !
	 }
	 tmp ^= RROT(tmp, r2);
	 uint32_t k = (i - m) % SIMON_ZSEQ_LEN;
	 uint32_t inv_key = (~(key[i - m])) & MASK;
#if 0									  // DEBUG
	 printf("[%s:%d] %8X %8X\n", __FILE__, __LINE__, key[i-m], (~key[i-m]) & MASK);
	 print_binary(key[i-m]);
	 printf("\n");
	 print_binary(inv_key);
	 printf("\n");
#endif
	 key[i] = inv_key ^ tmp ^ Z[j][k] ^ xconst;
  }
}

/**
 * Simon encryption procedure.
 * \param key expanded key
 * \param nrounds number of rounds
 * \param x_in first plaintext word
 * \param y_in second plaintext word
 */
void simon_encrypt(uint32_t key[SIMON_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t* x_in, uint32_t* y_in)
{
  uint32_t T = nrounds;
  uint32_t x = *x_in;
  uint32_t y = *y_in;

  // left rotation constants
  uint32_t r1 = 1;
  uint32_t r2 = 8;
  uint32_t r3 = 2;

  for(uint32_t i = 0; i < T; i++) {
#if 0									  // DEBUG
	 printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, i, x, y);
#endif
	 uint32_t tmp = x;
	 //	 uint32_t f = (LROT(x, r1) & LROT(x, r2))) ^ LROT(x, r3);
	 x = (y ^ (LROT(x, r1) & LROT(x, r2))) ^ LROT(x, r3) ^ key[i];
	 y = tmp;
  }
#if 0									  // DEBUG
  printf("[%s:%d] %2d: %8X %8X\n", __FILE__, __LINE__, T, x, y);
#endif
  *x_in = x;
  *y_in = y;
}

// for the GraphViz graph
void simon_diff_graph_check_edge(std::vector<simon_diff_graph_edge_t>* E, 
											const simon_diff_graph_edge_t new_edge)
{
  bool b_found = false;
  uint32_t edge_iter = 0; 
  while((!b_found) && (edge_iter != E->size())) {
	 simon_diff_graph_edge_t edge = E->at(edge_iter);
	 if( (edge.level == new_edge.level) &&
		  (edge.node_from[0] == new_edge.node_from[0]) && 
		  (edge.node_from[1] == new_edge.node_from[1]) &&
		  (edge.node_to[0] == new_edge.node_to[0]) && 
		  (edge.node_to[1] == new_edge.node_to[1]) ) {
		b_found = true;
		assert(edge.p == new_edge.p); // !!!
	 } else {
		edge_iter++;
	 }
  }
  if(b_found) {
	 E->at(edge_iter).cnt++;
#if 0									  // DEBUG
	 //	 printf("[%s:%d] Edge found : %d(%4X %4X) -> (%4X %4X) | %f , old %f : update \n", __FILE__, __LINE__, 
	 //			  new_edge.level, 
	 //			  new_edge.node_from[0], new_edge.node_from[1],
	 //			  new_edge.node_to[0], new_edge.node_to[1], 
	 //			  E->at(edge_iter).p, E->at(edge_iter).p);
	 //	 E->at(edge_iter).p += new_edge.p;
	 //	 assert(E->at(edge_iter).p <= 1.0);

	 printf("[%s:%d] Update count: %d(%4X %4X) -> (%4X %4X) %d | E.size %d\n", __FILE__, __LINE__, 
			  E->at(edge_iter).level, 
			  E->at(edge_iter).node_from[0], E->at(edge_iter).node_from[1],
			  E->at(edge_iter).node_to[0], E->at(edge_iter).node_to[1],
			  E->at(edge_iter).cnt, E->size());
#endif
  } else {
	 assert(edge_iter == E->size());
	 E->push_back(new_edge);
  }
}

void simon_encrypt_pairs(uint32_t key[SIMON_MAX_NROUNDS], uint32_t nrounds,
								 uint32_t* x_in, uint32_t* y_in,
								 uint32_t* xx_in, uint32_t* yy_in,
								 std::vector<simon_diff_graph_edge_t>* E)
{
#if SIMON_DRAW_GRAPH
  //  FILE* fp = fopen(SIMON_GVIZ_DATFILE, "a");
  uint32_t dx_prev = (*x_in) ^ (*xx_in);
  uint32_t dy_prev = (*y_in) ^ (*yy_in);
  uint32_t i_prev = 0;
#endif

  uint32_t T = nrounds;
  uint32_t x = *x_in;
  uint32_t y = *y_in;
  uint32_t xx = *xx_in;
  uint32_t yy = *yy_in;

  // left rotation constants
  uint32_t r1 = 1;
  uint32_t r2 = 8;
  uint32_t r3 = 2;

  double p_trail = 1.0;
  for(uint32_t i = 0; i < T; i++) {
	 uint32_t dx = x ^ xx;
	 uint32_t dy = y ^ yy;
#if 0									  // DEBUG
	 printf("[%s:%d] %2d: %8X %8X | ", __FILE__, __LINE__, i, dx, dy);
#endif
#if SIMON_DRAW_GRAPH
	 if(i > 0) {
		//		fprintf(fp, "    \"%2d(%X,%X)\" -> \"%2d(%X,%X)\"\n", i_prev, dx_prev, dy_prev, (i+1), dx, dy);
 		//		std::vector<simon_diff_graph_edge_t>::const_iterator edge_iter = E.begin();
		//		printf("    \"%2d(%X,%X)\" -> \"%2d(%X,%X)\"\n", i_prev, dx_prev, dy_prev, (i+1), dx, dy);
 		simon_diff_graph_edge_t new_edge;
		new_edge.level = i_prev;
		new_edge.node_from[0] = dx_prev;
		new_edge.node_from[1] = dy_prev;
		new_edge.node_to[0] = dx;
		new_edge.node_to[1] = dy;
		new_edge.cnt = 1;
		simon_diff_graph_check_edge(E, new_edge);
	 }
#endif
	 uint32_t tmp_x = x;
	 x = (y ^ (LROT(x, r1) & LROT(x, r2))) ^ LROT(x, r3) ^ key[i];
	 y = tmp_x;

	 uint32_t tmp_xx = xx;
	 xx = (yy ^ (LROT(xx, r1) & LROT(xx, r2))) ^ LROT(xx, r3) ^ key[i];
	 yy = tmp_xx;
#if 1									  // compute probabilities
	 uint32_t dxx = x ^ xx;
	 uint32_t f_dx = dx;
	 uint32_t f_dy = dy ^ dxx ^ LROT(dx, SIMON_LROT_CONST_U);
	 double p = xdp_rot_and(f_dx, f_dy, SIMON_LROT_CONST_S, SIMON_LROT_CONST_T);
	 p_trail *= p;
#endif
#if 0									  // DEBUG
	 printf("%f (2^%f)", p, log2(p));
	 printf("\n");
#endif
#if SIMON_DRAW_GRAPH
	 dx_prev = dx;
	 dy_prev = dy;
	 i_prev = (i+1);
#endif
  }
#if SIMON_DRAW_GRAPH
  uint32_t dx = x ^ xx;
  uint32_t dy = y ^ yy;
  //  fprintf(fp, "    \"%2d(%X,%X)\" -> \"%2d(%X,%X)\"\n", i_prev, dx_prev, dy_prev, (T+1), dx, dy);
  simon_diff_graph_edge_t new_edge;
  new_edge.level = i_prev;
  new_edge.node_from[0] = dx_prev;
  new_edge.node_from[1] = dy_prev;
  new_edge.node_to[0] = dx;
  new_edge.node_to[1] = dy;
  new_edge.cnt = 1;
  simon_diff_graph_check_edge(E, new_edge);
#endif
#if 0									  // DEBUG
  printf("[%s:%d] %2d: %8X %8X | \n", __FILE__, __LINE__, T, dx, dy);
  printf("p_trail = %f (2^%f)\n", p_trail, log2(p_trail));
#endif
  *x_in = x;
  *y_in = y;
  *xx_in = xx;
  *yy_in = yy;

  //#if SIMON_DRAW_GRAPH
  //  fclose(fp);
  //#endif
}

// --- TESTS ---

#if(WORD_SIZE == 16)
/*
Simon test vector
Simon32/64
Key: 1918 1110 0908 0100
Plaintext: 6565 6877
Ciphertext: c69b e9bb
*/
uint32_t tv_key[4] = {0x0100, 0x0908, 0x1110, 0x1918};
uint32_t tv_pt[2] = {0x6565, 0x6877}; // {x, y}
uint32_t tv_ct[2] = {0xc69b, 0xe9bb};
#endif

#if(WORD_SIZE == 32)
/*
Simon test vector
Simon64/128
Key: 1b1a1918 13121110 0b0a0908 03020100
Plaintext: 656b696c 20646e75
Ciphertext: 44c8fc20 b9dfa07a
*/
uint32_t tv_key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
uint32_t tv_pt[2] = {0x656b696c, 0x20646e75}; // {x, y}
uint32_t tv_ct[2] = {0x44c8fc20, 0xb9dfa07a};
#endif

// check test vectors
#if ((WORD_SIZE == 16) || (WORD_SIZE == 32))
void test_simon_encrypt_tv()
{
  uint32_t word_size = WORD_SIZE;
  uint32_t key_size = simon_get_keysize(word_size);
#if 1									  // DEBUG
  printf("[%s:%d] word_size %d\n", __FILE__, __LINE__, word_size);
  printf("[%s:%d] key_size %d\n", __FILE__, __LINE__, key_size);
#endif
  uint32_t nkey_words = simon_compute_nkeywords(word_size, key_size);
#if 1									  // DEBUG
  printf("[%s:%d] nkey_words %d\n", __FILE__, __LINE__, nkey_words);
#endif
  uint32_t zseq_j = 0;
  uint32_t nrounds = simon_compute_nrounds(word_size, nkey_words, &zseq_j);
#if 1									  // DEBUG
  printf("[%s:%d] nrounds %d\n", __FILE__, __LINE__, nrounds);
  printf("[%s:%d] zseq_index %d\n", __FILE__, __LINE__, zseq_j);
#endif
  uint32_t key[SIMON_MAX_NROUNDS] = {0};
  for(uint32_t i = 0; i < nkey_words; i++) { // init key
	 key[i] = tv_key[i];//random32() & MASK;
  }
#if 1									  // DEBUG
  printf("[%s:%d] Before key expansion:\n", __FILE__, __LINE__);
  for(uint32_t i = 0; i < nrounds; i++) {
	 printf("%8X ", key[i]);
  }
  printf("\n");
#endif
  simon_key_expansion(key, g_simon_zseq, zseq_j, nrounds, nkey_words);
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
  simon_encrypt(key, nrounds, &x, &y);
#if 1									  // DEBUG
  printf("[%s:%d]  After encryption: %8X %8X (%8X %8X)\n", __FILE__, __LINE__, x, y, tv_ct[0], tv_ct[1]);
#endif
  assert(x == tv_ct[0]);
  assert(y == tv_ct[1]);
  printf("[%s:%d] OK\n", __FILE__, __LINE__);
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

#if ((WORD_SIZE == 16) || (WORD_SIZE == 32))
  test_simon_encrypt_tv();
#endif  // #if ((WORD_SIZE == 16) || (WORD_SIZE == 32))

  return 0;
}
#endif
