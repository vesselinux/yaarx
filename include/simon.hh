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
 * \file  simon.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for simon.cc: \copybrief simon.cc.
 */ 
#ifndef SIMON_H
#define SIMON_H

#define SIMON_LROT_CONST_S 1
#define SIMON_LROT_CONST_T 8
#define SIMON_LROT_CONST_U 2
#define SIMON_NPAIRS (1ULL << 20)
#define SIMON_NROUNDS 20
#define SIMON_NDIFFS 2
#define SIMON_MAX_NKEY_WORDS 4
#define SIMON_KEY_LEN_BITS 128
#define SIMON_ZSEQ_LEN 62
#define SIMON_MAX_NROUNDS 72
#define SIMON_EPS (double)(1.0 / (double)(1ULL << 15))//(double)(1.0 / (double)(1ULL << 15))
#define SIMON_DRAW_GRAPH 0		  // draw gviz graph
#define SIMON_BACK_TO_HWAY true
#define SIMON_TRAIL_LEN_MAX 21

#define SIMON_GVIZ_DATFILE "simon-gviz.dat" // full graph
#define SIMON_GVIZ_DATFILE_CON  "simon-gviz-con.dat" // concentrated graph
#define SIMON_BEST_TRAILS_LATEX_FILE "simon-trails.tex"

#define SIMON_GVIZ_CLUSTER_TRAILS_DATFILE "gviz-cluster-full.dat" // full graph
#define SIMON_GVIZ_CLUSTER_TRAILS_DATFILE_CON "gviz-cluster.dat" // condensed graph
//#define SIMON_CLUSTER_TRAILS_DATFILE "simon-cluster-trails.dat" // full graph
//#define SIMON_CLUSTER_TRAILS_DATFILE "simon-cluster-trails-21r.optimized.dat" // full graph
#define SIMON_CLUSTER_TRAILS_DATFILE "temp.dat"

extern uint32_t g_simon_zseq[5][62];

// Example:  " 2(1,0)" -> " 3(104,1)"
typedef struct {
  uint32_t level;					  // eg. 2
  uint32_t node_from[2];		  // eg. [1,0]
  uint32_t node_to[2];			  // eg. [104,1]
  uint32_t cnt;					  // how many such edges
  double p;							  // the probability to go to node_to i.e. P(node_from -> node_to)
} simon_diff_graph_edge_t;

typedef struct {
  uint32_t level;
  uint32_t node[2];
  uint32_t deg_in;				  // in-degree
  uint32_t deg_out;				  // out-degree
  double p_sum;					  // sum of the probs of all edges that enter this node
} simon_diff_graph_node_t;

void simon_diff_graph_check_edge(std::vector<simon_diff_graph_edge_t>* E, 
											const simon_diff_graph_edge_t new_edge);
uint32_t simon_compute_nkeywords(uint32_t word_size, uint32_t key_size);
uint32_t simon_get_keysize(uint32_t word_size);
uint32_t simon_compute_nrounds(uint32_t word_size, uint32_t nkey_words, uint32_t* zseq_j);
void simon_key_expansion(uint32_t key[SIMON_MAX_NROUNDS], uint32_t Z[5][62], uint32_t zseq_j,
								 uint32_t nrounds, uint32_t nkey_words);
void simon_encrypt(uint32_t key[SIMON_MAX_NROUNDS], uint32_t nrounds,
						 uint32_t* x_in, uint32_t* y_in);

void simon_encrypt_pairs(uint32_t key[SIMON_MAX_NROUNDS], uint32_t nrounds,
								 uint32_t* x_in, uint32_t* y_in,
								 uint32_t* xx_in, uint32_t* yy_in,
								 std::vector<simon_diff_graph_edge_t>* E);


#endif  // #ifndef SIMON_H
