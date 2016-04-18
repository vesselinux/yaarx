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
 * \file  simon-xor-threshold-search.hh
 * \author A.Roy, V.Velichkov, arnab.roy@uni.lu, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header file for xdp-rot-and.cc: \copybrief simon-xor-threshold-search.cc.
 */ 
#ifndef SIMON_XOR_THRESHOLD_SEARCH_H
#define SIMON_XOR_THRESHOLD_SEARCH_H 

// http://www.boost.org/doc/libs/1_47_0/doc/html/unordered/hash_equality.html

// Best found bounds and trails for Simon64
#if(WORD_SIZE == 16)
#define SIMON_TRAIL_LEN 15
#elif(WORD_SIZE == 24)
#define SIMON_TRAIL_LEN 15
#elif(WORD_SIZE == 32)
#define SIMON_TRAIL_LEN 21
#endif

#define SIMON32_TRAIL_LEN 15
#define SIMON48_TRAIL_LEN 20
#define SIMON64_TRAIL_LEN 21

#if(WORD_SIZE == 16)
extern double g_B[SIMON_TRAIL_LEN];
extern differential_t g_trail[SIMON32_TRAIL_LEN];
#elif(WORD_SIZE == 24)
extern double g_B[SIMON_TRAIL_LEN];
extern differential_t g_trail[SIMON_TRAIL_LEN];
#elif(WORD_SIZE == 32)
extern double g_B[SIMON_TRAIL_LEN];
extern differential_t g_trail[SIMON64_TRAIL_LEN];
#endif

struct simon_diff_equal_to
  : std::binary_function<std::array<differential_t, SIMON_NDIFFS>, std::array<differential_t, SIMON_NDIFFS>, bool>
{
  bool operator()(std::array<differential_t, SIMON_NDIFFS> const& a,
						std::array<differential_t, SIMON_NDIFFS> const& b) const
  {
	 assert(a.size() == SIMON_NDIFFS);
	 assert(b.size() == SIMON_NDIFFS);

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

struct simon_diff_hash
  : std::unary_function<std::array<differential_t, SIMON_NDIFFS>, std::size_t>
{
  std::size_t operator()(std::array<differential_t, SIMON_NDIFFS> const& a) const
  {
	 assert(a.size() == SIMON_NDIFFS);
	 std::size_t seed = 0;

	 for(uint32_t i = 0; i < a.size(); i++) {
		boost::hash_combine(seed, a[i].dx);
		boost::hash_combine(seed, a[i].dy);
	 }
	 return seed;
  }
};

struct simon_trail_equal_to
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

struct simon_trail_hash
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

struct simon_diff_graph_node_comp
  : std::binary_function<simon_diff_graph_node_t, simon_diff_graph_node_t, bool>
{
  bool operator()(simon_diff_graph_node_t const& a,
						simon_diff_graph_node_t const& b) const
  {
	 bool b_less = false;
	 if(a.level != b.level) {
		b_less = (a.level < b.level);
	 } else {
		if(a.node[1] != b.node[1]) {
		  b_less = (a.node[1] < b.node[1]);
		} else {
		  if(a.node[0] != b.node[0]) {
			 b_less = (a.node[0] < b.node[0]);
		  }
		}
	 }
#if 0									  // DEBUG
	 printf("(%d %d) (%X %X) (%X %X) | %d\n", a.level, b.level, a.node[1], b.node[1], a.node[0], b.node[0], b_less);
#endif
	 return b_less;
  }
};

struct simon_diff_graph_node_alloc
  : std::unary_function<simon_diff_graph_node_t, simon_diff_graph_node_t>
{
  simon_diff_graph_node_t operator()(simon_diff_graph_node_t const& a) const
  {

	 simon_diff_graph_node_t node_key = {0, {0, 0}, 0, 0, 0.0};

	 node_key.level = a.level;
	 node_key.node[0] = a.node[0];
	 node_key.node[1] = a.node[1];

	 return node_key;
  }
};

void simon_diff_graph_check_edge(std::vector<simon_diff_graph_edge_t>* E, 
											const simon_diff_graph_edge_t new_edge);
void simon_print_diff_array(std::array<differential_t, SIMON_NDIFFS> diff_array);
void simon_print_diff_hash_map(boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to> diffs_hash_map);
void simon_print_trail_array(std::array<differential_t, NROUNDS> trail_array);
void simon_print_trail_hash_map(boost::unordered_map<std::array< differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map);
uint32_t simon_xor_threshold_count_lp(differential_t trail[NROUNDS], uint32_t trail_len, double p_thres);
uint32_t simon_verify_xor_trail(uint32_t nrounds, uint32_t npairs, 
										  uint32_t key_in[SIMON_MAX_NROUNDS],
										  differential_t trail[NROUNDS], uint32_t dy_init,
										  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u);
double simon_verify_differential(const uint32_t key_in[SIMON_MAX_NROUNDS],
											const differential_t input_diff, 
											const differential_t output_diff, 
											const uint32_t nrounds,
											const uint64_t npairs,
											std::vector<simon_diff_graph_edge_t>* E);
double simon_verify_differential_approx(const uint32_t key_in[SIMON_MAX_NROUNDS],
													 const differential_t input_diff, 
													 const differential_t output_diff, 
													 const uint32_t nrounds,
													 const uint64_t npairs,
													 std::vector<simon_diff_graph_edge_t>* E);
void simon_graphviz_write_file(char* datfile, char* datfile_con, 
										 std::vector< simon_diff_graph_edge_t> E);
void simon_trail_to_round_diffs(differential_t trail_in[NROUNDS], differential_t round_diffs[NROUNDS + 1],
										  uint32_t nrounds, uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u);
uint32_t simon_verify_xor_differential(uint32_t nrounds, uint32_t npairs, 
													uint32_t key_in[SIMON_MAX_NROUNDS],
													differential_t trail_in[NROUNDS], uint32_t dy_init,
													uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u);
void simon_encrypt_pairs(uint32_t key[SIMON_MAX_NROUNDS], uint32_t nrounds,
								 uint32_t* x_in, uint32_t* y_in,
								 uint32_t* xx_in, uint32_t* yy_in);
void simon_xor_threshold_search(const int n, const int nrounds, 
										  double B[NROUNDS], double* Bn,
										  const differential_t diff_in[NROUNDS], differential_t trail[NROUNDS], 
										  const uint32_t dyy_init,
										  uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
										  std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // initial highways
										  //										  std::multiset<differential_t, struct_comp_diff_hw>* diff_mset_hw, // initial highways
										  std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										  std::multiset<differential_t, struct_comp_diff_p>* hways_diff_mset_p, // all highways
										  std::set<differential_t, struct_comp_diff_dx_dy>* hways_diff_set_dx_dy,
										  std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
										  std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy,
										  boost::unordered_map<std::array<differential_t, SIMON_NDIFFS>, uint32_t, simon_diff_hash, simon_diff_equal_to>* diffs_hash_map,
										  boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
										  differential_t** diff_max,
										  bool b_hash_map,
										  double p_eps,
										  double p_thres);
void simon_print_round_diffs_latex(FILE* fp, uint32_t nrounds, uint32_t keys[4], differential_t trail[NROUNDS + 1]);
uint32_t simon_xor_trail_search(uint32_t key[SIMON_MAX_NROUNDS], double B[NROUNDS], 
										  differential_t best_trail[NROUNDS], uint32_t* best_trail_len);
std::string trail_to_string(differential_t* trail, uint32_t trail_len);
std::string differential_to_string(const differential_t diff);
uint32_t differential_to_num(const differential_t diff);
void simon_xor_cluster_trails(const int n, const int nrounds, 
										const double B[NROUNDS], 
										const differential_t diff_in[NROUNDS], const differential_t best_trail[NROUNDS], 
										std::unordered_map<std::string, differential_t**>* trails_hash_map,
										//										const uint32_t dyy_init,
										const differential_t input_diff, const differential_t output_diff, 
										uint32_t lrot_const_s, uint32_t lrot_const_t, uint32_t lrot_const_u,
										std::multiset<differential_t, struct_comp_diff_p>* diff_mset_p, // highways
										std::set<differential_t, struct_comp_diff_dx_dy>* diff_set_dx_dy,
										std::multiset<differential_t, struct_comp_diff_p>* croads_diff_mset_p, // country roads
										std::set<differential_t, struct_comp_diff_dx_dy>* croads_diff_set_dx_dy,
										double eps);
void simon_trail_cluster_search(std::unordered_map<std::string, differential_t**>* trails_hash_map,
										 double B[NROUNDS], const differential_t trail_in[NROUNDS], uint32_t trail_len, uint32_t* dyy_init);
void simon_trail_cluster_search_boost(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to>* trails_hash_map,
													  double B[NROUNDS], const differential_t trail_in[NROUNDS], uint32_t trail_len, uint32_t* dyy_init);
void simon_print_hash_table(std::unordered_map<std::string, differential_t**> trails_hash_map, uint32_t trail_len);
void simon_boost_print_hash_table(boost::unordered_map<std::array<differential_t, NROUNDS>, uint32_t, simon_trail_hash, simon_trail_equal_to> trails_hash_map, uint32_t trail_len);
void simon_cluster_trails_datfile_read(std::vector<simon_diff_graph_edge_t>* E);
void simon_diff_graph_extract_nodes(std::vector<simon_diff_graph_edge_t> E,
												std::map<simon_diff_graph_node_t, // key
															simon_diff_graph_node_t, // value
															simon_diff_graph_node_comp>* V); // comparison function
void simon_diff_graph_print_nodes(std::map<simon_diff_graph_node_t, simon_diff_graph_node_t, simon_diff_graph_node_comp> V);
bool simon_diff_vec_comp(std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> a, 
								 std::pair<simon_diff_graph_node_t, simon_diff_graph_node_t> b);
#endif  // #ifndef SIMON_XOR_THRESHOLD_SEARCH_H
