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
 * \file  tea-add-threshold-search.hh
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Header for tea-add-threshold-search.cc. \copybrief tea-add-threshold-search.cc.
 */ 
#ifndef TEA_ADD_THRESHOLD_SEARCH_H
#define TEA_ADD_THRESHOLD_SEARCH_H

uint32_t tea_add_threshold_count_lp(differential_t trail[NROUNDS], uint32_t trail_len, double p_thres);

uint32_t tea_add_trail_search(uint32_t key[4], double B[NROUNDS], differential_t trail[NROUNDS]);

uint32_t tea_add_trail_search_full(uint32_t key[4], double BB[NROUNDS], differential_t trail[NROUNDS], uint32_t num_rounds);

#endif  // #ifndef TEA_ADD_THRESHOLD_SEARCH_H
