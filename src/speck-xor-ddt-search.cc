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
 * \file  speck-xor-ddt-search.cc 
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Automatic search for XOR differentials in block cipher Speck using full DDT.
 */ 
#ifndef COMMON_H
#include "common.hh"
#endif
#ifndef ADP_XOR_H
#include "xdp-add.hh"
#endif
#ifndef XDP_ADD_PDDT_H
#include "xdp-add-pddt.hh"
#endif
#ifndef MAX_XDP_ADD_H
#include "max-xdp-add.hh"
#endif
#ifndef SPECK_H
#include "speck.hh"
#endif
#ifndef SPECK_XOR_THRESHOLD_SEARCH_H
#include "speck-xor-threshold-search.hh"
#endif
//#ifndef SPECK_XOR_DDT_SEARCH_H
//#include "speck-xor-ddt-search.hh"
//#endif

// TODO:
