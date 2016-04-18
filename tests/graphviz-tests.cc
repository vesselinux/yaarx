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
 * \file  graphviz-tests.cc
 * \author V.Velichkov, vesselin.velichkov@uni.lu
 * \date 2012-2013
 * \brief Tests for the graph drawing program GraphViz \url http://www.graphviz.org/
 */ 
/* 
 * Compile as: 
 * Debian:  ./bin$ g++ -O3 -std=c++0x -Wall -I/usr/include/graphviz/ -lgvc ../tests/graphviz-tests.cc -o gviz-program
 * Xubuntu: ./bin$ g++ -O3 -std=c++0x -Wall -I/usr/include/graphviz/ ../tests/graphviz-tests.cc -o gviz-program -lgvc -lgraph
 */
#ifndef GVC_H
#include <gvc.h> /**< GraphViz library */
#endif

int main(int argc, char **argv)
{
  char datfile[0xFFFF] = {0};
  sprintf(datfile, "digraph.gv");
  //  sprintf(datfile, "simon-gviz.dat");

  char picfile[0xFFFF] = {0};
  sprintf(picfile, "gvpic.png");
  //  sprintf(picfile, "gvpic.ps");

  GVC_t * gvc;
  Agraph_t *g;
  FILE *fp;

  gvc = gvContext();

  if(argc > 1) {
	 fp = fopen(argv[1], "r");
  } else {
	 fp = fopen(datfile, "r");
  }

  if(fp == NULL) {
	 printf("[%s:%d] Error opening file %s\n", __FILE__, __LINE__, datfile);
  }

  g = agread(fp);

  gvLayout(gvc, g, "dot");

  gvRenderFilename(gvc, g, "png", picfile);
  //  gvRenderFilename(gvc, g, "ps", picfile);

  gvFreeLayout(gvc, g);

  agclose(g);

  fclose(fp);

  return (gvFreeContext(gvc));
}
