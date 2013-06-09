YAARX: Yet Another ARX Toolkit for Analysis of ARX Cryptographic Algorithms

What is YAARX?

YAARX is a set of programs for the differential analysis of ARX cryptographic algorithms. The latter represent a broad class of symmetric-key algorithms designed by combining a small set of simple operations such as modular addition, bit rotation, bit shift and XOR. The more notable representatives of the ARX class of algorithms are the block ciphers FEAL, RC5, TEA and XTEA, the stream cipher Salsal20, the hash functions MD4, MD5, Skein and BLAKE as well as the recently proposed hash function for short messages SipHash.

What About Other ARX Tools?

YAARX complements existing toolkits such as "ARXtools" and extends others, such as "The S-functions Toolkit". More specifically, YAARX is the first tool that provides means to search for differential trails in ARX algorithms in a fully automatic way. The latter has been a notoriously difficult task to perform on ciphers that do not have S-boxes. Additionally, YAARX provides methods for the computation of the differential probabilities of various ARX operations (XOR, modular addition, bit shift, bit rotation) as well as of several larger components built from them.

How Can YAARX Help Me?

YAARX can help the cryptanalyst in the process of analyzing ARX-based constructions in at least two ways. The first one is to use the tools to directly compute differential probabilities for a target cipher. To this end YAARX provides a set of programs for the computation of the differential probabilities (DP) of several operations with user provided inputs. Such are for example the programs for computing the DP of modular addition, XOR, bit shift, bit rotation, etc. 

A conceivable scenario would be the case in which the cryptanalyst constructs a differential characteristic by hand and wants to estimate its probability by computing the probabilities of its composing differentials through the ARX operations. In this case YAARX can help answer questions such as: "Given input differences da and db to an operation F, and an output difference dc, what is the probability of the differential (da, db -> dc)?" or "Given input differences da and db to F, what is the output difference dc that has maximum probability?" or "Given an input difference da and an input value b to F and an output difference (da, b -> dc)?" or "Given input difference da and a set of input differences {db_0, db_2, db_3} to F, and an output difference dc, what is the probability of the differential (da, {db_0, db_2, db_3} -> dc)?" etc. The differences da, db and dc can be XOR or additive (ADD) differences and the operation F can either be one of the basic ARX operation, such as XOR, addition, etc. or a larger component e.g. a sequence of bit shit and XOR or of addition, rotation and XOR. 

The second way in which YAARX can be useful would require more effort and programming literacy on the part of the cryptanalyst. The idea is, instead of directly using one of the YAARX tools, to first modify it according to ones' specific needs. This scenario is realistic in a case in which for a given target cipher, none of the YAARX tools is capable of solving the problem at hand. 

Such a case is likely to occur when one wants to automatically search for differential trails in a given cipher. While YAARX supports a general strategy for automatic search of trails, that is potentially applicable to many ARX algorithms, it is implemented for two specific ciphers, namely TEA and XTEA. Since the algorithmic technique underlying this implementation is general, the latter can be applied to other ARX algorithms after respective modifications.

The YAARX Toolkit

A full list of the tools provided in YAARX is given below. DP stands for "Differential Probability".

\f$\mathrm{adp}^{\ll}\f$
The ADD differential probability of left shift (LSH).
\f$O(1)\f$

\f$\mathrm{adp}^{\gg}\f$
The ADD differential probability of right shift (RSH).
\f$O(1)\f$

\f$\mathrm{adp}^{\gg\oplus}\f$
The ADD differential probability of RSH followed by XOR.
\f$O(n)\f$

\f$ F(k_0, k_1, \delta |~ x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$
\f$\mathrm{adp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$
The ADD differential probability of the F-function of TEA for a fixed key and round constants 
\f$ O(n) \ll c \le O(2^n)\f$

\f$y = F'(k_0, k_1, \delta |~ x) = (x + k_0) \oplus (x + \delta) \oplus (x + k_1)\f$.
\f$\mathrm{adp}^{F'}(k_0, k_1, \delta |~ da \rightarrow db)\f$
The additive differential probability (ADP) of a modified version of F':
the F-function of TEA with the shift operations removed 
Complexity \f$O(n)\f$.

\f$\mathrm{adp}^{3\oplus}(da,db,dc \rightarrow dd)\f$
The ADD differential probability of XOR with three inputs.
\f$O(n)\f$

\f$\mathrm{adp}^{\oplus}(da,db \rightarrow dc)\f$
The ADD differential probability of XOR.
\f$O(n)\f$

\f$\mathrm{adp}^{\oplus}_{\mathrm{FI}}(a,db \rightarrow db)\f$
The ADD differential probability of XOR with one fixed input.
\f$O(n)\f$

Compute a partial difference distribution table (pDDT) for fixed probability threshold \f$p_\mathrm{thres}\f$
\f$\mathrm{adp}^{\oplus}\f$ pDDT.
\f$c = f(p_\mathrm{thres})\f$

Compute a partial difference distribution table (pDDT) for fixed probability threshold \f$p_\mathrm{thres}\f$
\f$\mathrm{xdp}^{+}\f$.
\f$c = f(p_\mathrm{thres})\f$

The ADD differential probability of the F-function of XTEA for a fixed key
\f$\mathrm{adp}^{F}(k, \delta |~ da \rightarrow dd)\f$.
Complexity: \f$ O(n) < c \le O(2^n) \f$.

\f$ F(x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$.
The expected additive differential probability (EADP) of the F-function of TEA, 
averaged over all round keys and constants: 
\f$\mathrm{eadp}^{F}(da \rightarrow dd)\f$.
Complexity: \f$O(n)\f$.

The maximum ADD differential probability of XOR with three inputs:
\f$\max_{dd}~\mathrm{adp}^{3\oplus}(da, db, dc \rightarrow dd)\f$.

The maximum ADD differential probability of XOR with three inputs, where 
one of the inputs satisfies a \em set of ADD differences: 
\f$\max_{dd} \mathrm{adp}^{\oplus}_{\mathrm{SET}}(da, db, \{{dc}_0, {dc}_1, \ldots\} \rightarrow dd)\f$.

The maximum ADD differential probability of XOR with one fixed input:
\f$\max_{dc} \mathrm{adp}^{\oplus}_{\mathrm{FI}}(a, db \rightarrow dc)\f$.

\f$\max_{dc}~\mathrm{adp}^{\oplus}(da, db \rightarrow dc)\f$
The maximum ADD differential probability of XOR.
\f$O(n) \le c \le O(2^n)\f$

\f$ F(x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$.
The maximum expected additive differential probability (EADP) of the F-function of TEA, 
averaged over all round keys and constants: 
\f$\max_{dd} \mathrm{eadp}^{F}(da \rightarrow dd)\f$
Complexity: \f$O(n)\f$.

\f$\mathrm{xdp}^{+}(da,db \rightarrow dc)\f$
The XOR differential probability of ADD.
\f$O(n)\f$

\f$\max_{dc}~\mathrm{xdp}^{+}(da, db \rightarrow dc)\f$
The maximum XOR differential probability of ADD.
\f$O(n) \le c \le O(2^n)\f$

\f$ F(x) = ((x \ll 4) + k_0) \oplus (x + \delta) \oplus ((x \gg 5) + k_1)\f$.
The XOR differential probability (XDP) of the F-function of TEA for a fixed key and round constants: 
\f$\mathrm{xdp}^{F}(k_0, k_1, \delta |~ da \rightarrow dd)\f$.

\f$ F(x)  = ((((x \ll 4) \oplus (x \gg 5)) + x) \oplus (k + \delta)\f$.
The XOR differential probability (XDP) of the F-function of XTEA for a fixed key and round constants: 
\f$\mathrm{xdp}^{F}(k, \delta |~ da \rightarrow dd)\f$.

Automatic search for ADD differential trails in block cipher TEA.

Automatic search for ADD differential trails in block cipher XTEA.

Automatic search for XOR differential trails in block cipher XTEA.

Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher XTEA.

Computing an XOR partial difference distribution table (pDDT) for the F-function of block cipher XTEA.

Computing an ADD partial difference distribution table (pDDT) for the F-function of block cipher TEA.


