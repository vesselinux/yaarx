YAARX: Yet Another ARX Toolkit for Analysis of ARX Cryptographic Algorithms

Note: Full documentation is available at: https://github.com/vesselinux/yaarx .

What is YAARX?

YAARX is a set of programs for the differential analysis of ARX cryptographic algorithms. The latter represent a broad class of symmetric-key algorithms designed by combining a small set of simple operations such as modular addition, bit rotation, bit shift and XOR. The more notable representatives of the ARX class of algorithms are the block ciphers FEAL, RC5, TEA and XTEA, the stream cipher Salsal20, the hash functions MD4, MD5, Skein and BLAKE as well as the recently proposed hash function for short messages SipHash.

What About Other ARX Tools?

YAARX complements existing toolkits such as ARXtools (http://www.di.ens.fr/~leurent/arxtools.html) and significantly extends others, such as The S-function Toolkit (http://www.ecrypt.eu.org/tools/s-function-toolkit) . More specifically, YAARX provides methods for the computation of the differential probabilities of various ARX operations (XOR, modular addition, multiplication, bit shift, bit rotation) as well as of several larger components built from them. YAARX also provides means to search for high-probability differential trails in ARX algorithms in a fully automatic way. The latter has been a notoriously difficult task for ciphers that do not have S-boxes, such as ARX. 

How Can YAARX Help You?

YAARX can help the cryptanalyst in the process of analyzing ARX-based constructions in at least two ways. The first one is to use the tools to directly compute differential probabilities for a target cipher. To this end YAARX provides a set of programs for the computation of the differential probabilities (DP) of several operations with user provided inputs. Such are for example the programs for computing the DP of modular addition, XOR, bit shift, bit rotation, etc. 

A conceivable scenario would be the case in which the cryptanalyst constructs a differential characteristic by hand and wants to estimate its probability by computing the probabilities of its composing differentials through the ARX operations. In this case YAARX can help answer questions such as: "Given input differences da and db to an operation F, and an output difference dc, what is the probability of the differential (da, db -> dc)?" or "Given input differences da and db to F, what is the output difference dc that has maximum probability?" or "Given an input difference da and an input value b to F and an output difference (da, b -> dc)?" or "Given input difference da and a set of input differences {db_0, db_2, db_3} to F, and an output difference dc, what is the probability of the differential (da, {db_0, db_2, db_3} -> dc)?" etc. The differences da, db and dc can be XOR or additive (ADD) differences and the operation F can either be one of the basic ARX operation, such as XOR, addition, etc. or a larger component e.g. a sequence of bit shit and XOR or of addition, rotation and XOR. 

The second way in which YAARX can be useful would require more effort and programming literacy on the part of the cryptanalyst. The idea is, instead of directly using one of the YAARX tools, to first modify it according to ones' specific needs. This scenario is realistic in a case in which for a given target cipher, none of the YAARX tools is capable of solving the problem at hand. 

Such a case is likely to occur when one wants to automatically search for differential trails in a given cipher. While YAARX supports a general strategy for automatic search of trails, that is potentially applicable to many ARX algorithms, it is implemented for two specific ciphers, namely TEA and XTEA. Since the algorithmic technique underlying this implementation is general, the latter can be applied to other ARX algorithms after respective modifications.

Compilation

For successful compilation it is required to install the development version of the GNU Scientific Library (GSL) and the Multiprecision arithmetic library (GMP) developers tools. Under Ubuntu/Debian Linux the name of the packages are resp. libgsl0-dev and libgmp-dev. After downloading the YAARX source code, it can be compiled by running the make command from within the top directory of the source tree. The pre-compiled programs are stored in the ./bin directoy . 
