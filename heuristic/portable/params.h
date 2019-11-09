/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: heuristic qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#if defined(_qTESLA_I_)

#define PARAM_N 512
#define PARAM_N_LOG 9
#define PARAM_SIGMA 9.7
#define PARAM_Q 4205569
#define PARAM_Q_LOG 23
#define PARAM_QINV 3098553343
#define PARAM_BARR_MULT 1021
#define PARAM_BARR_DIV 32
#define PARAM_B 2097151
#define PARAM_B_BITS 21
#define PARAM_S_BITS 8
#define PARAM_K 2
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 30
#define PARAM_D 21
#define PARAM_GEN_A 38	
#define PARAM_KEYGEN_BOUND_E 645
#define PARAM_E PARAM_KEYGEN_BOUND_E
#define PARAM_KEYGEN_BOUND_S 645
#define PARAM_S PARAM_KEYGEN_BOUND_S
#define PARAM_R2_INVN 113307
#define PARAM_R 1081347
#define SHAKE shake128
#define cSHAKE cshake128_simple
#define SHAKE_RATE SHAKE128_RATE

#elif defined(_qTESLA_II_)

#define PARAM_N 768
#define PARAM_N_LOG 10
#define PARAM_SIGMA 9.73
#define PARAM_Q 16777729
#define PARAM_Q_LOG 25
#define PARAM_QINV 150733311
#define PARAM_BARR_MULT 255
#define PARAM_BARR_DIV 32
#define PARAM_B_BITS 23
#define PARAM_B ((1 << PARAM_B_BITS) - 1)
#define PARAM_S_BITS 9
#define PARAM_K 2
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 39
#define PARAM_D 23
#define PARAM_GEN_A 78
#define PARAM_KEYGEN_BOUND_E 887
#define PARAM_E (2*PARAM_KEYGEN_BOUND_E)
#define PARAM_KEYGEN_BOUND_S 887
#define PARAM_S (2*PARAM_KEYGEN_BOUND_S)
#define PARAM_R2_INVN 16315901
#define PARAM_R 16646401
#define SHAKE shake128
#define cSHAKE cshake128_simple
#define SHAKE_RATE SHAKE128_RATE

#elif defined(_qTESLA_III_)

#define PARAM_N 1024
#define PARAM_N_LOG 10
#define PARAM_SIGMA 10.2
#define PARAM_Q 16801793
#define PARAM_Q_LOG 25
#define PARAM_QINV 3707789311
#define PARAM_BARR_MULT 255
#define PARAM_BARR_DIV 32
#define PARAM_B 8388607
#define PARAM_B_BITS 23
#define PARAM_S_BITS 9
#define PARAM_K 2
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 48
#define PARAM_D 23	
#define PARAM_GEN_A 98
#define PARAM_KEYGEN_BOUND_E 1148 
#define PARAM_E PARAM_KEYGEN_BOUND_E
#define PARAM_KEYGEN_BOUND_S 1234
#define PARAM_S PARAM_KEYGEN_BOUND_S
#define PARAM_R2_INVN 6863778
#define PARAM_R 10510081
#define SHAKE shake256
#define cSHAKE cshake256_simple
#define SHAKE_RATE SHAKE256_RATE

#endif

#endif
