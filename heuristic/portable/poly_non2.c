/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: NTT, modular reduction and polynomial functions
**************************************************************************************/

#include "poly.h"
#include "sha3/fips202.h"
#include "api.h"

extern poly zeta;
extern poly zetainv;


void poly_uniform(poly_k a, const unsigned char *seed)         
{ // Generation of polynomials "a_i"
  unsigned int pos=0, i=0, nbytes = (PARAM_Q_LOG+7)/8;
  unsigned int nblocks=PARAM_GEN_A;
  uint32_t val1, val2, val3, val4, mask = (uint32_t)(1<<PARAM_Q_LOG)-1;
  unsigned char buf[SHAKE128_RATE*PARAM_GEN_A + 1];
  uint16_t dmsp=0;

  cshake128_simple(buf, SHAKE128_RATE*PARAM_GEN_A, dmsp++, seed, CRYPTO_RANDOMBYTES);    
     
  while (i < PARAM_K*PARAM_N) {   
    if (pos > SHAKE128_RATE*nblocks - 4*nbytes) {
      nblocks = 1;
      cshake128_simple(buf, SHAKE128_RATE*nblocks, dmsp++, seed, CRYPTO_RANDOMBYTES);    
      pos = 0;
    } 
    val1  = (*(uint32_t*)(buf+pos)) & mask;
    pos += nbytes;
    val2  = (*(uint32_t*)(buf+pos)) & mask;
    pos += nbytes;
    val3  = (*(uint32_t*)(buf+pos)) & mask;
    pos += nbytes;
    val4  = (*(uint32_t*)(buf+pos)) & mask;
    pos += nbytes;
    if (val1 !=0 && val1 < PARAM_Q && i < PARAM_K*PARAM_N)
      a[i++] = reduce((int64_t)val1*PARAM_R2_INVN);
    if (val2 !=0 && val2 < PARAM_Q && i < PARAM_K*PARAM_N)
      a[i++] = reduce((int64_t)val2*PARAM_R2_INVN);
    if (val3 !=0 && val3 < PARAM_Q && i < PARAM_K*PARAM_N)
      a[i++] = reduce((int64_t)val3*PARAM_R2_INVN);
    if (val4 !=0 && val4 < PARAM_Q && i < PARAM_K*PARAM_N)
      a[i++] = reduce((int64_t)val4*PARAM_R2_INVN);
  }
}


int32_t reduce(int64_t a)
{ // Montgomery reduction
  int64_t u;

  u = (a*PARAM_QINV) & 0xFFFFFFFF;
  u *= PARAM_Q;
  a += u;
  return (int32_t)(a>>32);
}


void ntt(poly a, const poly w)
{ // Forward NTT transform
  int NumoProblems = PARAM_N>>1, jTwiddle=1, bound=3;
  sdigit_t W = (sdigit_t)w[jTwiddle++];

  for(int j=0; j<NumoProblems; j++){
    int32_t temp = reduce((int64_t)W * a[j+NumoProblems]);
    a[j + NumoProblems] = a[j] + a[j+NumoProblems] - temp;
    a[j] = temp + a[j];
  }
  NumoProblems >>= 1;

  for (; NumoProblems>=bound; NumoProblems>>=1) {
    int jFirst,j=0;
    for (jFirst=0; jFirst<PARAM_N; jFirst=j+NumoProblems) {
      sdigit_t W = (sdigit_t)w[jTwiddle++];
      for (j=jFirst; j<jFirst+NumoProblems; j++) {
        int32_t temp = reduce((int64_t)W * a[j+NumoProblems]);
        a[j + NumoProblems] = a[j] - temp;
        a[j] = temp + a[j];
      }
    }
  }
}


int32_t barr_reduce(int32_t a)
{ // Barrett reduction
  int32_t u = ((int64_t)a*PARAM_BARR_MULT)>>PARAM_BARR_DIV;
  return a - (int32_t)u*PARAM_Q;
}


void nttinv(poly a, const poly w)
{ // Inverse NTT transform
  int NumoProblems=3, jTwiddle=0, N=PARAM_N/2;
  for (; NumoProblems<N; NumoProblems*=2) {
    int jFirst, j=0;
    for (jFirst = 0; jFirst<PARAM_N; jFirst=j+NumoProblems) {
      sdigit_t W = (sdigit_t)w[jTwiddle++];
      for (j=jFirst; j<jFirst+NumoProblems; j++) {
        int32_t temp = a[j];
        a[j] = temp + a[j + NumoProblems];
        if (NumoProblems == 16*3) 
          a[j] = barr_reduce(a[j]);
        a[j + NumoProblems] = reduce((int64_t)W * (temp - a[j + NumoProblems]));
      }
    }
  }
 
  for (int j=0; j<NumoProblems; j++) {
    int32_t temp = reduce((int64_t)w[PARAM_N/3-2] * (a[j] - a[j + NumoProblems]));
    a[j] = reduce((int64_t)w[PARAM_N/3-1] * (a[j] + a[j + NumoProblems] - temp));
    a[j + NumoProblems] = reduce((int64_t)w[PARAM_N/3] * temp);
  }
  for (int i = 0; i < PARAM_N/2; i++)
    a[i] = reduce((int64_t)PARAM_R*a[i]);
}


static void poly_basemul(poly result, const poly x, const poly y, const poly w) 
{
  for (int i=0; i<PARAM_N/6; i++) {
    result[i*6 + 0]  = reduce((int64_t)x[i*6 + 2]*y[i*6 + 1]) + reduce((int64_t)x[i*6 + 1]*y[i*6 + 2]);
    result[i*6 + 0]  = reduce((int64_t)result[i*6 + 0]*w[128 + i])+ reduce((int64_t)x[i*6 + 0]*y[i*6 + 0]);
    result[i*6 + 1]  = reduce((int64_t)w[128 + i]*reduce((int64_t)x[i*6 + 2]*y[i*6 + 2]));
    result[i*6 + 1] += reduce((int64_t)x[i*6 + 0]*y[i*6 + 1]) + reduce((int64_t)x[i*6 + 1]*y[i*6 + 0]);
    result[i*6 + 2]  = reduce((int64_t)x[i*6 + 2]*y[i*6 + 0]) + reduce((int64_t)x[i*6 + 0]*y[i*6 + 2]);
    result[i*6 + 2] += reduce((int64_t)x[i*6 + 1]*y[i*6 + 1]);
    result[i*6 + 3]  = reduce((int64_t)x[i*6 + 5]*y[i*6 + 4]) + reduce((int64_t)x[i*6 + 4]*y[i*6 + 5]);
    result[i*6 + 3]  = reduce((int64_t)result[i*6 + 3]*(PARAM_Q-w[128 + i]))+ reduce((int64_t)x[i*6 + 3]*y[i*6 + 3]);
    result[i*6 + 4]  = reduce((int64_t)(PARAM_Q-w[128 + i])*reduce((int64_t)x[i*6 + 5]*y[i*6 + 5]));
    result[i*6 + 4] += reduce((int64_t)x[i*6 + 3]*y[i*6 + 4]) + reduce((int64_t)x[i*6 + 4]*y[i*6 + 3]);
    result[i*6 + 5]  = reduce((int64_t)x[i*6 + 5]*y[i*6 + 3]) + reduce((int64_t)x[i*6 + 3]*y[i*6 + 5]);
    result[i*6 + 5] += reduce((int64_t)x[i*6 + 4]*y[i*6 + 4]);
  }
}


void poly_ntt(poly x_ntt, const poly x)
{ // Call to NTT function. Avoids input destruction 

  for (int i=0; i<PARAM_N; i++)
    x_ntt[i] = x[i];
  ntt(x_ntt, zeta);
}


void poly_mul(poly result, const poly x, const poly y)
{ // Polynomial multiplication result = x*y, with in place reduction for (X^N+1)
  // The inputs x and y are assumed to be in NTT form

  poly_basemul(result, x, y, zeta);
  nttinv(result, zetainv);
}


void poly_add(poly result, const poly x, const poly y)
{ // Polynomial addition result = x+y

    for (int i=0; i<PARAM_N; i++)
      result[i] = x[i] + y[i];
}


void poly_add_correct(poly result, const poly x, const poly y)
{ // Polynomial addition result = x+y with correction

    for (int i=0; i<PARAM_N; i++) {
      result[i] = x[i] + y[i];
      result[i] += (result[i] >> (RADIX32-1)) & PARAM_Q;    // If result[i] < 0 then add q
      result[i] -= PARAM_Q;
      result[i] += (result[i] >> (RADIX32-1)) & PARAM_Q;    // If result[i] >= q then subtract q
    }
}


void poly_sub(poly result, const poly x, const poly y)
{ // Polynomial subtraction result = x-y

    for (int i=0; i<PARAM_N; i++)
      result[i] = x[i] - y[i];
}


void poly_sub_reduce(poly result, const poly x, const poly y)
{ // Polynomial subtraction result = x-y with Montgomery reduction

    for (int i=0; i<PARAM_N; i++)
      result[i] = reduce((int64_t)PARAM_R*(x[i] - y[i]));
}


/********************************************************************************************
* Name:        sparse_mul16
* Description: performs sparse polynomial multiplication
* Parameters:  inputs:
*              - const unsigned char* s: part of the secret key
*              - const uint32_t pos_list[PARAM_H]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_H]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*
* Note: pos_list[] and sign_list[] contain public information since c is public
*********************************************************************************************/
void sparse_mul16(poly prod, const int16_t *s, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H])
{
  int i, j, pos;
  int16_t *t = (int16_t*)s;

  for (i=0; i<PARAM_N; i++)
    prod[i] = 0;

  for (i=0; i<PARAM_H; i++) {
    pos = pos_list[i];
    for (j=0; j<pos; j++) {
      if(j<(PARAM_N>>1)){
        prod[j] = prod[j] - sign_list[i]*t[j+PARAM_N-pos];
        prod[j+(PARAM_N>>1)] = prod[j+(PARAM_N>>1)] + sign_list[i]*t[j+PARAM_N-pos];
      } else {
        prod[j-(PARAM_N>>1)] = prod[j-(PARAM_N>>1)] - sign_list[i]*t[j+PARAM_N-pos];
      }
    }
    for (j=pos; j<PARAM_N; j++) {
      prod[j] = prod[j] + sign_list[i]*t[j-pos];
    }
  }
}


/********************************************************************************************
* Name:        sparse_mul32
* Description: performs sparse polynomial multiplication 
* Parameters:  inputs:
*              - const int32_t* pk: part of the public key
*              - const uint32_t pos_list[PARAM_H]: list of indices of nonzero elements in c
*              - const int16_t sign_list[PARAM_H]: list of signs of nonzero elements in c
*              outputs:
*              - poly prod: product of 2 polynomials
*********************************************************************************************/
void sparse_mul32(poly prod, const int32_t *pk, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H])
{
  int i, j, pos;

  for (i=0; i<PARAM_N; i++)
    prod[i] = 0;
 
  for (i=0; i<PARAM_H; i++) {
    pos = pos_list[i];
    for (j=0; j<pos; j++) {
      if(j<(PARAM_N>>1)){
        prod[j] = prod[j] - sign_list[i]*pk[j+PARAM_N-pos];
        prod[j+(PARAM_N>>1)] = prod[j+(PARAM_N>>1)] + sign_list[i]*pk[j+PARAM_N-pos];
      } else {
        prod[j-(PARAM_N>>1)] = prod[j-(PARAM_N>>1)] - sign_list[i]*pk[j+PARAM_N-pos];
      }
    }
    for (j=pos; j<PARAM_N; j++) {
      prod[j] = prod[j] + sign_list[i]*pk[j-pos];
    }
  }
}
