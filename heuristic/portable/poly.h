#ifndef POLY_H
#define POLY_H

#include "params.h"
#include "config.h"
#include <stdint.h>

typedef int32_t poly[PARAM_N];
typedef	int32_t poly_k[PARAM_N*PARAM_K];

int32_t reduce(int64_t a);
int32_t barr_reduce(int32_t a);
void ntt(poly a, const poly w);
void nttinv(poly a, const poly w);
void poly_ntt(poly x_ntt, const poly x);
void poly_mul(poly result, const poly x, const poly y);
void poly_add(poly result, const poly x, const poly y);
void poly_add_correct(poly result, const poly x, const poly y);
void poly_sub(poly result, const poly x, const poly y);
void poly_sub_reduce(poly result, const poly x, const poly y);
void sparse_mul16(poly prod, const int16_t *s, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H]);
void sparse_mul32(poly prod, const int32_t *pk, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H]);
void poly_uniform(poly_k a, const unsigned char *seed);

#endif
