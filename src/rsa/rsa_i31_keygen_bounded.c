/*
 * Copyright (c) 2026 RinOS contributors
 * SPDX-License-Identifier: MIT
 *
 * Bounded wrapper for BearSSL's i31 key generator.  The implementation stays
 * in rsa_i31_keygen_inner.c so the candidate accounting covers both factors.
 */

#include "inner.h"

uint32_t
br_rsa_i31_keygen_bounded(const br_prng_class **rng,
	br_rsa_private_key *sk, void *kbuf_priv,
	br_rsa_public_key *pk, void *kbuf_pub,
	unsigned size, uint32_t pubexp, uint32_t max_candidates)
{
	return br_rsa_i31_keygen_inner_bounded(rng, sk, kbuf_priv, pk, kbuf_pub,
		size, pubexp, &br_i31_modpow_opt, max_candidates);
}
