#ifndef ENCRYPT_HPP
#define ENCRYPT_HPP

#include <vector>
#include <random>

#include <immintrin.h>
#include <openssl/sha.h>

#ifdef AESNI
#include <wmmintrin.h>
#endif

namespace encryption {

using encr_key_t = unsigned int;

extern std::mt19937 encr_noise_generator;

alignas(__m256i) static unsigned char sha1_buf[32];

inline unsigned int prng_uint(unsigned int input)
{
    unsigned char* hash = SHA1(reinterpret_cast<unsigned char*>(&input), sizeof(unsigned int), sha1_buf);
    return *reinterpret_cast<unsigned int*>(hash);
}

inline __m128i prng_m128(__m128i input)
{
    unsigned char* hash = SHA1(reinterpret_cast<unsigned char*>(&input), sizeof(__m128i), sha1_buf);
    return *reinterpret_cast<__m128i*>(hash);
}

inline __m256i prng_m256(__m256i input)
{
    unsigned char* hash = SHA1(reinterpret_cast<unsigned char*>(&input), sizeof(__m256i), sha1_buf);
    return *reinterpret_cast<__m256i*>(hash);
}

void encrypt_int_sum_naive(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
			   std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_sum_naive(unsigned int *rbuf, int count,
			   std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_int_sum_sha1sse2(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
			      std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_sum_sha1sse2(unsigned int *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_int_sum_sha1avx2(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
			      std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_sum_sha1avx2(unsigned int *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_int_prod_naive(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
			   std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_prod_naive(unsigned int *rbuf, int count,
			    std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_float_sum_naive(float *encr_sbuf, const float *sbuf, int count, int rank,
			     std::vector<unsigned int> &k_s, unsigned int k_n);
void decrypt_float_sum_naive(float *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);

#ifdef AESNI

unsigned int aesni128_prng(unsigned int);
void aesni128_load_key(char *enc_key);

void encrypt_int_sum_aesni128(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
			      std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_sum_aesni128(unsigned int *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_int_sum_aesni128_unroll(unsigned int *encr_sbuf, const unsigned int *sbuf, int count, int rank,
				     std::vector<unsigned int> &k_s, unsigned int k_n, bool is_edge);
void decrypt_int_sum_aesni128_unroll(unsigned int *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);
void encrypt_float_sum_aesni128_unroll(float *encr_sbuf, const float *sbuf, int count, int rank,
				       std::vector<unsigned int> &k_s, unsigned int k_n);
void decrypt_float_sum_aesni128_unroll(float *rbuf, int count, std::vector<unsigned int> &k_s, unsigned int k_n);

#endif

}

#endif
