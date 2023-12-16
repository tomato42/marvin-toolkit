/* Script to test RSA decryption with the OpenSSL EVP_PKEY_decrypt() API
 * in OpenSSL before version 3.2.0 (i.e. before OpenSSL implemented
 * implicit rejection a.k.a. Marvin workaround)
 */
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

void help(char *name) {
    printf("Usage: %s -i file -o file -k file -n num -a num [-h]\n", name);
    printf("\n");
    printf(" -i file    File with concatenated ciphertexts to decrypt\n");
    printf(" -o file    File where to write the time to decrypt the ciphertext\n");
    printf(" -k file    File with the RSA private key in PEM format\n");
    printf(" -n num     Length of RSA ciphertexts in bytes\n");
    printf(" -a num     Length of AES ciphertexts in bytes\n");
    printf(" -2         Use AES-256-CBC instead AES-128-CBC\n");
    printf(" -h         This message\n");
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the start of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_before() {
    uint64_t time_before = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_before = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    asm volatile (
        "mftb    %0": "=r" (time_before) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_before) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_before_high = 0, time_before_low = 0;
    asm volatile (
        "CPUID\n\t"
        "RDTSC\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t" : "=r" (time_before_high),
        "=r" (time_before_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_before = (uint64_t)time_before_high<<32 | time_before_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_before;
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the end of the measurement period
 * (because of barriers against speculative execution
 */
uint64_t get_time_after() {
    uint64_t time_after = 0;
#if defined( __s390x__ )
    /* The 64 bit TOD (time-of-day) value is running at 4096.000MHz, but
     * on some machines not all low bits are updated (the effective frequency
     * remains though)
     */

    /* use STCKE as it has lower overhead,
     * see http://publibz.boulder.ibm.com/epubs/pdf/dz9zr007.pdf
     */
    //asm volatile (
    //    "stck    %0": "=Q" (time_before) :: "memory", "cc");

    uint8_t clk[16];
    asm volatile (
          "stcke %0" : "=Q" (clk) :: "memory", "cc");
    /* since s390x is big-endian we can just do a byte-by-byte copy,
     * First byte is the epoch number (143 year cycle) while the following
     * 8 bytes are the same as returned by STCK */
    time_after = *(uint64_t *)(clk + 1);
#elif defined( __PPC64__ )
    /* Note: mftb can be used with a single instruction on ppc64, for ppc32
     * it's necessary to read upper and lower 32bits of the values in two
     * separate calls and verify that we didn't do that during low value
     * overflow
     */
    asm volatile (
        "mftb    %0": "=r" (time_after) :: "memory", "cc");
#elif defined( __aarch64__ )
    asm volatile (
        "mrs %0, cntvct_el0": "=r" (time_after) :: "memory", "cc");
#elif defined( __x86_64__ )
    uint32_t time_after_high = 0, time_after_low = 0;
    asm volatile (
        "RDTSCP\n\t"
        "mov %%edx, %0\n\t"
        "mov %%eax, %1\n\t"
        "CPUID\n\t": "=r" (time_after_high),
        "=r" (time_after_low)::
        "%rax", "%rbx", "%rcx", "%rdx");
    time_after = (uint64_t)time_after_high<<32 | time_after_low;
#else
#error Unsupported architecture
#endif /* ifdef __s390x__ */
    return time_after;
}

/* The boolean methods return a bitmask of all ones (0xff..ff) for true
 * and 0 for false
 */

/* make the compiler think that the value is being modified without
 * actually doing so
 */
static inline unsigned int
value_barrier(unsigned int a)
{
    unsigned int r;
    asm volatile (
        "" : "=r"(r) : "0"(a));
    // without asm:
    //volatile unsigned int r = a;
    return r;
}

static inline unsigned int
constant_time_msb(unsigned int a)
{
    return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline unsigned int
constant_time_select(unsigned int mask, unsigned int a, unsigned int b)
{
    return (value_barrier(mask) & a) | (value_barrier(~mask) & b);
}

static inline unsigned int
constant_time_is_zero(unsigned int a)
{
    return constant_time_msb(~a & (a - 1));
}

static inline unsigned int
constant_time_lt(unsigned int a, unsigned int b)
{
    return constant_time_msb(a ^ ((a ^ b) | ((a - b) ^ b)));
}

static inline unsigned int
constant_time_ge(unsigned int a, unsigned int b)
{
    return ~constant_time_lt(a, b);
}

static inline unsigned int
constant_time_eq(unsigned int a, unsigned int b)
{
    return constant_time_is_zero(a ^ b);
}

static inline void
constant_time_select_str(unsigned int mask,
                         char* restrict dst,
                         char* restrict a,
                         char* restrict b,
                         size_t sz)
{
    unsigned int mask_inv = ~mask;

    for (size_t i=0; i < sz; i++) {
        dst[i] = (value_barrier(mask) & a[i]) | (value_barrier(mask_inv) & b[i]);
    }
}

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_CIPHER_CTX *sctx = NULL;
    size_t plaintext_len = 0;
    size_t ciphertext_len = 0;
    size_t aes_len = 0;
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *aes_ciphertext = NULL;
    unsigned char *aes_plaintext = NULL;
    int aes_plaintext_len = 0;
    int opt;
    uint64_t time_before, time_after, time_diff;
    char iv[16];
    char key[32];
    char alt_key[32];
    char tag[] = "example";
    unsigned int op_res = -1; // true

    while ((opt = getopt(argc, argv, "i:o:k:n:a:h2")) != -1 ) {
        switch (opt) {
            case 'i':
                in_file_name = optarg;
                break;
            case 'o':
                out_file_name = optarg;
                break;
            case 'k':
                key_file_name = optarg;
                break;
            case 'n':
                sscanf(optarg, "%zi", &ciphertext_len);
                break;
            case 'a':
                sscanf(optarg, "%zi", &aes_len);
                break;
            case '2':
                fprintf(stderr, "AES-256 not supported yet\n");
                exit(1);
            case 'h':
                help(argv[0]);
                exit(0);
                break;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                help(argv[0]);
                exit(1);
                break;
        }
    }

    if (!in_file_name || !out_file_name || !key_file_name || !ciphertext_len
            || !aes_len) {
        fprintf(stderr, "Missing parameters!\n");
        help(argv[0]);
        exit(1);
    }

    in_fd = open(in_file_name, O_RDONLY);
    if (in_fd == -1) {
        fprintf(stderr, "can't open input file %s\n", in_file_name);
        goto err;
    }

    out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666);
    if (out_fd == -1) {
        fprintf(stderr, "can't open output file %s\n", out_file_name);
        goto err;
    }

    fprintf(stderr, "malloc(plaintext)\n");
    plaintext = malloc(ciphertext_len);
    if (!plaintext)
        goto err;

    fprintf(stderr, "malloc(ciphertext)\n");
    ciphertext = malloc(ciphertext_len);
    if (!ciphertext)
        goto err;

    fprintf(stderr, "malloc(aes_ciphertext)\n");
    aes_ciphertext = malloc(aes_len);
    if (!aes_ciphertext)
        goto err;

    fprintf(stderr, "malloc(aes_plaintext)\n");
    aes_plaintext = malloc(aes_len);
    if (!aes_plaintext)
        goto err;

    fprintf(stderr, "fopen()\n");
    fp = fopen(key_file_name, "r");
    if (!fp) {
        fprintf(stderr, "Can't open key file %s\n", key_file_name);
        goto err;
    }

    fprintf(stderr, "PEM_read_PrivateKey()\n");
    if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL)
        goto err;

    fprintf(stderr, "fclose()\n");
    if (fclose(fp) != 0)
        goto err;
    fp = NULL;

    fprintf(stderr, "EVP_PKEY_CTX_new()\n");
    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
        goto err;

    fprintf(stderr, "EVP_PKEY_decrypt_init()\n");
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        goto err;

    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding()\n");
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        goto err;

    fprintf(stderr, "EVP_CIPHER_CTX_new()\n");
    if ((sctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    fprintf(stderr, "EVP_CipherInit_ex2()\n");
    if (!EVP_CipherInit_ex2(sctx, EVP_aes_128_cbc(), NULL, NULL, 0, NULL))
        goto err;

    fprintf(stderr, "EVP_CIPHER_CTX_set_padding()\n");
    if (!EVP_CIPHER_CTX_set_padding(sctx, 0))
        goto err;

    fprintf(stderr, "Decrypting ciphertexts...\n");

    while ((r_ret = read(in_fd, ciphertext, ciphertext_len)) > 0) {
        if (r_ret != ciphertext_len) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            goto err;
        }

        r_ret = read(in_fd, iv, 16);
        if (r_ret != 16) {
            fprintf(stderr, "Reading AES IV failed (truncated file?)\n");
            goto err;
        }

        r_ret = read(in_fd, aes_ciphertext, aes_len);
        if (r_ret != aes_len) {
            fprintf(stderr, "Reading AES ciphertext failed (truncated file?)\n");
            goto err;
        }

        plaintext_len = ciphertext_len;

        time_before = get_time_before();

        ERR_set_mark();

        if (RAND_bytes(alt_key, 16) <= 0) {
            fprintf(stderr, "RAND_bytes() failed\n");
            goto err;
        }

        r_ret = EVP_PKEY_decrypt(ctx, plaintext, &plaintext_len,
                                 ciphertext, ciphertext_len);

        /*
        if (r_ret != 1 || plaintext_len != 16) {
            memcpy(key, alt_key, 16);
        } else {
            memcpy(key, plaintext, 16);
        }
        */
        op_res = constant_time_eq(r_ret, 1);
        op_res &= constant_time_eq(plaintext_len, 16);
        constant_time_select_str(op_res, key, plaintext, alt_key, 16);

        if (!EVP_CipherInit_ex2(sctx, NULL, key, iv, 0, NULL)) {
            fprintf(stderr, "Setting key/IV failed\n");
            goto err;
        }

        if (!EVP_CIPHER_CTX_set_padding(sctx, 0)) {
            fprintf(stderr, "Disabling padding failed\n");
            goto err;
        }

        if (!EVP_CipherUpdate(sctx,
                              aes_plaintext, &aes_plaintext_len,
                              aes_ciphertext, aes_len)) {
            fprintf(stderr, "AES Decryption failed\n");
            goto err;
        }

        if (!EVP_CipherFinal_ex(sctx, aes_plaintext + aes_plaintext_len,
                                &aes_plaintext_len)) {
            fprintf(stderr, "AES padding check failed\n");
            goto err;
        }

        int pad_len = aes_plaintext[aes_len-1];
        /*
        if (pad_len < 1 || pad_len > 16) {
            r_ret = -1;
            pad_len = 16;
        } else {
            for (int i=aes_len-pad_len; i < aes_len; i++) {
                if (aes_plaintext[i] != pad_len)
                    r_ret = -1;
            }
        }
        */
        op_res &= ~constant_time_lt(pad_len, 1);
        op_res &= ~constant_time_lt(16, pad_len);
        pad_len = constant_time_select(op_res, pad_len, 1);
        int real_start = aes_len-pad_len;
        for (int i = aes_len-16-1; i < aes_len; i++) {
            op_res &= constant_time_select(
                    constant_time_ge(i, real_start),
                    constant_time_eq(aes_plaintext[i], pad_len),
                    op_res);
        }

        real_start -= (sizeof(tag)-1);

        /*
        for (int i=0; i < sizeof(tag)-1; i++) {
            if (aes_plaintext[i+aes_len-pad_len-(sizeof(tag)-1)] != tag[i])
                r_ret = -1;
        }
        */
        /* XXX it tests as side-channel free, but it probably should be
         * position independent (i.e. start at -16-sizeof(tag), and
         * continue up to -2) and compare every position with full tag
         * (i.e. use quadratic complexity algorithm).
         */
        for (int i=0; i < sizeof(tag)-1; i++) {
            op_res &= constant_time_eq(aes_plaintext[real_start + i],
                                       tag[i]);
        }

        ERR_pop_to_mark();

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(out_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

    err:
    fprintf(stderr, "failed!\n");
    ERR_print_errors_fp(stderr);
    result = 1;

    out:
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
    if (aes_ciphertext)
        free(aes_ciphertext);
    if (aes_plaintext)
        free(aes_plaintext);
    if (sctx)
        EVP_CIPHER_CTX_free(sctx);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return result;
}

