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
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
# include <openssl/core_names.h>
#endif

#define TPM_POSIX
#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>

void help(char *name) {
    printf("Usage: %s -i file -o file -k file -n num [-h]\n", name);
    printf("\n");
    printf(" -i file    File with concatenated ciphertexts to decrypt\n");
    printf(" -o file    File where to write the time to decrypt the ciphertext\n");
    printf(" -k file    File with the RSA private key in PEM format\n");
    printf(" -n num     Length of individual ciphertexts in bytes\n");
    printf(" -v         Turn on TSS log/debug messages\n");
    printf(" -V         Turn decryption error messages\n");
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

TPM_RC RsaPemToTPM(EVP_PKEY            *pkey,
                   TPM2B_SENSITIVE     *objSensitive,
                   TPM2B_PUBLIC        *objPublic,
                   TPMI_ALG_SIG_SCHEME  scheme,
                   TPMI_ALG_HASH        nameAlg)
{
    TPMT_SENSITIVE *tSensitive = &objSensitive->t.sensitiveArea;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BIGNUM *p = NULL;
    BIGNUM *n = NULL;
#else
    const BIGNUM *p = NULL;
    const BIGNUM *n = NULL;
    const RSA *rsa;
#endif
    TPM_RC rc = -1;

    objSensitive->t.size = sizeof(*tSensitive);

    tSensitive->sensitiveType = TPM_ALG_RSA;
    tSensitive->authValue.b.size = 0;
    tSensitive->seedValue.b.size = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p)) {
        fprintf(stderr, "EVP_PKEY_get_bn_param failed for factor 1\n");
        return -1;
    }
#else
    rsa = EVP_PKEY_get0_RSA(pkey);
    p = RSA_get0_p(rsa);
#endif
    if (BN_num_bytes(p) > sizeof(tSensitive->sensitive.rsa.t.buffer)) {
        fprintf(stderr, "Private exponent is too large: %d > %zu\n",
                BN_num_bytes(p), sizeof(tSensitive->sensitive.rsa.t.buffer));
        return -1;
    }
    tSensitive->sensitive.rsa.t.size = BN_num_bytes(p);
    BN_bn2bin(p, tSensitive->sensitive.rsa.t.buffer);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
        fprintf(stderr, "EVP_PKEY_get_bn_param failed for modulus\n");
        goto error;
    }
#else
    n = RSA_get0_n(rsa);
#endif
    if (BN_num_bytes(n) > sizeof(objPublic->publicArea.unique.rsa.t.buffer)) {
        fprintf(stderr, "Modulus is too large: %d > %zu\n",
                BN_num_bytes(n), sizeof(objPublic->publicArea.unique.rsa.t.buffer));
        goto error;
    }

    objPublic->publicArea.type = TPM_ALG_RSA;
    objPublic->publicArea.nameAlg = nameAlg;
    objPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA |
                                                 TPMA_OBJECT_USERWITHAUTH |
                                                 TPMA_OBJECT_DECRYPT;
    objPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
    objPublic->publicArea.authPolicy.t.size = 0;
    objPublic->publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_RSAES;
    objPublic->publicArea.parameters.rsaDetail.keyBits = BN_num_bytes(n) * 8;
    objPublic->publicArea.parameters.rsaDetail.exponent = 0;

    objPublic->publicArea.unique.rsa.t.size = BN_num_bytes(n);
    BN_bn2bin(n, objPublic->publicArea.unique.rsa.t.buffer);

    rc = 0;

error:
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    BN_free(p);
    BN_free(n);
#endif

    return rc;
}

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t ciphertext_len = 0;
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    int opt;
    uint64_t time_before, time_after, time_diff;
    TPM_RC rc;
    LoadExternal_In le_in;
    LoadExternal_Out le_out;
    RSA_Decrypt_In rd_in;
    RSA_Decrypt_Out rd_out;
    TSS_CONTEXT *tssContext = NULL;
    int verbose = 0;

    while ((opt = getopt(argc, argv, "i:o:k:n:vVh")) != -1 ) {
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
            case 'v':
                TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
                break;
            case 'V':
                verbose = 1;
                break;
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

    if (!in_file_name || !out_file_name || !key_file_name || !ciphertext_len) {
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

    fprintf(stderr, "RsaPemToTPM()\n");
    memset(&le_in, 0, sizeof(le_in));
    if (RsaPemToTPM(pkey, &le_in.inPrivate, &le_in.inPublic,
                    TPM_ALG_NULL, TPM_ALG_SHA256) < 0) {
        fprintf(stderr, "Could not convert key to public\n");
        goto err;
    }
    le_in.hierarchy = TPM_RH_NULL;

    if (ciphertext_len > le_in.inPublic.publicArea.unique.rsa.t.size) {
        fprintf(stderr, "The -n parameter is larger then the size of modulus: %zu > %d\n",
                ciphertext_len, le_in.inPublic.publicArea.unique.rsa.t.size);
        goto err;
    }

    if ((rc = TSS_Create(&tssContext)) != 0) {
        fprintf(stderr, "Could not create TSS context: 0x%x\n", rc);
        goto err;
    }

    if ((rc = TSS_Execute(tssContext,
                          (RESPONSE_PARAMETERS *)&le_out,
                          (COMMAND_PARAMETERS *)&le_in,
                          NULL,
                          TPM_CC_LoadExternal,
                          TPM_RH_NULL, NULL, 0,
                          TPM_RH_NULL, NULL, 0,
                          TPM_RH_NULL, NULL, 0,
                          TPM_RH_NULL, NULL, 0)) != 0) {
        fprintf(stderr, "Could not execute LoadExternal command: 0x%x\n", rc);
        goto err;
    }

    fprintf(stderr, "Decrypting ciphertexts using TPM 2 ...\n");

    int c = 0, dec_fail = 0, msg_fail = 0;

    while ((r_ret = read(in_fd, ciphertext, ciphertext_len)) > 0) {
        if (r_ret != ciphertext_len) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            goto err;
        }
        c++;

        memset(&rd_in, 0, sizeof(rd_in));
        rd_in.keyHandle = le_out.objectHandle;
        rd_in.cipherText.t.size = ciphertext_len;
        memcpy(rd_in.cipherText.t.buffer, ciphertext, ciphertext_len);
        rd_in.inScheme.scheme = TPM_ALG_RSAES;
        rd_in.label.t.size = 0;

        time_before = get_time_before();

        r_ret = TSS_Execute(tssContext,
                            (RESPONSE_PARAMETERS *)&rd_out,
                            (COMMAND_PARAMETERS *)&rd_in,
                            NULL,
                            TPM_CC_RSA_Decrypt,
                            TPM_RS_PW, "", 0,
                            TPM_RH_NULL, NULL, 0,
                            TPM_RH_NULL, NULL, 0,
                            TPM_RH_NULL, NULL, 0);

        time_after = get_time_after();

        if (r_ret != 0) {
            if (verbose) {
                fprintf(stderr, "Decryption failure: 0x%x\n", r_ret);
                fprintf(stderr, "%x\n", ciphertext[0]);
            }
            dec_fail++;
        } else if (rd_out.message.t.size != 48) {
            /* this should not happen */
            if (verbose)
                fprintf(stderr, "Unexpected plaintext size: %d\n",
                        rd_out.message.t.size);
            msg_fail++;
        }

        time_diff = time_after - time_before;

        r_ret = write(out_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error\n");
            goto err;
        }
    }

    result = 0;
    fprintf(stderr,
            "finished  total: %d decryption failures: %d  unexpected msg len: %d\n",
            c, dec_fail, msg_fail);
    goto out;

    err:
    fprintf(stderr, "failed!\n");
    ERR_print_errors_fp(stderr);
    result = 1;

    out:
    if (tssContext)
        TSS_Delete(tssContext);
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
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
