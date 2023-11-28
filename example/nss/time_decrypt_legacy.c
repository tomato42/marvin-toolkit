/* Script to test RSA decryption with the NSS freebl API
 */
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#define USE_UTIL_DIRECTLY 1
#include <seccomon.h>
#include <blapi.h>
#include <secasn1.h>
#include <secoid.h>
#include <secitem.h>
#include <secerr.h>
#include <base64.h>
#include <prerror.h>
#include <nssutil.h>

void help(char *name) {
    printf("Usage: %s -i file -o file -k file -n num [-h -r -p]\n", name);
    printf("\n");
    printf(" -i file    File with concatenated ciphertexts to decrypt\n");
    printf(" -o file    File where to write the time to decrypt the ciphertext\n");
    printf(" -k file    File with the RSA private key in PEM format\n");
    printf(" -n num     Length of individual ciphertexts in bytes\n");
    printf(" -r         use raw RSA rather than RSA-PKCS\n");
    printf(" -p         use RSA-OAEP rather than RSA-PKCS\n");
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

const SEC_ASN1Template rsaPrivateKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(RSAPrivateKey) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, version) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, modulus) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, publicExponent) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, privateExponent) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, prime1) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, prime2) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, exponent1) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, exponent2) },
    { SEC_ASN1_INTEGER, offsetof(RSAPrivateKey, coefficient) },
    { 0 }
};

typedef struct PrivateKeyInfoStr {
    PLArenaPool *arena;
    SECItem version;
    SECAlgorithmID algorithm;
    SECItem privateKey;
} PrivateKeyInfo;

/* ASN1 Templates for new decoder/encoder */
const SEC_ASN1Template privateKeyInfoTemplate[] = {
    { SEC_ASN1_SEQUENCE,
      0, NULL, sizeof(PrivateKeyInfo) },
    { SEC_ASN1_INTEGER,
      offsetof(PrivateKeyInfo, version) },
    { SEC_ASN1_INLINE | SEC_ASN1_XTRN,
      offsetof(PrivateKeyInfo, algorithm),
      SEC_ASN1_SUB(SECOID_AlgorithmIDTemplate) },
    { SEC_ASN1_OCTET_STRING,
      offsetof(PrivateKeyInfo, privateKey) },
    { 0 }
};

void
dump_item(const SECItem *item)
{
    int i;
    for (i=0; i < item->len; i++){
        printf("%02x", item->data[i]);
    }
}

#define TRIGGER "----"
int
pem_check_start_end(char *sbuf) {
    return strncmp(sbuf, TRIGGER, sizeof(TRIGGER)-1) == 0;
}

SECStatus
SECITEM_AppendItem(SECItem *ibuf, const SECItem *iabuf)
{
    SECStatus rv;
    unsigned int ibuf_len = ibuf->len;
    unsigned int new_len = ibuf->len+iabuf->len;

    if (iabuf->len == 0) {
        return SECSuccess;
    }
    rv = SECITEM_ReallocItem(NULL, ibuf, ibuf_len, new_len);
    if (rv != SECSuccess) {
        return rv;
    }
    ibuf->len=new_len;
    PORT_Memcpy(ibuf->data+ibuf_len, iabuf->data, iabuf->len);
    return SECSuccess;
}

#define MAX_LINE_LENGTH 200
SECStatus
readkeydata(FILE *fp, SECItem *ibuf)
{
    char sbuf[MAX_LINE_LENGTH];
    SECItem iabuf = {siBuffer, NULL, 0};
    char *s;
    int trigger;
    enum { STATE_BEGIN, STATE_DECODE, STATE_END} state = STATE_BEGIN;
    SECStatus rv;

    ibuf->data = NULL;
    ibuf->len = 0;

    /* should we autodetect binary files here */
    while ((s  = fgets(sbuf, MAX_LINE_LENGTH, fp)) != NULL) {
        trigger = pem_check_start_end(sbuf);
        switch (state) {
            case STATE_BEGIN:
                if (trigger) {
                    state = STATE_DECODE;
                }
                break;
            case STATE_DECODE:
                if (trigger) {
                    state = STATE_END;
                    break;
                }
                rv = ATOB_ConvertAsciiToItem(&iabuf, sbuf);
                if (rv != SECSuccess) {
                    goto loser;
                }
                rv = SECITEM_AppendItem(ibuf, &iabuf);
                if (rv != SECSuccess) {
                    goto loser;
                }
                SECITEM_FreeItem(&iabuf, PR_FALSE);
                break;
            case STATE_END:
                break;
        }
    }
    return SECSuccess;

loser:
    SECITEM_FreeItem(&iabuf, PR_FALSE);
    SECITEM_FreeItem(ibuf, PR_FALSE);
    return SECFailure;
}


RSAPrivateKey *
nss_PEM_read_PrivateKey(FILE *fp)
{
    SECItem buf = { siBuffer, NULL, 0};
    PrivateKeyInfo pki;
    RSAPrivateKey *pkey;
    PLArenaPool *arena;
    SECOidTag algTag;
    SECStatus rv;

    arena = PORT_NewArena(2048);
    if (!arena) {
        goto loser;
    }

    rv = readkeydata(fp, &buf);
    if (rv != SECSuccess) {
        goto loser;
    }
    pkey = (RSAPrivateKey *)PORT_ArenaZAlloc(arena, sizeof(RSAPrivateKey));
    pkey->arena = arena;
    pkey->modulus.type = siUnsignedInteger;
    pkey->publicExponent.type = siUnsignedInteger;
    pkey->privateExponent.type = siUnsignedInteger;
    pkey->prime1.type = siUnsignedInteger;
    pkey->prime2.type = siUnsignedInteger;
    pkey->exponent1.type = siUnsignedInteger;
    pkey->exponent2.type = siUnsignedInteger;
    pkey->coefficient.type = siUnsignedInteger;

    rv = SEC_QuickDERDecodeItem(arena, &pki, privateKeyInfoTemplate, &buf);
    if (rv != SECSuccess) {
        goto loser;
    }
    algTag = SECOID_GetAlgorithmTag(&pki.algorithm);
    if ((algTag != SEC_OID_PKCS1_RSA_ENCRYPTION) && (algTag != SEC_OID_PKCS1_RSA_PSS_SIGNATURE)) {
        PORT_SetError(SEC_ERROR_INVALID_KEY);
        goto loser;
    }
    rv = SEC_QuickDERDecodeItem(arena, pkey, rsaPrivateKeyTemplate, &pki.privateKey);
    if (rv != SECSuccess) {
        goto loser;
    }
    return pkey;

loser:
    SECITEM_FreeItem(&buf, PR_FALSE);
    if (arena) {
        PORT_FreeArena(arena, PR_TRUE);
    }
    return NULL;
}

typedef enum { RSA_OAEP, RSA_PKCS, RSA_RAW } RSAEncoding;

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    RSAPrivateKey *pkey = NULL;
    unsigned int plaintext_len = 0;
    size_t ciphertext_len = 0;
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    int opt;
    uint64_t time_before, time_after, time_diff;
    HASH_HashType hashAlg = HASH_AlgSHA256;
    HASH_HashType maskHashAlg = HASH_AlgSHA256;
    char label[] = "default label";
    unsigned int labelLen = sizeof(label);
    RSAEncoding type = RSA_PKCS;
    SECStatus rv = SECSuccess;

    while ((opt = getopt(argc, argv, "i:o:k:n:rph")) != -1 ) {
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
            case 'r':
                type = RSA_RAW;
                break;
            case 'p':
                type = RSA_OAEP;
                break;
            case 'n':
                sscanf(optarg, "%zi", &ciphertext_len);
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

    (void)NSS_InitializePRErrorTable();
    PORT_SetError(0);
    SECOID_Init();

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
    if ((pkey = nss_PEM_read_PrivateKey(fp)) == NULL) {
        rv = SECFailure;
        goto err;
    }

    fprintf(stderr, "fclose()\n");
    if (fclose(fp) != 0)
        goto err;
    fp = NULL;


    fprintf(stderr, "Decrypting ciphertexts...\n");

    while ((r_ret = read(in_fd, ciphertext, ciphertext_len)) > 0) {
        if (r_ret != ciphertext_len) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            goto err;
        }

        plaintext_len = ciphertext_len;

        switch (type) {
        case RSA_OAEP:
            time_before = get_time_before();
            (void) RSA_DecryptOAEP(pkey, hashAlg, maskHashAlg, label, labelLen,
                                 plaintext, &plaintext_len, plaintext_len,
                                 ciphertext, ciphertext_len);
            time_after = get_time_after();
            break;
        case RSA_PKCS:
            time_before = get_time_before();
            rv = RSA_DecryptBlock(pkey, plaintext, &plaintext_len,
                                  plaintext_len, ciphertext, ciphertext_len);
            time_after = get_time_after();
            break;

        case RSA_RAW:
            time_before = get_time_before();
            rv = RSA_DecryptRaw(pkey, plaintext, &plaintext_len,
                                  plaintext_len, ciphertext, ciphertext_len);
            time_after = get_time_after();
            break;
        default:
            fprintf(stderr,"Unknown RSA key type\n");
            goto err;
        }
        if (rv != SECSuccess) {
            goto err;
        }



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
    if (rv == SECSuccess) {
        perror("failed!\nlibc");
    } else {
        fprintf(stderr,  "failed!\nnss:%s (%d)\n",
                PORT_ErrorToString(PORT_GetError()), PORT_GetError());
    }
    result = 1;

    out:
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
    if (pkey)
        PORT_FreeArena(pkey->arena, PR_TRUE);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return result;
}

