/* Script to test RSA decryption with Apple CoreCrypto
 */
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <mach/mach_time.h>

#import <Foundation/Foundation.h>
#import <Security/Security.h>

void help(char *name) {
    printf("Usage: %s -i file -o file -k file -n num [-h]\n", name);
    printf("\n");
    printf(" -i file    File with concatenated ciphertexts to decrypt\n");
    printf(" -o file    File where to write the time to decrypt the ciphertext\n");
    printf(" -k file    File with the RSA private key in PEM format\n");
    printf(" -n num     Length of individual ciphertexts in bytes\n");
    printf(" -h         This message\n");
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the start of the measurement period
 * (because of barriers against speculative execution).
 */
static uint64_t get_time_before() {
    return mach_absolute_time();
}

/* Get an architecture specific most precise clock source with the lowest
 * overhead. Should be executed at the end of the measurement period
 * (because of barriers against speculative execution).
 */
static uint64_t get_time_after() {
    return mach_absolute_time();
}

static int nsvfprintf (FILE *stream, NSString *format, va_list args) {
    int retval;

    NSString *str;
    str = (NSString *) CFStringCreateWithFormatAndArguments(NULL, NULL, (CFStringRef) format, args);
    retval = fprintf(stream, "%s", [str UTF8String]);
    [str release];

    return retval;
}

static int nsfprintf (FILE *stream, NSString *format, ...) {
    va_list ap;
    int retval;

    va_start(ap, format);
    {
        retval = nsvfprintf(stream, format, ap);
    }
    va_end(ap);

    return retval;
}

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    size_t ciphertext_len = 0;
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1;
    struct stat st;
    unsigned char *ciphertext = NULL;
    uint8_t *key_bytes = NULL;
    int opt;
    uint64_t time_before, time_after, time_diff;
	SecKeyRef key = NULL;
	mach_timebase_info_data_t timebase;

	mach_timebase_info(&timebase);

    while ((opt = getopt(argc, argv, "i:o:k:n:h")) != -1 ) {
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
        return EXIT_FAILURE;
    }

    if ((in_fd = open(in_file_name, O_RDONLY)) == -1) {
        fprintf(stderr, "can't open input file %s\n", in_file_name);
        goto err;
    }
    if ((out_fd = open(out_file_name, O_WRONLY|O_TRUNC|O_CREAT, 0666)) == -1) {
        fprintf(stderr, "can't open output file %s\n", out_file_name);
        goto err;
    }

    if ((ciphertext = malloc(ciphertext_len)) == NULL) {
        fprintf(stderr, "malloc(ciphertext): %m\n");
        goto err;
    }

    if ((fp = fopen(key_file_name, "r")) == NULL) {
        fprintf(stderr, "Can't open key file %s: %m\n", key_file_name);
        goto err;
    }
    if (fstat(fileno(fp), &st) != 0) {
        fprintf(stderr, "Can't fstat(2) key file %s: %m\n", key_file_name);
        goto err;
    }
    if ((key_bytes = malloc(st.st_size + 1)) == NULL) {
        fprintf(stderr, "malloc(key_bytes, %jd): %m", (intmax_t) st.st_size);
        goto err;
    }
    if (fread(key_bytes, st.st_size, 1, fp) != 1) {
        fprintf(stderr, "Can't fread(3) key file %s: %m\n", key_file_name);
        goto err;
    }
    fclose(fp);
    fp = NULL;

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, key_bytes, st.st_size);

    // The key is assumed to be public, 2048-bit RSA
    NSDictionary* options = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
        (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate
    };
    CFErrorRef error = NULL;
    key = SecKeyCreateWithData(data,
                               (__bridge CFDictionaryRef)options,
                               &error);
    if (!key) {
        NSError *err = CFBridgingRelease(error);  // ARC takes ownership
        nsfprintf(stderr, @"Failed to load key: %@\n", err);
		key_bytes[st.st_size] = '\0';
		fprintf(stderr, "Key was:\n%s\n", (const char *)key_bytes);
        return EXIT_FAILURE;
    }

    CFRelease(data);


    fprintf(stderr, "Decrypting ciphertexts...\n");
    while ((r_ret = read(in_fd, ciphertext, ciphertext_len)) > 0) {
        if (r_ret != ciphertext_len) {
            fprintf(stderr, "read less data than expected (truncated file?)\n");
            goto err;
        }

		CFDataRef cf_ciphertext = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, ciphertext, ciphertext_len, kCFAllocatorNull);
		CFErrorRef err = NULL;

        time_before = get_time_before();
        CFDataRef plaintext = SecKeyCreateDecryptedData(key, kSecKeyAlgorithmRSAEncryptionPKCS1, cf_ciphertext, &err);
        time_after = get_time_after();

		if (!plaintext) {
			CFRelease(err);
			//NSError *ns_err = CFBridgingRelease(err);
			//nsfprintf(stderr, @"Failed to decrypt: %@\n", ns_err);
			//goto err;
		} else {
			CFRelease(plaintext);
		}

		/* convert mach_absolute_time() to nanoseconds */
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
    result = 1;

    out:
    if (key)
        CFRelease(key);
    if (ciphertext)
        free(ciphertext);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return result;
}
