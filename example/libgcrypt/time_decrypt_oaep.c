#include "common.c"

int main(int argc, char *argv[]) {
    int result = 1, r_ret;
    gcry_sexp_t pkey = NULL;
    size_t ciphertext_len = 0;
    FILE *fp;
    char *key_file_name = NULL, *in_file_name = NULL, *out_file_name = NULL;
    int in_fd = -1, out_fd = -1;
    unsigned char *ciphertext = NULL;
    unsigned char *plaintext = NULL;
    int opt;
    uint64_t time_before, time_after, time_diff;

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

    fprintf(stderr, "read_private_key()\n");
    if ((pkey = read_private_key(fp))== NULL) {
        fprintf(stderr, "Can't read key from file %s\n", key_file_name);
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

        gcry_sexp_t ciphertext_sexp;
        gcry_sexp_t plaintext_sexp;
        size_t erroff;

        if (r_ret = gcry_sexp_build(&ciphertext_sexp, &erroff,
                "(enc-val (flags oaep) (rsa (a %b)))",
                ciphertext_len, ciphertext)) {
            fprintf(stderr, "ciphertext s-expression construction failed\n");
            fprintf(stderr, "error at pos %i\n", erroff);
            fprintf(stderr, "error code: %i\n", r_ret);
            fprintf(stderr, "failure: %s/%s\n",
                    gcry_strsource(r_ret), gcry_strerror(r_ret));
            goto err;
        }

        time_before = get_time_before();

        r_ret = gcry_pk_decrypt(&plaintext_sexp, ciphertext_sexp, pkey);
        if (r_ret == 0) {
            fprintf(stderr, "Decryption did not fail as expected\n");
            goto err;
        }

        gcry_sexp_release(plaintext_sexp);

        time_after = get_time_after();

        time_diff = time_after - time_before;

        r_ret = write(out_fd, &time_diff, sizeof(time_diff));
        if (r_ret <= 0) {
            fprintf(stderr, "Write error\n");
            goto err;
        }

        gcry_sexp_release(ciphertext_sexp);
    }

    result = 0;
    fprintf(stderr, "finished\n");
    goto out;

    err:
    fprintf(stderr, "failed!\n");
    result = 1;

    out:
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
    if (pkey)
        gcry_sexp_release(pkey);
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    return result;
}
