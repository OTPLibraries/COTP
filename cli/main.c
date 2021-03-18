#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "../cotp.h"


// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
int hmac_algo_sha1(const char byte_secret[], const char byte_string[], char out[]) {

	// Output len
	unsigned int len = SHA1_BYTES;

	// Return the HMAC success
	return HMAC(
			EVP_sha1(),									// algorithm
			(unsigned char*)byte_secret, 10,			// key
			(unsigned char*)byte_string, 8,				// data
			(unsigned char*)out, &len) == 0 ? 0 : 1;	// output
}


void print_usage (char* cmd) {
    fprintf (stderr, "Usage:\n\n");
    fprintf (stderr, "  Generate secret with a length of 16 characters:\n    %s -g secret -l 16\n\n", cmd);
    fprintf (stderr, "  Generate 6-digit code which is valid for 30 seconds:\n    %s -g code -s <secret> -l 6 -t 30\n\n", cmd);
    fprintf (stderr, "  Verify code which is valid for <validity-period> seconds using <secret>:\n    %s -v -s <secret> -t <validity-period> -c <code>\n\n", cmd);
}

char* generate_secret (int length) {
    char *value = NULL;

    if (length < 1 || length > 64) {
        length = 16;
    }

    value = malloc(length + 1 * sizeof(char));
    otp_random_base32(length, otp_DEFAULT_BASE32_CHARS, value);
    value[length] = '\0';

    return value;
}

char* generate_code (char *secret, int length, int time_period) {
    char *value = NULL;

    if (length < 1 || length > 12) {
        length = 6;
    }

    if (time_period < 1 || time_period > 180) {
        time_period = 30;
    }

    OTPData* tdata = totp_new(
        secret,
        SHA1_BITS,
        hmac_algo_sha1,
        SHA1_DIGEST,
        length,
        time_period
    );

    value = malloc(length + 1 * sizeof(char));
    totp_now(tdata, value);
    value[length] = '\0';

    return value;
}

int verify_code (char *code, char *secret, int time_period) {
    return strcmp (code, generate_code (secret, strlen (code), time_period)) == 0;
}

int main(int argc, char** argv) {
    bool verify_flag = false;

    char *generate_value = NULL;
    char *secret_value = NULL;
    char *code_value = NULL;

    int length = 0;
    int time_period = 0;
    int opt;

    if (argc == 1) {
        print_usage (argv[0]);
        return EXIT_FAILURE;

    } else {
        while ((opt = getopt (argc, argv, "vg:s:c:l:t:")) != -1) {
            switch (opt) {
            case 'v':
                verify_flag = true;
                break;

            case 'g':
                generate_value = optarg;
                break;

            case 's':
                secret_value = optarg;
                break;

            case 'c':
                code_value = optarg;
                break;

            case 'l':
                if (optarg != NULL) {
                    length = atoi(optarg);
                }
                break;

            case 't':
                if (optarg != NULL) {
                    time_period = atoi(optarg);
                }
                break;

            default:
                print_usage (argv[0]);
                return EXIT_FAILURE;
            }
        }
    }

    if (generate_value != NULL && generate_value != 0) {
        if (strcmp(generate_value, "code") == 0 && secret_value != NULL && secret_value != 0) {
            // Generate Code
            printf ("%s\n", generate_code (secret_value, length, time_period));
            return EXIT_SUCCESS;

        } else if (strcmp(generate_value, "secret") == 0) {
            printf ("%s\n", generate_secret (length));
            return EXIT_SUCCESS;
        }

    } else if (
        verify_flag &&
        code_value != NULL && code_value != 0 &&
        secret_value != NULL && secret_value != 0
    ) {
        if (verify_code (code_value, secret_value, time_period)) {
            printf ("Code %s is valid.\n", code_value);
            return EXIT_SUCCESS;
        } else {
            fprintf (stderr, "Code %s is not valid.\n", code_value);
            return EXIT_FAILURE;
        }
    }

    print_usage (argv[0]);

    return EXIT_FAILURE;
}