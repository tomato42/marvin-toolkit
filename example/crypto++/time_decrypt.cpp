#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/pssr.h>
#include <cryptopp/osrng.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

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

int main() {
    // Load the private key from a file
    RSA::PrivateKey privateKey;
    ByteQueue q;
    FileSource file("rsa2048/pkcs8.key", true);
    file.TransferTo(q);

    try {
        privateKey.BERDecodePrivateKey(q, false, 0);
    } catch (const Exception &ex) {
        std::cerr << "Failed to load private key: " << ex.what() << std::endl;
        return 1;
    }

    // Load the ciphertext to decrypt
    std::ifstream cipherFile("rsa2048_repeat/ciphers.bin",
                             std::ios::in | std::ios::binary);
    if (!cipherFile) {
        std::cerr << "Failed to open the ciphertext file." << std::endl;
        return 1;
    }

    std::ofstream timesFile("rsa2048_repeat/raw_times.bin",
                            std::ios::out | std::ios::binary);
    if (!timesFile) {
        std::cerr << "Failed to open the raw_times.bin file." << std::endl;
        return 1;
    }

    while (! cipherFile.eof()) {
        char buffer[256];

        cipherFile.read(buffer, 256);

        std::string ciphertext(buffer, 256);

        // Decrypt the ciphertext using the loaded private key
        std::string decryptedText;
        uint64_t start_time = get_time_before();
        try {
            CryptoPP::AutoSeededRandomPool rng;
            RSAES_PKCS1v15_Decryptor decryptor(privateKey);
            StringSource(ciphertext, true,
                         new PK_DecryptorFilter(rng, decryptor,
                                                new StringSink(decryptedText)));
        } catch (const Exception &ex) {
            ;;
        }
        uint64_t elapsed = get_time_after() - start_time;

        timesFile.write((char*)&elapsed, 8);

    }
    return 0;
}

