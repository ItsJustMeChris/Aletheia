#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PAYLOAD_SIZE 512

#define DEFINE_STAGE(ID, CONST_A, CONST_B)                                                         \
    __attribute__((noinline)) static void stage_##ID(char *buffer, size_t len, uint32_t *checksum) \
    {                                                                                              \
        uint32_t acc = *checksum ^ CONST_A;                                                        \
        for (size_t i = 0; i < len; ++i) {                                                         \
            uint8_t byte = (uint8_t)buffer[i];                                                     \
            byte = (uint8_t)((byte + (uint8_t)CONST_B + (uint8_t)i) ^ (uint8_t)(acc >> 5));        \
            byte = (uint8_t)((byte << 1) | (byte >> 7));                                           \
            acc = (acc * 1664525u) + 1013904223u + (uint32_t)byte + CONST_B;                       \
            buffer[i] = (char)(byte & 0x7F);                                                       \
        }                                                                                          \
        acc ^= CONST_B ^ (uint32_t)len;                                                            \
        *checksum = acc;                                                                           \
        printf("Stage %2d complete | checksum=0x%08x | preview=\"%.8s\"\n", ID, acc, buffer);      \
    }

#if defined(__aarch64__) || defined(__arm64__)
#define NOP_INSN "nop"
#elif defined(__x86_64__)
#define NOP_INSN "nop"
#else
#define NOP_INSN "nop"
#endif

#define DEFINE_FILLER(ID, REPS)                                    \
    __attribute__((noinline)) static void filler_##ID(void)        \
    {                                                              \
        __asm__ volatile(                                          \
            ".rept " #REPS "\n"                                    \
            NOP_INSN "\n"                                          \
            ".endr\n"                                              \
            :::);                                                  \
        printf("Filler block %d executed.\n", ID);                 \
    }

DEFINE_STAGE(1, 0x13579BDFu, 17)
DEFINE_STAGE(2, 0x2468ACE0u, 23)
DEFINE_STAGE(3, 0x10203040u, 5)
DEFINE_STAGE(4, 0x8899AABBu, 41)
DEFINE_STAGE(5, 0x55667788u, 3)
DEFINE_STAGE(6, 0xCAFEBABEu, 29)
DEFINE_STAGE(7, 0x0F1E2D3Cu, 11)
DEFINE_STAGE(8, 0x31415926u, 7)
DEFINE_STAGE(9, 0xDEADBEEFu, 19)
DEFINE_STAGE(10, 0xA5A5A5A5u, 13)

DEFINE_FILLER(1, 4096)
DEFINE_FILLER(2, 6144)
DEFINE_FILLER(3, 8192)
DEFINE_FILLER(4, 12288)

__attribute__((noinline)) static void secret_report(const char *payload, uint32_t checksum)
{
    printf("\n======== FINAL REPORT ========\n");
    printf("Decrypted payload length : %zu bytes\n", strlen(payload));
    printf("Aggregate checksum       : 0x%08x\n", checksum);
    printf("Payload preview          : \"%.32s\"\n", payload);
    printf("This secret routine stayed hidden until runtime!\n");
    printf("================================\n");
}

int main(void)
{
    printf("Parent process started. Preparing payload...\n");

    char payload[PAYLOAD_SIZE];
    memset(payload, 0, sizeof(payload));
    snprintf(payload, sizeof(payload),
             "Top secret message: Only visible with live decryption! [%u]",
             PAYLOAD_SIZE);

    uint32_t checksum = 0x1234ABCDu;

    stage_1(payload, sizeof(payload), &checksum);
    filler_1();
    stage_2(payload, sizeof(payload), &checksum);
    stage_3(payload, sizeof(payload), &checksum);
    filler_2();
    stage_4(payload, sizeof(payload), &checksum);
    stage_5(payload, sizeof(payload), &checksum);
    filler_3();
    stage_6(payload, sizeof(payload), &checksum);
    stage_7(payload, sizeof(payload), &checksum);
    filler_4();
    stage_8(payload, sizeof(payload), &checksum);
    stage_9(payload, sizeof(payload), &checksum);
    stage_10(payload, sizeof(payload), &checksum);

    secret_report(payload, checksum);

    printf("Parent process exiting.\n");
    return (int)checksum;
}
