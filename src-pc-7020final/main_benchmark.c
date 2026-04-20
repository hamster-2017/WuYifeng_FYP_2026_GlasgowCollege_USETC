#include <stdio.h>
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"

#include "ike_protocol.h"
#include "sa_manager.h"
#include "network.h"
#include "crypto_hw.h"
#include "platform.h"
#include "xtime_l.h"          // XTime_GetTime, COUNTS_PER_SECOND
#include "mbedtls/aes.h"      // mbedtls_aes_context
#include "mbedtls/md.h"       // mbedtls_md_hmac
/* NOTE: 重复次数，多次取平均以减少测量噪声 */
#define BENCH_REPEAT  100
static double ticks_to_us(XTime ticks) {
    return (double)ticks * 1000000.0 / (double)COUNTS_PER_SECOND;
}
void run_benchmark(void)
{
    XTime tStart, tEnd;
    double hw_us, sw_us;
    int i;
    xil_printf("\r\n========================================\r\n");
    xil_printf("  Hardware vs Software Benchmark Start\r\n");
    xil_printf("========================================\r\n");
    /* ---- 测试数据（NIST 标准向量） ---- */
    uint8_t aes_key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    uint8_t aes_iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    uint8_t plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    uint8_t ciphertext[16];
    uint8_t iv_copy[16];
    /* ============================================================
     * 测试 1: AES-128-CBC 单块加密
     * ============================================================ */
    /* ---- 1a: 硬件 AES 加密 ---- */
    /* 预热一次，确保密钥已加载 */
    aes_load_key(aes_key);
    memcpy(iv_copy, aes_iv, 16);
    aes_load_iv(iv_copy);
    aes_encrypt_block(plaintext, ciphertext);
    aes_load_key(aes_key);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {

        memcpy(iv_copy, aes_iv, 16);
        aes_load_iv(iv_copy);
        aes_encrypt_block(plaintext, ciphertext);
    }
    XTime_GetTime(&tEnd);
    hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;

    /* 用 printf 打印浮点数，xil_printf 不支持 %f */
    printf("[AES-ENC-HW]  Single block: %.3f us  (avg of %d runs)\r\n",
           hw_us, BENCH_REPEAT);
    /* ---- 1b: 软件 mbedTLS AES 加密 ---- */
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);
    /* 预热 */
    memcpy(iv_copy, aes_iv, 16);
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                           16, iv_copy, plaintext, ciphertext);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        memcpy(iv_copy, aes_iv, 16);
        mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                               16, iv_copy, plaintext, ciphertext);
    }
    float hw_us_reg = hw_us;
    XTime_GetTime(&tEnd);
    sw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[AES-ENC-SW]  Single block: %.3f us  (avg of %d runs)\r\n",
           sw_us, BENCH_REPEAT);
    printf("[AES-ENC]     Speedup: %.1fx\r\n\r\n", sw_us / hw_us);
    mbedtls_aes_free(&aes_ctx);
    xil_printf("\r\n--- AXI Overhead Breakdown ---\r\n");
    aes_load_key(aes_key);
    aes_load_iv(aes_iv);
    for (int j = 0; j < 4; j++) {
        uint32_t val = ((uint32_t)plaintext[j*4] << 24) |
                       ((uint32_t)plaintext[j*4+1] << 16) |
                       ((uint32_t)plaintext[j*4+2] << 8) |
                       ((uint32_t)plaintext[j*4+3]);
        HW_WRITE32(AES_BASE_ADDR, AES_DIN0_OFFSET + j * 4, val);
    }
    // 只测 "发 START → DONE 置位" 这段纯 PL 计算时间
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        HW_WRITE32(AES_BASE_ADDR, AES_CTRL_OFFSET, AES_CTRL_START);
        while (!(HW_READ32(AES_BASE_ADDR, AES_STATUS_OFFSET) & AES_STATUS_DONE));
    }
    XTime_GetTime(&tEnd);
    hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[PL-ONLY]  AES compute (START to DONE): %.3f us\r\n", hw_us);
    printf("[TOTAL]    AES single block end-to-end:  %.3f us\r\n", hw_us_reg); // 用前面测的
    printf("[AXI-IO]   Register R/W overhead:        %.3f us (%.0f%%)\r\n",
    		hw_us_reg - hw_us, (hw_us_reg - hw_us) / hw_us_reg * 100);
    /* ============================================================
     * 测试 2: AES-128-CBC 多块加密 (16 块 = 256 字节)
     * ============================================================ */
    uint8_t multi_plain[256];
    uint8_t multi_cipher[256];
    for (i = 0; i < 256; i++) multi_plain[i] = (uint8_t)(i & 0xFF);
    /* ---- 2a: 硬件多块 ---- */
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        hw_aes128_cbc_encrypt(aes_key, aes_iv, multi_plain, 256, multi_cipher);
    }
    XTime_GetTime(&tEnd);
    hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[AES-multiple blocks-HW] 16 blocks: %.3f us  (avg of %d runs)\r\n",
           hw_us, BENCH_REPEAT);
    /* ---- 2b: 软件多块 ---- */
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        memcpy(iv_copy, aes_iv, 16);
        mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                               256, iv_copy, multi_plain, multi_cipher);
    }
    XTime_GetTime(&tEnd);
    sw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[AES-256B-SW] 16 blocks: %.3f us  (avg of %d runs)\r\n",
           sw_us, BENCH_REPEAT);
    printf("[AES-256B]    Speedup: %.1fx\r\n\r\n", sw_us / hw_us);
    mbedtls_aes_free(&aes_ctx);
    /* ============================================================
     * 测试 3: HMAC-SHA1 短消息
     * ============================================================ */
    uint8_t hmac_key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b
    };
    uint8_t hmac_msg[8] = "Hi There";
    uint8_t hmac_out[20];
    /* ---- 3a: 硬件 HMAC ---- */
    /* 预热 */
    hmac_sha1_compute(hmac_key, 20, hmac_msg, 8, hmac_out);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        hmac_sha1_compute(hmac_key, 20, hmac_msg, 8, hmac_out);
    }
    XTime_GetTime(&tEnd);
    hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[HMAC-HW]     Short msg: %.3f us  (avg of %d runs)\r\n",
           hw_us, BENCH_REPEAT);
    /* ---- 3b: 软件 HMAC (mbedTLS) ---- */
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    /* 预热 */
    mbedtls_md_hmac(md_info, hmac_key, 20, hmac_msg, 8, hmac_out);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        mbedtls_md_hmac(md_info, hmac_key, 20, hmac_msg, 8, hmac_out);
    }
    XTime_GetTime(&tEnd);
    sw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[HMAC-SW]     Short msg: %.3f us  (avg of %d runs)\r\n",
           sw_us, BENCH_REPEAT);
    printf("[HMAC]        Speedup: %.1fx\r\n\r\n", sw_us / hw_us);
    /* ============================================================
     * 测试 4: AES 解密对比
     * ============================================================ */
    /* 先加密得到密文 */
    hw_aes128_cbc_encrypt(aes_key, aes_iv, plaintext, 16, ciphertext);
    uint8_t dec_out[16];
    /* ---- 4a: 硬件解密 ---- */
    aes_load_key(aes_key);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {

        memcpy(iv_copy, aes_iv, 16);
        aes_load_iv(iv_copy);
        aes_decrypt_block(ciphertext, dec_out);
    }
    XTime_GetTime(&tEnd);
    hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[AES-DEC-HW]  Single block: %.3f us  (avg of %d runs)\r\n",
           hw_us, BENCH_REPEAT);
    /* ---- 4b: 软件解密 ---- */
    mbedtls_aes_init(&aes_ctx);
    mbedtls_aes_setkey_dec(&aes_ctx, aes_key, 128);
    XTime_GetTime(&tStart);
    for (i = 0; i < BENCH_REPEAT; i++) {
        memcpy(iv_copy, aes_iv, 16);
        mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT,
                               16, iv_copy, ciphertext, dec_out);
    }
    XTime_GetTime(&tEnd);
    sw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
    printf("[AES-DEC-SW]  Single block: %.3f us  (avg of %d runs)\r\n",
           sw_us, BENCH_REPEAT);
    printf("[AES-DEC]     Speedup: %.1fx\r\n\r\n", sw_us / hw_us);
    mbedtls_aes_free(&aes_ctx);
    xil_printf("\r\n--- Throughput Scaling Test ---\r\n");
    uint8_t big_plain[1024]; // 最大 1024B = 64 blocks
    uint8_t big_cipher[1024];
    for (i = 0; i < 1024; i++) big_plain[i] = (uint8_t)(i & 0xFF);
    int test_sizes[] = {16, 64, 256, 512, 1024}; // 字节数
    int num_tests = 5;
    for (int t = 0; t < num_tests; t++) {
        int data_len = test_sizes[t];
        int blocks = data_len / 16;
        /* 硬件 */
        XTime_GetTime(&tStart);
        for (i = 0; i < BENCH_REPEAT; i++) {
            hw_aes128_cbc_encrypt(aes_key, aes_iv, big_plain, data_len, big_cipher);
        }
        XTime_GetTime(&tEnd);
        hw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
        /* 软件 */
        mbedtls_aes_init(&aes_ctx);
        mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 128);
        XTime_GetTime(&tStart);
        for (i = 0; i < BENCH_REPEAT; i++) {
            memcpy(iv_copy, aes_iv, 16);
            mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT,
                                   data_len, iv_copy, big_plain, big_cipher);
        }
        XTime_GetTime(&tEnd);
        sw_us = ticks_to_us(tEnd - tStart) / BENCH_REPEAT;
        mbedtls_aes_free(&aes_ctx);
        /* 计算吞吐量 (Mbps) */
        double hw_mbps = (double)(data_len * 8) / hw_us;  // Mbit/s
        double sw_mbps = (double)(data_len * 8) / sw_us;
        printf("[%4dB/%2d blk] HW: %.1f us (%.1f Mbps) | SW: %.1f us (%.1f Mbps) | Speedup: %.2fx\r\n",
               data_len, blocks, hw_us, hw_mbps, sw_us, sw_mbps, sw_us / hw_us);
    }
    xil_printf("========================================\r\n");
    xil_printf("  Benchmark Complete\r\n");
    xil_printf("========================================\r\n\r\n");

}
// 声明一个全局 IKE 状态机上下文，以便 network 中的 UDP 接收回调能够调用
ike_context_t g_ike_ctx;

int main() {
    // 启用 Cache (提高跑 bignum 软算法和 lwIP 栈的性能)
    Xil_ICacheEnable();
    Xil_DCacheEnable();
    run_benchmark();
    xil_printf("\r\n======================================\r\n");
    xil_printf("  IKE Crypto System - ZYNQ PS Backend \r\n");
    xil_printf("======================================\r\n");

    // 1. 初始化 SA 管理器
    sa_manager_init();
    xil_printf("[INFO] SA Manager initialized.\r\n");

    //初始化硬件定时器和中断(LWIP必选)
    init_platform();

    // 2. 初始化网络协议栈 (lwIP & GEM MAC)
    xil_printf("[INFO] Initializing Network stack (lwIP)...\r\n");
    network_init(); 
    platform_enable_interrupts(); // 在配置好网络和回调后打开全局中断
    xil_printf("[INFO] Network stack initialized.\r\n");

    // 3. 初始化 IKE 引擎 (默认设为 Responder 接收模式等待 PC 发起连接)
    uint8_t psk[] = "mysecretkey";
    
    // Local IP: 10.0.0.10, Peer IP预留: 10.0.0.100 (0x0A000064)
    ike_init(&g_ike_ctx, IKE_ROLE_RESPONDER, psk, sizeof(psk)-1, 0x0A00000A, 0);
    xil_printf("[INFO] IKE Engine initialized (Role: Responder).\r\n");

    // 4. 等待网络封包并且进行轮询
    xil_printf("[INFO] Waiting for incoming IKE packets on UDP 500...\r\n");
    
    while(1) {
        // 轮询 lwIP 堆栈，处理网络收发
        network_poll();
        
        // 此处可以加入其它应用层的测速或模拟发包逻辑
        // ...
    }

    Xil_DCacheDisable();
    Xil_ICacheDisable();
    return 0;
}
