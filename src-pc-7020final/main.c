




#include <stdio.h>
#include "xil_printf.h"
#include "xil_cache.h"
#include "xparameters.h"

#include "ike_protocol.h"
#include "sa_manager.h"
#include "network.h"
#include "crypto_hw.h"
#include "platform.h"


ike_context_t g_ike_ctx;

int main() {
    Xil_ICacheEnable();
    Xil_DCacheEnable();

    xil_printf("\r\n======================================\r\n");
    xil_printf("  IKE Crypto System - ZYNQ PS Backend \r\n");
    xil_printf("======================================\r\n");

    sa_manager_init();
    xil_printf("[INFO] SA Manager initialized.\r\n");

    init_platform();

    xil_printf("[INFO] Initializing Network stack (lwIP)...\r\n");
    network_init(); 
    platform_enable_interrupts(); 
    xil_printf("[INFO] Network stack initialized.\r\n");

    uint8_t psk[] = "mysecretkey";
    ike_init(&g_ike_ctx, IKE_ROLE_RESPONDER, psk, sizeof(psk)-1, 0x0A00000A, 0);
    xil_printf("[INFO] IKE Engine initialized (Role: Responder).\r\n");

    xil_printf("[INFO] Waiting for incoming IKE packets on UDP 500...\r\n");
    while(1) {
        network_poll();
    }

    Xil_DCacheDisable();
    Xil_ICacheDisable();
    return 0;
}
