




#include "network.h"
#include "ike_protocol.h"


#include "lwip/init.h"
#include "lwip/err.h"
#include "lwip/udp.h"
#include "lwip/ip_addr.h"
#include "xparameters.h"
#include "netif/xadapter.h"
#include "xil_printf.h"






#include "xemacps.h"
#include "netif/xemacpsif.h"

#define IKE_UDP_PORT 500


#define YT_PHY_ADDR          7      
#define YT_EXT_REG_ADDR      0x1E   
#define YT_EXT_REG_DATA      0x1F   
#define YT_RGMII_CONFIG1     0xA003 




static struct netif server_netif;
struct netif *echo_netif = &server_netif; 


static struct udp_pcb *ike_pcb;


extern ike_context_t g_ike_ctx;




static void udp_recv_callback(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                              const ip_addr_t *addr, u16_t port)
{
    if (p != NULL) {
        uint8_t *rx_data = (uint8_t *)p->payload;
        uint16_t rx_len = p->len;
        xil_printf("[NET] Rx UDP packet from %s:%d, len=%d\r\n",
                   ipaddr_ntoa(addr), port, rx_len);
        static uint8_t tx_buf[1024];
        uint16_t tx_len = 0;
        int ret = ike_process_message(&g_ike_ctx, rx_data, rx_len, tx_buf, &tx_len);
        if (ret == 0 && tx_len > 0) {
            struct pbuf *p_tx = pbuf_alloc(PBUF_TRANSPORT, tx_len, PBUF_REF);
            if (p_tx != NULL) {
                p_tx->payload = tx_buf;
                err_t err = udp_sendto(pcb, p_tx, addr, port);
                if (err != ERR_OK) {
                    xil_printf("[NET] UDP send error: %d\r\n", err);
                } else {
                    xil_printf("[NET] Tx UDP response, len=%d\r\n", tx_len);
                }
                pbuf_free(p_tx);
            }
        }
        pbuf_free(p);
    }
}








static void configure_yt8521s_phy(uintptr_t baseaddr)
{
    u16 reg_val;
    XEmacPs *xemac_ptr = &((xemacpsif_s *)(server_netif.state))->emacps;

    xil_printf("[NET] Configuring YT8521S PHY at address %d...\r\n", YT_PHY_ADDR);







    XEmacPs_PhyWrite(xemac_ptr, YT_PHY_ADDR, YT_EXT_REG_ADDR, YT_RGMII_CONFIG1);

    XEmacPs_PhyRead(xemac_ptr, YT_PHY_ADDR, YT_EXT_REG_DATA, &reg_val);
    reg_val &= ~(0x000F); 
    reg_val |= 0x0103;    
    XEmacPs_PhyWrite(xemac_ptr, YT_PHY_ADDR, YT_EXT_REG_DATA, reg_val);

    xil_printf("[NET] YT8521S PHY RGMII delay enabled (Reg 0xA003 = 0x%04X).\r\n", reg_val);
}

void network_init(const char *ip_addr_str, const uint8_t mac_addr[6])
{
    ip_addr_t ipaddr, netmask, gw;

    if (!ipaddr_aton(ip_addr_str, &ipaddr)) {
        xil_printf("[NET] Error: Invalid IP address string: %s\r\n", ip_addr_str);
        IP4_ADDR(&ipaddr,  192, 168, 1, 10);
    }
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw,      192, 168, 1, 1);

    lwip_init();

    if (!xemac_add(&server_netif, &ipaddr, &netmask, &gw,
                   (uint8_t *)mac_addr, XPAR_XEMACPS_0_BASEADDR)) {
        xil_printf("[NET] Error adding network interface\n\r");
        return;
    }

    configure_yt8521s_phy(XPAR_XEMACPS_0_BASEADDR);

    netif_set_default(&server_netif);
    netif_set_up(&server_netif);
    xil_printf("[NET] IPv4 Address: %s\r\n", ipaddr_ntoa(&server_netif.ip_addr));

    ike_pcb = udp_new();
    if (ike_pcb != NULL) {
        err_t err = udp_bind(ike_pcb, IP_ADDR_ANY, IKE_UDP_PORT);
        if (err == ERR_OK) {
            udp_recv(ike_pcb, udp_recv_callback, NULL);
            xil_printf("[NET] Listening on UDP port %d (IKE)\r\n", IKE_UDP_PORT);
        } else {
            xil_printf("[NET] UDP bind failed: %d\r\n", err);
        }
    }
}

void udp_send_data(const uint8_t *data, uint16_t len)
{
    network_send_udp(g_ike_ctx.peer_ip, IKE_UDP_PORT, data, len);
}

int network_send_udp(uint32_t dest_ip, uint16_t dest_port, const uint8_t *data, uint16_t len)
{
    if (ike_pcb == NULL) return -1;
    ip_addr_t ip;
    ip.addr = dest_ip; 
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM);
    if (p == NULL) return -1;
    memcpy(p->payload, data, len);
    err_t err = udp_sendto(ike_pcb, p, &ip, dest_port);
    pbuf_free(p);
    return (err == ERR_OK) ? 0 : -1;
}

void network_poll(void)
{
    xemacif_input(&server_netif);
}
