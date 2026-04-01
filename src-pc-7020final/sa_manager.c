




#include "sa_manager.h"
#include <string.h>

static sa_entry_t sa_table[4];

void sa_manager_init(void) {
    memset(sa_table, 0, sizeof(sa_table));
}

sa_entry_t* sa_alloc(void) {
    for (int i = 0; i < 4; i++) {
        if (sa_table[i].state == IKE_STATE_IDLE) {
            return &sa_table[i];
        }
    }
    return NULL;
}

sa_entry_t* sa_find_by_spi(uint32_t spi) {
    for (int i = 0; i < 4; i++) {
        if (sa_table[i].spi == spi && sa_table[i].state != IKE_STATE_IDLE) {
            return &sa_table[i];
        }
    }
    return NULL;
}

sa_entry_t* sa_find_by_ip(uint32_t ip) {
    for (int i = 0; i < 4; i++) {
        if (sa_table[i].peer_ip == ip && sa_table[i].state != IKE_STATE_IDLE) {
            return &sa_table[i];
        }
    }
    return NULL;
}
