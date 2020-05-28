#ifndef __RTP_H__
#define __RTP_H__

#include "sdp.h"

/* rtp packet macros */
#ifndef TCP_MSS
#define TCP_MSS 1460
#endif
#define RTP_PACKET_MAX_SIZE 1472

enum rtp_transport {
    RTP_TRANSPORT_UDP,
    RTP_TRANSPORT_TCP
};

struct list_t {
    struct list_t* prev;
    struct list_t* next;
};

struct rtp_packet {
    int is_key;
    char tcp_buf[RTP_PACKET_MAX_SIZE];
    char* udp_buf;
    int tcp_rtp_len;
    int udp_rtp_len;
    int tcp_header_len;
    int udp_header_len;
    struct list_t link;
};

struct pkt_pool {
    char* buf;
    int len;
    int pos;
};

struct rtp_info {
    unsigned short sequence_num;
    unsigned long ssrc;
    unsigned char has_sdp;
    struct sdp_info sdp;
    struct pkt_pool pool;
    int udp_send_socket;
};

void rtp_list_init(struct list_t* list);

void rtp_list_add(struct list_t* list, struct list_t* elm);

void rtp_list_del(struct list_t* elm);

void init_packet_pool(struct rtp_info* info);

void reset_packet_pool(struct rtp_info* info);

void generate_rtp_packets_and_send(struct rtp_info* rtp_info, struct list_t* pkt_list, void* data, int size,
    unsigned long long pts, void* _user);

#endif