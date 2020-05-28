#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtp.h"

extern void rtsp_send_for_rtp(struct rtp_packet* pkt, void* _user);

void rtp_list_init(struct list_t* list)
{
    list->prev = list;
    list->next = list;
}

void rtp_list_add(struct list_t* list, struct list_t* elm)
{
    elm->prev = list;
    elm->next = list->next;
    list->next = elm;
    elm->next->prev = elm;
}

void rtp_list_del(struct list_t* elm)
{
    elm->prev->next = elm->next;
    elm->next->prev = elm->prev;
    elm->next = NULL;
    elm->prev = NULL;
}

void init_packet_pool(struct rtp_info* info)
{
    info->pool.buf = malloc(4096);
    info->pool.len = 4096;
    info->pool.pos = 0;
}

void reset_packet_pool(struct rtp_info* info)
{
    info->pool.pos = 0;
}

struct rtp_packet* get_packet_from_pool(struct rtp_info* info)
{
    char* ptr;
    struct rtp_packet* pkt;

    ptr = info->pool.buf + info->pool.pos;
    //info->pool.pos += sizeof(struct rtp_packet);
    memset(ptr, 0, sizeof(struct rtp_packet));
    pkt = (struct rtp_packet*)ptr;

    return pkt;
}

int generate_rtp_header(char* dst, int payload_len, int is_last, unsigned short seq_num, unsigned long long pts,
    unsigned long ssrc, enum rtp_transport transport, int playload_code)
{
    int index = 0;

    if (transport == RTP_TRANSPORT_TCP) {
        /* RTSP interleaved frame header */
        dst[index++] = 0x24;
        dst[index++] = 0x00;
        dst[index++] = ((payload_len + 12) >> 8) & 0xff;
        dst[index++] = (payload_len + 12) & 0xff;
    }

    /* RTP header */
    dst[index++] = 0x80;
    dst[index++] = (is_last ? 0x80 : 0x00) | playload_code;
    dst[index++] = (seq_num >> 8) & 0xff;
    dst[index++] = seq_num & 0xff;
    dst[index++] = (pts >> 24) & 0xff;
    dst[index++] = (pts >> 16) & 0xff;
    dst[index++] = (pts >> 8) & 0xff;
    dst[index++] = pts & 0xff;
    dst[index++] = (ssrc >> 24) & 0xff;
    dst[index++] = (ssrc >> 16) & 0xff;
    dst[index++] = (ssrc >> 8) & 0xff;
    dst[index++] = ssrc & 0xff;

    return index;
}

void generate_rtp_packets_and_send(struct rtp_info* rtp_info, struct list_t* pkt_list, void* data, int size,
    unsigned long long pts, void* _user)
{
    char* nal;
    int nal_len;
    int is_key = 0;
    struct rtp_packet* pkt;
    int tcp_header_offset, tcp_max_len;
    int udp_header_offset, udp_max_len;

    if (pkt_list->next != pkt_list)
        return;

    //if (server->rtp_info.transport == RTP_TRANSPORT_TCP) {
    tcp_header_offset = 16;
    tcp_max_len = TCP_MSS;
    //} else
    //{
    udp_header_offset = 12;
    udp_max_len = RTP_PACKET_MAX_SIZE;
    //}

    nal = data + 4;
    nal_len = size - 4;

    if (rtp_info->sdp.video_type == RTSP_STREAM_TYPE_H264) {
        if (((nal[0] & 0x1f) == 5)
            || ((nal[0] & 0x1f) == 7)
            || ((nal[0] & 0x1f) == 8)) /* I frame */
        {
            is_key = 1;
        }
    } else {
        int nalu_type = (nal[0] >> 1) & 0x3f;
        if (nalu_type == 2
            || nalu_type == 19
            || nalu_type == 32
            || nalu_type == 33
            || nalu_type == 34) /* I frame */
        {
            is_key = 1;
        }
    }

    if (nal_len > tcp_max_len - tcp_header_offset) { // only for rtp over tcp
        int fragment_len = 0;
        if (rtp_info->sdp.video_type == RTSP_STREAM_TYPE_H264) {
            fragment_len = tcp_max_len - tcp_header_offset - 2;
        } else {
            fragment_len = tcp_max_len - tcp_header_offset - 3;
        }

        int pkt_num, i;
        int fu_len = fragment_len;
        char* fu_buf;

        if ((nal_len - 1) % fragment_len == 0) {
            pkt_num = (nal_len - 1) / fragment_len;
        } else {
            pkt_num = (nal_len - 1) / fragment_len + 1;
        }

        for (i = 0; i < pkt_num; i++) {
            pkt = get_packet_from_pool(rtp_info);
            if (i == pkt_num - 1)
                fu_len = nal_len - 1 - i * fragment_len;
            rtp_info->sequence_num++;

            pkt->is_key = is_key;

            if (rtp_info->sdp.video_type == RTSP_STREAM_TYPE_H264) {
                pkt->tcp_header_len = generate_rtp_header(pkt->tcp_buf, fu_len + 2, i == pkt_num - 1, rtp_info->sequence_num,
                    pts, rtp_info->ssrc, RTP_TRANSPORT_TCP, 96);
                fu_buf = pkt->tcp_buf + tcp_header_offset;
                fu_buf[0] = (nal[0] & 0x60) | 0x1C;
                fu_buf[1] = (i == 0 ? 0x80 : 0x00) | ((i == pkt_num - 1) ? 0x40 : 0x00) | (nal[0] & 0x1f);
                memcpy(fu_buf + 2, nal + 1 + i * fragment_len, fu_len);
                pkt->tcp_rtp_len = tcp_header_offset + 2 + fu_len;
            } else {
                pkt->tcp_header_len = generate_rtp_header(pkt->tcp_buf, fu_len + 3, i == pkt_num - 1, rtp_info->sequence_num,
                    pts, rtp_info->ssrc, RTP_TRANSPORT_TCP, 97);
                fu_buf = pkt->tcp_buf + tcp_header_offset;
                fu_buf[0] = 49 << 1;
                fu_buf[1] = 1;
                fu_buf[2] = (i == 0 ? 0x80 : 0x00) | ((i == pkt_num - 1) ? 0x40 : 0x00) | ((nal[0] >> 1) & 0x3F);
                memcpy(fu_buf + 3, nal + 2 + i * fragment_len, fu_len);
                pkt->tcp_rtp_len = tcp_header_offset + 3 + fu_len;
            }

            pkt->udp_header_len = pkt->tcp_header_len - 4;
            pkt->udp_rtp_len = pkt->tcp_rtp_len - 4;
            pkt->udp_buf = pkt->tcp_buf + 4;

            rtp_list_add(pkt_list->prev, &pkt->link);
            rtsp_send_for_rtp(pkt, _user);
            is_key = 0;
        }
    } else {
        rtp_info->sequence_num++;
        pkt = get_packet_from_pool(rtp_info);
        if (rtp_info->sdp.video_type == RTSP_STREAM_TYPE_H264) {
            pkt->tcp_header_len = generate_rtp_header(pkt->tcp_buf, nal_len, 0, rtp_info->sequence_num, pts,
                rtp_info->ssrc, RTP_TRANSPORT_TCP, 96);
            memcpy(pkt->tcp_buf + tcp_header_offset, nal, nal_len);
            pkt->tcp_rtp_len = tcp_header_offset + nal_len;
        } else {
            pkt->tcp_header_len = generate_rtp_header(pkt->tcp_buf, nal_len, ((nal[0] >> 1) & 0x3f) < 32 ? 1 : 0, rtp_info->sequence_num, pts,
                rtp_info->ssrc, RTP_TRANSPORT_TCP, 97);
            memcpy(pkt->tcp_buf + tcp_header_offset, nal, nal_len);
            pkt->tcp_rtp_len = tcp_header_offset + nal_len;
        }

        pkt->udp_header_len = pkt->tcp_header_len - 4;
        pkt->udp_rtp_len = pkt->tcp_rtp_len - 4;
        pkt->udp_buf = pkt->tcp_buf + 4;

        rtp_list_add(pkt_list->prev, &pkt->link);
        rtsp_send_for_rtp(pkt, _user);
    }
}