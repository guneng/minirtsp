#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <pthread.h>
#include <sys/time.h>

#include <netdb.h>
#include <sys/socket.h>

#include "rtsp.h"

#include "rtp.h"
#include "sdp.h"

/* rtsp macros */
#ifdef RT_LWIP_TCP_PCB_NUM
#define MAX_CLIENT_COUNT RT_LWIP_TCP_PCB_NUM
#else
#define MAX_CLIENT_COUNT 10
#endif
#define REQUEST_READ_BUF_SIZE 1024
#define RESPONSE_BUF_SIZE 4096
#define RTP_UDP_SEND_PORT 3056
#define RTSP_THREAD_PRIORITY (RT_THREAD_PRIORITY_MAX >> 1)
#define RTSP_THREAD_STACK_SIZE 1024
#define RTSP_THREAD_TIMESLICE 10

#define rtp_list_container_of(ptr, sample, member) \
    (__typeof__(sample))((char*)(ptr)-offsetof(__typeof__(*sample), member))

#define rtp_list_for_each(pos, head, member)                                             \
    for (pos = rtp_list_container_of((head)->next, pos, member); &pos->member != (head); \
         pos = rtp_list_container_of(pos->member.next, pos, member))

#define rtp_list_for_each_safe(pos, tmp, head, member)                \
    for (pos = rtp_list_container_of((head)->next, pos, member),      \
        tmp = rtp_list_container_of((pos)->member.next, tmp, member); \
         &pos->member != (head); pos = tmp, tmp = rtp_list_container_of(pos->member.next, tmp, member))

enum {
    RTSP_MSG_NULL,
    RTSP_MSG_OPTIONS,
    RTSP_MSG_DESCRIBE,
    RTSP_MSG_SETUP,
    RTSP_MSG_PLAY,
    RTSP_MSG_TEARDOWN
};

struct client_context {
    struct rtsp_server_context* server;
    enum rtp_transport transport;
    int fd;
    struct sockaddr_in addr;
    int udp_send_port;
    int start_play;
    int find_i_frame;
    void* session;
    int (*process_func)(struct client_context* ctx);
    pthread_t thread_id;
    struct list_t link;
};

struct rtsp_server_context {
    int stop;
    int sd;
    pthread_t thread_id;
    int port;
    enum RTSP_STREAM_TYPE video_stream_type;
    void (*init_client)(struct client_context* ctx);
    void (*release_client)(struct client_context* ctx);
    struct rtp_info rtp_info;
    pthread_mutex_t client_list_lock;
    struct list_t client_list;
};

struct rtsp_session {
    struct client_context* ctx;
    char read_buf[REQUEST_READ_BUF_SIZE];
    char response_buf[RESPONSE_BUF_SIZE];
    char cseq[10];
    unsigned long session_num;
};

int _send(int fd, void* buf, int len)
{
    struct timeval tv;
    fd_set fds;
    int ret;
    int count = 10;
    do {
        tv.tv_sec = 0;
        tv.tv_usec = 1000;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        ret = select(fd + 1, NULL, &fds, NULL, &tv);
        if (ret > 0) {
            if (FD_ISSET(fd, &fds)) {
                send(fd, buf, len, 0);
                count = 0;
            }
        } else if (ret == 0) {
            count--;
            continue;
        } else {
            return -1;
        }
    } while (count > 0);

    return 0;
}

void send_stream(struct client_context* client, struct rtp_packet* pkt)
{
    if (client->transport == RTP_TRANSPORT_UDP) {
        client->addr.sin_port = htons(client->udp_send_port);
        sendto(client->server->rtp_info.udp_send_socket, pkt->udp_buf, pkt->udp_rtp_len, 0, (struct sockaddr*)&client->addr,
            sizeof(struct sockaddr_in));
    } else {
        _send(client->fd, pkt->tcp_buf, pkt->tcp_rtp_len);
    }
}

void send_to_clients(struct rtsp_server_context* server, struct rtp_packet* pkt)
{
    struct client_context *client, *next;
    char* p = pkt->tcp_buf + pkt->tcp_header_len;

    pthread_mutex_lock(&server->client_list_lock);
    rtp_list_for_each_safe(client, next, &server->client_list, link)
    {
        if (client) {
            if (client->start_play) {
                if (server->port != 0 && client->find_i_frame == 0) { /* using RTSP */
                    if (pkt->is_key) {
                        client->find_i_frame = 1;
                    }
                }
                if (client->find_i_frame) {
                    send_stream(client, pkt);
                }
            }
        }
    }
    pthread_mutex_unlock(&server->client_list_lock);
}

void rtsp_send_for_rtp(struct rtp_packet* pkt, void* _user)
{
    struct rtsp_server_context* server = _user;
    send_to_clients(server, pkt);
}

void* client_thread_proc(void* arg)
{
    struct client_context* client_ctx = (struct client_context*)arg;

    while (client_ctx->server->stop == 0) {
        if (client_ctx->process_func) {
            if (client_ctx->process_func(client_ctx) < 0) {
                pthread_mutex_lock(&client_ctx->server->client_list_lock);
                rtp_list_del(&client_ctx->link);
                pthread_mutex_unlock(&client_ctx->server->client_list_lock);
                close(client_ctx->fd);
                if (client_ctx->server->release_client)
                    client_ctx->server->release_client(client_ctx);
                free(client_ctx);
                break;
            }
        }
    }
}

void* rtp_tcp_server_thread(void* arg)
{
    struct rtsp_server_context* server_ctx = (struct rtsp_server_context*)arg;
    struct sockaddr_in addr;
    int on;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    struct client_context* client_ctx;
    int fd;
    int ret = 0;
    pthread_mutex_init(&server_ctx->client_list_lock, NULL);

    server_ctx->sd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_ctx->sd < 0) {
        debug("create server socket failed\n");
        return NULL;
    }

    /* ignore "socket already in use" errors */
    on = 1;
    setsockopt(server_ctx->sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    fcntl(server_ctx->sd, F_SETFL, O_NONBLOCK);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(server_ctx->port);
    addr.sin_addr.s_addr = INADDR_ANY;
    memset(&(addr.sin_zero), 8, sizeof(addr.sin_zero));

    if (bind(server_ctx->sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        debug("Unable to bind\n");
        return NULL;
    }

    if (listen(server_ctx->sd, MAX_CLIENT_COUNT) != 0) {
        debug("Listen error\n");
        return NULL;
    }

    while (!server_ctx->stop) {
        bzero(&addr, sizeof(addr));
        fd = accept(server_ctx->sd, (struct sockaddr*)&addr, &addr_len);
        if (fd != -1) {
            client_ctx = malloc(sizeof(struct client_context));
            if (client_ctx == NULL) {
                debug("failed to allocate (a very small amount of) memory\n");
                close(fd);
                continue;
            }
            memcpy(&client_ctx->addr, &addr, sizeof(addr));
            client_ctx->server = server_ctx;
            client_ctx->fd = fd;
            client_ctx->start_play = 0;
            client_ctx->find_i_frame = 0;
            if (server_ctx->init_client)
                server_ctx->init_client(client_ctx);
            rtp_list_add(server_ctx->client_list.prev, &client_ctx->link);
            ret = pthread_create(&client_ctx->thread_id, NULL, client_thread_proc, client_ctx);
            if (ret < 0) {
                free(client_ctx);
            }
        }
    }
    close(server_ctx->sd);
}

static void _generate_h264_sdp(struct rtsp_server_context* server, unsigned char* data, int size)
{
    if (!server->rtp_info.sdp.has_sps
        || !server->rtp_info.sdp.has_pps) {
        if (7 == (data[4] & 0x1f)) {
            memcpy(server->rtp_info.sdp.sps, data + 4, size);
            server->rtp_info.sdp.sps_len = size - 4;
            server->rtp_info.sdp.has_sps = 1;
        } else if (8 == (data[4] & 0x1f)) {
            memcpy(server->rtp_info.sdp.pps, data + 4, size);
            server->rtp_info.sdp.pps_len = size - 4;
            server->rtp_info.sdp.has_pps = 1;
        }

        if (server->rtp_info.sdp.has_sps
            && server->rtp_info.sdp.has_pps) {
            server->rtp_info.has_sdp = 1;
            generate_sdp(&server->rtp_info.sdp);
        }
    }
}

static void _generate_h265_sdp(struct rtsp_server_context* server, unsigned char* data, int size)
{
    if (!server->rtp_info.sdp.has_sps
        || !server->rtp_info.sdp.has_pps
        || !server->rtp_info.sdp.has_vps) {
        if (33 == ((data[4] >> 1) & 0x3f)) {
            memcpy(server->rtp_info.sdp.sps, data + 4, size);
            server->rtp_info.sdp.sps_len = size - 4;
            server->rtp_info.sdp.has_sps = 1;
        } else if (34 == ((data[4] >> 1) & 0x3f)) {
            memcpy(server->rtp_info.sdp.pps, data + 4, size);
            server->rtp_info.sdp.pps_len = size - 4;
            server->rtp_info.sdp.has_pps = 1;
        } else if (32 == ((data[4] >> 1) & 0x3f)) {
            memcpy(server->rtp_info.sdp.vps, data + 4, size);
            server->rtp_info.sdp.vps_len = size - 4;
            server->rtp_info.sdp.has_vps = 1;
        }

        if (server->rtp_info.sdp.has_sps
            && server->rtp_info.sdp.has_pps
            && server->rtp_info.sdp.has_vps) {
            server->rtp_info.has_sdp = 1;
            generate_sdp(&server->rtp_info.sdp);
        }
    }
}

void rtp_push_data(struct rtsp_server_context* server, void* data, int size, unsigned long long pts)
{
    char* p = (char*)data;
    struct list_t packets;

    if (server == NULL)
        return;
    if (!server->rtp_info.has_sdp) {
        if (server->video_stream_type == RTSP_STREAM_TYPE_H264) {
            _generate_h264_sdp(server, data, size);
        } else if (server->video_stream_type == RTSP_STREAM_TYPE_H265) {
            _generate_h265_sdp(server, data, size);
        }
        server->rtp_info.sdp.video_type = server->video_stream_type;
    } else if (server->client_list.next && server->client_list.next != &server->client_list) {
        rtp_list_init(&packets);
        generate_rtp_packets_and_send(&server->rtp_info, &packets, data, size, pts * 90, server);
        reset_packet_pool(&server->rtp_info);
    }
}

void server_cleanup(struct rtsp_server_context* server)
{
    struct client_context *client, *next;

    if (server == NULL)
        return;

    rtp_list_for_each_safe(client, next, &server->client_list, link)
    {
        if (client) {
            if (client->thread_id > 0)
                pthread_cancel(client->thread_id);
            if (server->release_client)
                server->release_client(client);
            rtp_list_del(&client->link);
            if (client->fd != -1) {
                debug("close client socket %d\n", client->fd);
                close(client->fd);
            }
            free(client);
        }
    }
    if (server->sd != -1) {
        debug("close server socket %d\n", server->sd);
        close(server->sd);
    }
    if (server->rtp_info.udp_send_socket != -1) {
        debug("close udp send socket %d\n", server->rtp_info.udp_send_socket);
        close(server->rtp_info.udp_send_socket);
    }
    free(server->rtp_info.pool.buf);
    pthread_mutex_destroy(&server->client_list_lock);
    free(server);
    server = NULL;
}

/**
 * rtsp requests processing functions
 */
void generate_response_header(struct rtsp_session* session)
{
    char tmp[32];

    session->response_buf[0] = 0;
    strcat(session->response_buf, "RTSP/1.0 200 OK\r\n");
    snprintf(tmp, sizeof(tmp), "CSeq: %s\r\n", session->cseq);
    strcat(session->response_buf, tmp);
}

void send_response(int fd, void* buffer, int size)
{
    printf("%s:[%s]\n", __func__, buffer);

    send(fd, buffer, size, 0);
}

void generate_session_number(struct rtsp_session* session)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);
    session->session_num = tv.tv_sec * 1000L + tv.tv_usec / 1000L;
}

void rtsp_handle_options(struct rtsp_session* session)
{
    generate_response_header(session);
    strcat(session->response_buf, "Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n\r\n");
    send_response(session->ctx->fd, session->response_buf, strlen(session->response_buf));
}

void rtsp_handle_describe(struct rtsp_session* session)
{
    char tmp[32];

    generate_response_header(session);
    strcat(session->response_buf, "Content-Type: application/sdp\r\n");
    snprintf(tmp, sizeof(tmp), "Content-Length: %d\r\n\r\n", strlen(session->ctx->server->rtp_info.sdp.content));
    strcat(session->response_buf, tmp);
    strcat(session->response_buf, session->ctx->server->rtp_info.sdp.content);
    send_response(session->ctx->fd, session->response_buf, strlen(session->response_buf));
}

void rtsp_handle_setup(struct rtsp_session* session)
{
    char tmp[100];
    char* start_p = NULL;
    generate_session_number(session);
    generate_response_header(session);
    snprintf(tmp, sizeof(tmp), "Session: %lu\r\n", session->session_num);
    strcat(session->response_buf, tmp);

    start_p = strstr(session->read_buf, "Transport:");
    if (start_p) {
        if (strstr(start_p, "RTP/AVP/TCP")) {
            strcat(session->response_buf,
                "Transport: RTP/AVP/TCP;unicast;interleaved=0-1;\r\n"
                "\r\n");
            session->ctx->transport = RTP_TRANSPORT_TCP;

        } else {
            if (session->ctx->udp_send_port == 0)
                session->ctx->udp_send_port = RTP_UDP_SEND_PORT;

            snprintf(tmp, 100,
                "Transport: RTP/AVP/UDP;unicast;"
                "client_port=%d-%d\r\n\r\n",
                session->ctx->udp_send_port, session->ctx->udp_send_port + 1);
            strcat(session->response_buf, tmp);
            session->ctx->transport = RTP_TRANSPORT_UDP;
        }
    }

    send_response(session->ctx->fd, session->response_buf, strlen(session->response_buf));
}

void rtsp_handle_play(struct rtsp_session* session)
{
    generate_response_header(session);
    strcat(session->response_buf, "\r\n");
    send_response(session->ctx->fd, session->response_buf, strlen(session->response_buf));
    session->ctx->start_play = 1;
}

int rtsp_get_request(struct rtsp_session* session)
{
    int msg_type;
    int ret;
    char* sub_str;
    fd_set fds;
    struct timeval tv;
    char *pos = NULL, *start = NULL;

    memset(session->read_buf, 0, REQUEST_READ_BUF_SIZE);

    FD_ZERO(&fds);
    FD_SET(session->ctx->fd, &fds);
    tv.tv_sec = 120;
    tv.tv_usec = 10 * 1000;

    ret = select(session->ctx->fd + 1, &fds, NULL, NULL, &tv);
    if (ret == 0)
        return -1;
    else if (ret < 0)
        return -2;

    if (FD_ISSET(session->ctx->fd, &fds)) {
        ret = recv(session->ctx->fd, session->read_buf, REQUEST_READ_BUF_SIZE - 1, 0);
        if (ret < 0)
            return -3;
        else if (ret == 0)
            return -4;
        session->read_buf[REQUEST_READ_BUF_SIZE - 1] = 0;
    } else {
        return -5;

    }

    if (strstr(session->read_buf, "OPTIONS"))
        msg_type = RTSP_MSG_OPTIONS;
    else if (strstr(session->read_buf, "DESCRIBE"))
        msg_type = RTSP_MSG_DESCRIBE;
    else if (strstr(session->read_buf, "SETUP"))
        msg_type = RTSP_MSG_SETUP;
    else if (strstr(session->read_buf, "PLAY"))
        msg_type = RTSP_MSG_PLAY;
    else if (strstr(session->read_buf, "TEARDOWN"))
        msg_type = RTSP_MSG_TEARDOWN;
    else
        msg_type = RTSP_MSG_NULL;

    pos = strstr(session->read_buf, "\r\n");
    if (pos) {
        start = pos + 2;
        if ((sub_str = strstr(start, "CSeq: ")) != NULL) {
            pos = strstr(sub_str, "\r\n");
            if (pos) {

                if ((pos - sub_str - 6) <= sizeof(session->cseq)) {
                    memcpy(session->cseq, sub_str + 6, pos - sub_str - 6);
                    session->cseq[pos - sub_str - 6] = 0;
                    //start = pos + 2;
                } else {
                    printf("%s:%d:CSeq buffer overflow\n", __func__, __LINE__);
                    msg_type = RTSP_MSG_TEARDOWN;
                }
            }
        }

        if ((sub_str = strstr(start, "client_port=")) != NULL) {
            pos = strstr(sub_str, "-");
            if (pos) {
                char tmp[32];
                if ((pos - sub_str - 6) <= sizeof(tmp)) {
                    memcpy(tmp, sub_str + 12, pos - sub_str - 12);
                    tmp[pos - sub_str - 12] = 0;
                    session->ctx->udp_send_port = strtol(tmp, NULL, 0);
                } else {
                    printf("%s:%d:client_por buffer overflow\n", __func__, __LINE__);
                    msg_type = RTSP_MSG_TEARDOWN;
                }
            }
        }
    }

    return msg_type;
}

void (*g_event_cb)(int event);
void rtsp_set_event_cb(void (*cb)(int event))
{
    g_event_cb = cb;
}

int rtsp_message_process(struct rtsp_session* session)
{
    int type;

    type = rtsp_get_request(session);

    if (type < 0) {
        printf("rtsp_get_request error with %d\n", type);
        session->ctx->start_play = 0;
        return -1;
    }

    switch (type) {
    case RTSP_MSG_OPTIONS:
        rtsp_handle_options(session);
        g_event_cb(0);
        break;
    case RTSP_MSG_DESCRIBE:
        rtsp_handle_describe(session);
        g_event_cb(1);
        break;
    case RTSP_MSG_SETUP:
        rtsp_handle_setup(session);
        g_event_cb(2);
        break;
    case RTSP_MSG_PLAY:
        rtsp_handle_play(session);
        g_event_cb(3);
        break;
    case RTSP_MSG_TEARDOWN:
        session->ctx->start_play = 0;
        g_event_cb(4);
        return -1;
    }
    return 0;
}

int rtsp_process_func(struct client_context* client)
{
    struct rtsp_session* session = (struct rtsp_session*)client->session;
    if (rtsp_message_process(session) < 0) {
        debug("rtsp: client teardown, socket=%d\n", client->fd);
        return -1;
    }
    return 0;
}

void init_rtsp_session(struct client_context* client)
{
    struct rtsp_session* session;

    debug("rtsp: new client connected, socket=%d\n", client->fd);

    session = malloc(sizeof(struct rtsp_session));
    memset(session, 0, sizeof(struct rtsp_session));
    session->ctx = client;
    client->session = session;
    client->process_func = rtsp_process_func;
}

void cleanup_rtsp_session(struct client_context* client)
{
    if (client->session)
        free(client->session);
}
struct rtsp_server_context* rtsp_start_server(enum RTSP_STREAM_TYPE stream_type, int port)
{
    struct rtsp_server_context* server;
    int ret = 0;

    server = malloc(sizeof(struct rtsp_server_context));
    if (server == NULL) {
        debug("rtsp: failed to create server context object\n");
        return NULL;
    }
    memset(server, 0, sizeof(struct rtsp_server_context));

    rtp_list_init(&server->client_list);
    init_packet_pool(&server->rtp_info);

    server->rtp_info.udp_send_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server->rtp_info.udp_send_socket == -1) {
        debug("rtsp: failed to create send socket\n");
        free(server);
        return NULL;
    }

    server->video_stream_type = stream_type;
    server->stop = 0;
    server->port = port;
    server->init_client = init_rtsp_session;
    server->release_client = cleanup_rtsp_session;

    ret = pthread_create(&server->thread_id, NULL, rtp_tcp_server_thread, server);
    if (ret < 0) {
        debug("rtsp: failed to create rtsp server thread\n");
        free(server);
        return NULL;
    }

    return server;
}

void rtsp_stop_server(struct rtsp_server_context* server)
{
    debug("rtsp: stop server\n");

    server->stop = 1;

    if (server->thread_id > 0) {
        debug("rtsp: delete server thread\n");
        pthread_cancel(server->thread_id);
    }
    server_cleanup(server);
}
