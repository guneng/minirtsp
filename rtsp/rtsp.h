#ifndef __RTSP_H__
#define __RTSP_H__

#define RTSP_DEBUG

#ifdef RTSP_DEBUG
#define debug printf
#else
#define debug
#endif

enum RTSP_STREAM_TYPE {
    RTSP_STREAM_TYPE_H264,
    RTSP_STREAM_TYPE_H265,
};

struct rtsp_server_context;

void rtsp_set_event_cb(void (*cb)(int event));

struct rtsp_server_context* rtsp_start_server(enum RTSP_STREAM_TYPE stream_type, int port);
void rtsp_stop_server(struct rtsp_server_context* server);
void rtp_push_data(struct rtsp_server_context* server, void* data, int size, unsigned long long pts);

#endif
