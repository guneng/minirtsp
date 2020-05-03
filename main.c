#include <stdio.h>

#include "rtsp.h"

int main(int argc, char** argv)
{
    struct rtsp_server_context* ctx = rtsp_start_server(RTP_TRANSPORT_UDP, 433);

    while (1) {
        rtp_push_data(ctx, NULL, 0, 0);
    }

    rtsp_stop_server(ctx);

    return 0;
}