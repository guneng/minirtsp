#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "sdp.h"

static void base64_encode(char* dst, char* src, int len)
{
    int out_len;
    int i;
    int left_count;
    int index;
    static const char base64[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if ((left_count = len % 3) > 0)
        out_len = (len / 3 + 1) * 4;
    else
        out_len = len / 3 * 4;

    for (i = 0; i < len / 3; i++) {
        index = src[i * 3] >> 2;
        dst[i * 4] = base64[index];
        index = ((src[i * 3] & 0x03) << 4) | ((src[i * 3 + 1] & 0xf0) >> 4);
        dst[i * 4 + 1] = base64[index];
        index = ((src[i * 3 + 1] & 0x0f) << 2) | ((src[i * 3 + 2] & 0xc0) >> 6);
        dst[i * 4 + 2] = base64[index];
        index = src[i * 3 + 2] & 0x3f;
        dst[i * 4 + 3] = base64[index];
    }
    if (left_count == 1) {
        index = src[i * 3] >> 2;
        dst[i * 4] = base64[index];
        index = (src[i * 3] & 0x03) << 4;
        dst[i * 4 + 1] = base64[index];
        dst[i * 4 + 2] = '=';
        dst[i * 4 + 3] = '=';
    }
    if (left_count == 2) {
        index = src[i * 3] >> 2;
        dst[i * 4] = base64[index];
        index = ((src[i * 3] & 0x03) << 4) | ((src[i * 3 + 1] & 0xf0) >> 4);
        dst[i * 4 + 1] = base64[index];
        index = (src[i * +1] & 0x0f) << 2;
        dst[i * 4 + 2] = base64[index];
        dst[i * 4 + 3] = '=';
    }
    dst[out_len] = 0;
}

void generate_sdp(struct sdp_info* sdp)
{
    char tmp[256];

    if (!sdp->has_sps || !sdp->has_pps)
        return;

    memset(sdp->content, '\0', sizeof(sdp->content));

    sdp->content[0] = 0;

    strcat(sdp->content, "v=0\r\n");

    strcat(sdp->content, "m=video 0 RTP/AVP 96\r\n");
    sprintf(sdp->content + strlen(sdp->content),
        "a=rtpmap:96 H264/90000\r\n"
        "a=fmtp:96 profile-level-id=%02hhx%02hhx%02hhx;packetization-mode=1;"
        "sprop-parameter-sets=",
        sdp->sps[5], sdp->sps[6], sdp->sps[7]);

    base64_encode(tmp, sdp->sps, sdp->sps_len);
    strcat(sdp->content, tmp);
    strcat(sdp->content, ",");
    base64_encode(tmp, sdp->pps, sdp->pps_len);
    strcat(sdp->content, tmp);
    strcat(sdp->content, "\r\n");

    sdp->len = strlen(sdp->content);
}