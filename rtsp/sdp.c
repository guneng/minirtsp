#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "sdp.h"

static char s_base64_enc[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};
static char s_base64_url[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
};

static size_t base64_encode_table(char* target, const void* source, size_t bytes, const char* table)
{
    size_t i, j;
    const uint8_t* ptr = (const uint8_t*)source;

    for (j = i = 0; i < bytes / 3 * 3; i += 3) {
        target[j++] = table[(ptr[i] >> 2) & 0x3F]; /* c1 */
        target[j++] = table[((ptr[i] & 0x03) << 4) | ((ptr[i + 1] >> 4) & 0x0F)]; /*c2*/
        target[j++] = table[((ptr[i + 1] & 0x0F) << 2) | ((ptr[i + 2] >> 6) & 0x03)]; /*c3*/
        target[j++] = table[ptr[i + 2] & 0x3F]; /* c4 */
    }

    if (i < bytes) {
        /* There were only 2 bytes in that last group */
        target[j++] = table[(ptr[i] >> 2) & 0x3F];

        if (i + 1 < bytes) {
            target[j++] = table[((ptr[i] & 0x03) << 4) | ((ptr[i + 1] >> 4) & 0x0F)]; /*c2*/
            target[j++] = table[((ptr[i + 1] & 0x0F) << 2)]; /*c3*/
        } else {
            /* There was only 1 byte in that last group */
            target[j++] = table[((ptr[i] & 0x03) << 4)]; /*c2*/
            target[j++] = '='; /*c3*/
        }

        target[j++] = '='; /*c4*/
    }

    return j;
}

static size_t _base64_encode(char* target, const void* source, size_t bytes)
{
    return base64_encode_table(target, source, bytes, s_base64_enc);
}

void generate_sdp(struct sdp_info* sdp)
{
    char tmp[256];

    memset(sdp->content, '\0', sizeof(sdp->content));

    sdp->content[0] = 0;

    strcat(sdp->content, "v=0\r\ns=miniplayer\r\n");

    if (sdp->video_type == RTSP_STREAM_TYPE_H264) {
        strcat(sdp->content, "m=video 0 RTP/AVP 96\r\n");
        sprintf(sdp->content + strlen(sdp->content),
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 profile-level-id=%02hhX%02hhX%02hhX;packetization-mode=1;"
            "sprop-parameter-sets=",
            sdp->sps[1], sdp->sps[2], sdp->sps[3]);

        memset(tmp, 0, sizeof(tmp));
        _base64_encode(tmp, sdp->sps, sdp->sps_len);
        strcat(sdp->content, tmp);
        strcat(sdp->content, ",");

        memset(tmp, 0, sizeof(tmp));
        _base64_encode(tmp, sdp->pps, sdp->pps_len);
        strcat(sdp->content, tmp);
        strcat(sdp->content, "\r\n");
    } else if (sdp->video_type == RTSP_STREAM_TYPE_H265) {
        strcat(sdp->content, "m=video 0 RTP/AVP 97\r\n");
        strcat(sdp->content, "a=rtpmap:97 H265/90000\r\n"
                             "a=fmtp:97 ");

        memset(tmp, 0, sizeof(tmp));
        _base64_encode(tmp, sdp->vps, sdp->vps_len);
        sprintf(sdp->content + strlen(sdp->content), "sprop-vps=%s;", tmp);

        memset(tmp, 0, sizeof(tmp));
        _base64_encode(tmp, sdp->sps, sdp->sps_len);
        sprintf(sdp->content + strlen(sdp->content), "sprop-sps=%s;", tmp);

        memset(tmp, 0, sizeof(tmp));
        _base64_encode(tmp, sdp->pps, sdp->pps_len);
        sprintf(sdp->content + strlen(sdp->content), "sprop-pps=%s\r\n", tmp);

    }

    sdp->len = strlen(sdp->content);
}