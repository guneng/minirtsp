#ifndef __SDP_H__
#define __SDP_H__

#include "rtsp.h"

struct sdp_info {
    enum RTSP_STREAM_TYPE video_type;
    unsigned char sps[128];
    int sps_len;
    int has_sps;
    unsigned char pps[128];
    int pps_len;
    int has_pps;
    unsigned char vps[128];
    int vps_len;
    int has_vps;
    char content[8192];
    int len;
};

void generate_sdp(struct sdp_info* sdp);

#endif