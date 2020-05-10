#ifndef __SDP_H__
#define __SDP_H__

struct sdp_info {
    char sps[128];
    int sps_len;
    int has_sps;
    char pps[128];
    int pps_len;
    int has_pps;
    char content[8192];
    int len;
};

void generate_sdp(struct sdp_info* sdp);

#endif