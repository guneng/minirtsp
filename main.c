#include <stdio.h>

#include "rtsp.h"

static struct rtsp_server_context* g_rtsp_servers[2];

#include "aom-av1.h"
#include "mov-format.h"
#include "mov-reader.h"
#include "mpeg4-aac.h"
#include "mpeg4-avc.h"
#include "mpeg4-hevc.h"
#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

const struct mov_buffer_t* mov_file_buffer(void);

static uint8_t s_packet[2 * 1024 * 1024];
static uint8_t s_buffer[4 * 1024 * 1024];
static FILE *s_vfp, *s_afp;
static struct mpeg4_hevc_t s_hevc;
static struct mpeg4_avc_t s_avc;
static struct mpeg4_aac_t s_aac;
static struct aom_av1_t s_av1;
static uint32_t s_aac_track = 0xFFFFFFFF;
static uint32_t s_avc_track = 0xFFFFFFFF;
static uint32_t s_av1_track = 0xFFFFFFFF;
static uint32_t s_hevc_track = 0xFFFFFFFF;

void send_data_for_channel(int chn, const unsigned char* data, const int len, unsigned long long pts);

static inline const char* ftimestamp(uint32_t t, char* buf)
{
    sprintf(buf, "%02u:%02u:%02u.%03u", t / 3600000, (t / 60000) % 60, (t / 1000) % 60, t % 1000);
    return buf;
}

static unsigned long long get_timems(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void onread(void* flv, uint32_t track, const void* buffer, size_t bytes, int64_t pts, int64_t dts, int flags)
{
    static char s_pts[64], s_dts[64];
    static int64_t v_pts, v_dts;
    static int64_t a_pts, a_dts;

    int* has_i = flv;

    if (s_avc_track == track)
    {
        printf("[H264] pts: %s, dts: %s, diff: %03d/%03d%s\n", ftimestamp(pts, s_pts), ftimestamp(dts, s_dts), (int)(pts - v_pts), (int)(dts - v_dts), flags ? " [I]" : "");
        if (flags) {
            *has_i = 1;
        }

        int64_t ms_sleep = 1000 * ((int64_t)(dts - v_dts));
        printf("[%lld]\n", ms_sleep);
        if (ms_sleep >= 0) {
            usleep(ms_sleep);
        }

        v_pts = pts;
        v_dts = dts;

        int n = h264_mp4toannexb(&s_avc, buffer, bytes, s_packet, sizeof(s_packet));
        if (n > 0) {
            pts = get_timems();
            send_data_for_channel(0, s_packet, n, (unsigned long long int)pts);
        }


        fwrite(s_packet, 1, n, s_vfp);
    }
    else if (s_hevc_track == track)
    {
        printf("[H265] pts: %s, dts: %s, diff: %03d/%03d%s\n", ftimestamp(pts, s_pts), ftimestamp(dts, s_dts), (int)(pts - v_pts), (int)(dts - v_dts), flags ? " [I]" : "");
        v_pts = pts;
        v_dts = dts;

        int n = h265_mp4toannexb(&s_hevc, buffer, bytes, s_packet, sizeof(s_packet));
        fwrite(s_packet, 1, n, s_vfp);
    }
}

static void mov_video_info(void* param, uint32_t track, uint8_t object, int width, int height, const void* extra, size_t bytes)
{
    if (MOV_OBJECT_H264 == object) {
        s_vfp = fopen("v.h264", "wb");
        s_avc_track = track;
        mpeg4_avc_decoder_configuration_record_load((const uint8_t*)extra, bytes, &s_avc);
    } else if (MOV_OBJECT_HEVC == object) {
        s_vfp = fopen("v.h265", "wb");
        s_hevc_track = track;
        mpeg4_hevc_decoder_configuration_record_load((const uint8_t*)extra, bytes, &s_hevc);
    }
}

static void mov_audio_info(void* param, uint32_t track, uint8_t object, int channel_count, int bit_per_sample, int sample_rate, const void* extra, size_t bytes)
{
}

void mov_reader_test(const char* mp4, int i_break)
{
    FILE* fp = fopen(mp4, "rb");
    mov_reader_t* mov = mov_reader_create(mov_file_buffer(), fp);
    uint64_t duration = mov_reader_getduration(mov);

    struct mov_reader_trackinfo_t info = { mov_video_info, mov_audio_info };
    mov_reader_getinfo(mov, &info, NULL);
    int has_i = 0;
    while (mov_reader_read(mov, s_buffer, sizeof(s_buffer), onread, &has_i) > 0)
    {
        if (i_break&&has_i) {
            break;
        }
    }

    duration /= 2;
    mov_reader_seek(mov, (int64_t*)&duration);

    mov_reader_destroy(mov);
    if (s_vfp)
        fclose(s_vfp);
    if (s_afp)
        fclose(s_afp);
    fclose(fp);
}

unsigned char* find_start_code(unsigned char* pos, int len)
{
    unsigned char* p = pos;
    unsigned char* end = pos + len;

    while (p != end) {
        if (p + 4 > end)
            break;
        if (p[0] == 0 && p[1] == 0 && p[2] == 0 && p[3] == 1)
            return p;
        else
            p += 1;
    }
    return NULL;
}

void send_data_for_channel(int chn, const unsigned char* data, const int len, unsigned long long pts)
{
    int i = 0;
    unsigned char* pos = data;
    unsigned char* end = data + len;
    int rest = len;
    unsigned char* next_start;

    struct rtsp_server_context* server = g_rtsp_servers[chn];

    do {
        next_start = find_start_code(pos + 4, rest - 4);
        if (next_start) {
            rtp_push_data(server, pos, next_start - pos, pts);
            i++;
            rest = rest - (next_start - pos);
            pos = next_start;
        } else { /* reach the end of data */
            rtp_push_data(server, pos, end - pos, pts);
        }
    } while (next_start != NULL);
}

static int started = 0;

static void __cb_event(int event_num)
{
    if (event_num == 3) {
        sleep(2);
        started = 1;
    }
}


int main(int argc, char** argv)
{
    rtsp_set_event_cb(__cb_event);
    g_rtsp_servers[0] = rtsp_start_server(RTSP_STREAM_TYPE_H264, 4433);

    mov_reader_test(argv[1], 1);

    while (1)
    {
        usleep(500000);
        if (started) 
            mov_reader_test(argv[1], 0);
    }

    rtsp_stop_server(g_rtsp_servers[0]);

    return 0;
}