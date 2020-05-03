all:
	gcc -I./rtsp main.c rtsp/*.c -o rtsp_server -lpthread