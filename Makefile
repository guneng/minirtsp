all:
	gcc -I./rtsp -I./iread/pc/include main.c mov-file-buffer.c rtsp/*.c ./iread/pc/libs/*.a -o rtsp_server -lpthread -g3 -O2 -fstack-protector-strong