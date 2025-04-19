
#include "udp_comm.h"
#include "receive_data_from_host.h"
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utils.h>
#include <errno.h>
#include <string.h>

int send_udp_data(char *src_buffer, size_t src_buffer_size, int index) {
    struct sockaddr_in addr;
    int sock_fd;
    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        printf("Failed to create socket\n");
        return -1;
    }

    addr.sin_addr.s_addr = inet_addr(IP);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT+index);
    printf("PORT+index : %d\n",PORT+index);
    /* Send the descriptor to the DPU */
    /* Send the buffer data to the DPU */
    int bytes_sent = sendto(sock_fd, src_buffer, src_buffer_size, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (bytes_sent < 0) {
        printf("Failed to send data\n");
        close(sock_fd);
        return -1;
    }
    close(sock_fd);
    return bytes_sent;
}

int receive_udp_data(char *store, int index) {
    int sock_fd;
    int result;

    struct sockaddr_in servaddr;

    sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == -1) {
        return -1;
    }

    //servaddr.sin_addr.s_addr = inet_addr("192.168.100.2");
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_family = AF_INET;
    printf("PORT+index : %d\n",PORT+index);
    servaddr.sin_port = htons(PORT+index);

    result = bind(sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    if (result != 0) {
        printf("failed to bind : %s\n",strerror(errno));
        return -1;
    }

    /* Receive the descriptor on the socket */
    int rcv_bytes = recv(sock_fd, store, 1024, 0);
    if (rcv_bytes < 0) {
        printf("failed to receive : %s\n",strerror(errno));
        close(sock_fd);
        return -1;
    }
    return rcv_bytes;
}
