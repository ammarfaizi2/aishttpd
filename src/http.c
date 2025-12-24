// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Alviro Iskandar Setiawan <alviro.iskandar@gnuweeb.org>
 */
#include "http.h"
#include "tcp.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

/*
 * TODO(viro_ssfs):
 *   - Make this file more modular.
 *   - Implement proper HTTP request parsing.
 *   - Implement HTTP routing and handling different methods.
 *   - and many more...
 *
 */

struct http_client {
	char	str_ip[INET6_ADDRSTRLEN + sizeof(":65535")];
};

static void store_str_ip(struct ais_sock_addr *addr, char *buf, size_t buf_len)
{
	size_t len;

	if (addr->sa.sa_family == AF_INET) {
		inet_ntop(AF_INET, &addr->in.sin_addr, buf, buf_len);
		len = strlen(buf);
		snprintf(buf + len, buf_len - len, ":%hu", ntohs(addr->in.sin_port));
	} else if (addr->sa.sa_family == AF_INET6) {
		inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, buf_len);
		len = strlen(buf);
		snprintf(buf + len, buf_len - len, ":%hu", ntohs(addr->in6.sin6_port));
	} else {
		snprintf(buf, buf_len, "unknown");
	}
}

static const char res[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/plain\r\n"
	"Content-Length: 14\r\n"
	"Connection: close\r\n"
	"\r\n"
	"Hello, World!\n";
static const size_t res_len = sizeof(res) - 1;

static ssize_t recv_callback(struct ais_sock_tcp_cli *cli)
{
	struct http_client *hc = cli->user_data;
	int r;

	printf("Received data from client %s: %s\n", hc->str_ip, cli->rx_buf.buf);
	r = ais_sock_buf_append_grow(&cli->tx_buf, res, res_len);
	if (r < 0)
		return r;

	return (ssize_t)cli->rx_buf.off;
}

static int send_callback(struct ais_sock_tcp_cli *cli, ssize_t sent_len)
{
	struct http_client *hc = cli->user_data;
	printf("Sent %zd bytes to client %s\n", sent_len, hc->str_ip);

	if (!cli->tx_buf.off)
		shutdown(cli->fd, SHUT_RDWR);

	return 0;
}

static void close_callback(struct ais_sock_tcp_cli *cli)
{
	struct http_client *hc = cli->user_data;
	printf("Connection with client %s closed\n", hc->str_ip);
	free(hc);
}

static int accept_callback(struct ais_sock_tcp_cli *cli)
{
	struct http_client *hc;
	hc = malloc(sizeof(*hc));
	if (!hc)
		return -ENOMEM;

	store_str_ip(&cli->addr, hc->str_ip, sizeof(hc->str_ip));
	cli->user_data = hc;
	ais_sock_tcp_cli_set_cb_rx(cli, &recv_callback);
	ais_sock_tcp_cli_set_cb_close(cli, &close_callback);
	ais_sock_tcp_cli_set_cb_tx(cli, &send_callback);
	return 0;
}

struct ais_sock_tcp_srv *g_srv;

static void handle_exit_signal(int sig)
{
	(void)sig;
	ais_sock_tcp_srv_stop(g_srv);
}

static void setup_signal(struct ais_sock_tcp_srv *srv)
{
	struct sigaction sa;

	g_srv = srv;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &handle_exit_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sa.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sa, NULL);
}

int start_http(void)
{
	struct ais_sock_tcp_srv_iarg iarg = {
		.bind_addr = "::",
		.port = 9980,
		.sock_backlog = 128,
		.epoll_nevents = 64,
		.max_clients = 1024,
	};
	struct ais_sock_tcp_srv srv;
	int r;

	setup_signal(&srv);
	r = ais_sock_tcp_srv_init(&srv, &iarg);
	if (r < 0) {
		fprintf(stderr, "Failed to initialize TCP server: %d\n", r);
		return -r;
	}

	ais_sock_tcp_srv_set_cb_accept(&srv, &accept_callback);
	printf("Starting TCP server on [%s]:%hu...\n", iarg.bind_addr, iarg.port);
	r = ais_sock_tcp_srv_run(&srv);
	if (r < 0)
		fprintf(stderr, "Failed to run TCP server: %d\n", r);

	printf("Shutting down TCP server...\n");
	ais_sock_tcp_srv_free(&srv);
	return -r;
}
