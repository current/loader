#include "../include.h"
#include "client.h"

#include "ca.h"

void tcp::client::start(const std::string_view server_ip, const uint16_t port) {
	wolfSSL_library_init();

	m_ssl_ctx = wolfSSL_CTX_new(wolfTLS_client_method());

	int ret = wolfSSL_CTX_load_verify_buffer(m_ssl_ctx, reinterpret_cast<const unsigned char*>(root_cert.data()), root_cert.size(), SSL_FILETYPE_PEM);
	if (ret != 1) {
		io::log_error("failed to load ca.");
		return;
	}
	wolfSSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_PEER, 0);

	WSADATA data;
	ret = WSAStartup(MAKEWORD(2, 2), &data);
	if (ret != 0) {
		io::log_error("failed to initialize WSA.");
		return;
	}

	m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_socket == -1) {
		io::log_error("failed to create socket.");
		return;
	}

	sockaddr_in server_addr;

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr(server_ip.data());
	server_addr.sin_port = htons(port);

	ret = connect(m_socket, reinterpret_cast<sockaddr*>(&server_addr),
		sizeof(server_addr));
	if (ret < 0) {
		io::log_error("failed to connect to server.");
		return;
	}

	m_server_ssl = wolfSSL_new(m_ssl_ctx);
	wolfSSL_set_fd(m_server_ssl, m_socket);

	ret = wolfSSL_connect(m_server_ssl);

	if (ret != 1) {
		ret = wolfSSL_get_error(m_server_ssl, ret);
		io::log_error("secure connection failed, code {}", ret);
		return;
	}

	m_active.store(true);

	connect_event.call();
}

int tcp::client::read_stream(std::vector<char>& out) {
	size_t size;
	read(&size, sizeof(size));

	size = ntohl(size);
	out.resize(size);

	constexpr size_t chunk_size = 4096;
	size_t total = 0;

	while (size > 0) {
		auto to_read = std::min(size, chunk_size);

		int ret = read(&out[total], to_read);
		if (ret <= 0) {
			break;
		}

		size -= ret;
		total += ret;
	}

	return total;
}

int tcp::client::stream(std::vector<char>& data) {
	auto size = data.size();

	auto networked_size = htonl(size);
	write(&networked_size, sizeof(networked_size));

	// with 4kb chunk size, speed peaks at 90mb/s
	constexpr size_t chunk_size = 4096;
	size_t sent = 0;

	while (size > 0) {
		auto to_send = std::min(size, chunk_size);

		int ret = write(&data[sent], to_send);
		if (ret <= 0) {
			break;
		}

		sent += ret;
		size -= ret;
	}

	return sent;
}
