// (C) 2022-2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <Arduino.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <unistd.h>
#include <vector>
#include <WiFi.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "mdns.h"


constexpr int ttl = 5;

static std::vector<std::string> split(std::string in, const std::string & splitter)
{
	std::vector<std::string> out;
	size_t splitter_size = splitter.size();

	for(;;)
	{
		size_t pos = in.find(splitter);
		if (pos == std::string::npos)
			break;

		std::string before = in.substr(0, pos);
		out.push_back(before);

		size_t bytes_left = in.size() - (pos + splitter_size);
		if (bytes_left == 0)
		{
			out.push_back("");
			return out;
		}

		in = in.substr(pos + splitter_size);
	}

	if (in.size() > 0)
		out.push_back(in);

	return out;
}

static uint16_t add_ptr(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	// svc name
	for(size_t i=1; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0x00;

	tgt[o++] = 0x00;  // PTR (12)
	tgt[o++] = 0x0c;

	tgt[o++] = 0x00;  // class: in
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t ptr_data_len = 1;

	for(size_t i=0; i<name.size(); i++)
		ptr_data_len += name.at(i).size() + 1;

	tgt[o++] = ptr_data_len >> 8;
	tgt[o++] = ptr_data_len;

	// name itself
	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0x00;

	return o;
}

static uint16_t add_srv(uint8_t *const tgt, const std::vector<std::string> & name, const int port)
{
	uint16_t o = 0;

	// name itself
	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 33 SRV (server selection)
	tgt[o++] = 0x21;

	tgt[o++] = 0x80;  // class (class: cache flush, in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t srv_data_len = 2 + 2 + 2 + 1 + name.at(0).size() + 1 + 5 /* "local" */ + 1;
	tgt[o++] = srv_data_len >> 8;  // data len
	tgt[o++] = srv_data_len;

	tgt[o++] = 0x00;  // priority
	tgt[o++] = 0x00;

	tgt[o++] = 0x00;  // weight
	tgt[o++] = 0x00;

	tgt[o++] = port >> 8;  // port on which it listens
	tgt[o++] = port;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0x00;

	return o;
}

static uint16_t add_a(uint8_t *const tgt, const std::vector<std::string> & name, const uint8_t a[4])
{
	uint16_t o = 0;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 0001 (A)
	tgt[o++] = 0x01;

	tgt[o++] = 0x80;  // class (cache flush: True, class: in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	tgt[o++] = 0x00;  // length of address
	tgt[o++] = 4;

	for(int i=0; i<4; i++)
		tgt[o++] = a[i];

	return o;
}

static uint16_t add_txt(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	for(size_t i=0; i<name.size(); i++) {
		tgt[o++] = name.at(i).size();

		o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(i).c_str());
	}

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 16 SRV (server selection)
	tgt[o++] = 0x10;

	tgt[o++] = 0x80;  // class (class: cache flush, in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	tgt[o++] = 0;  // data len
	tgt[o++] = 0;

	return o;
}

static uint16_t add_nsec(uint8_t *const tgt, const std::vector<std::string> & name)
{
	uint16_t o = 0;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // type 47 (NSEC)
	tgt[o++] = 0x2f;

	tgt[o++] = 0x00;  // class (class: in)
	tgt[o++] = 0x01;

	tgt[o++] = ttl >> 24;  // ttl
	tgt[o++] = ttl >> 16;
	tgt[o++] = ttl >> 8;
	tgt[o++] = ttl;

	uint16_t data_len = 1 + name.at(0).size() + 1 + 5/*"local"*/ + 1 + 2 + 6;
	tgt[o++] = data_len >> 8;  // length of nsec
	tgt[o++] = data_len;

	tgt[o++] = name.at(0).size();
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "%s", name.at(0).c_str());

	tgt[o++] = 5;
	o += sprintf(reinterpret_cast<char *>(&tgt[o]), "local");

	tgt[o++] = 0;  // string delimiter

	tgt[o++] = 0x00;  // window
	tgt[o++] = 0x06;  // bitmap len

	uint16_t bm_o = o;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;
	tgt[o++] = 0x00;

	tgt[bm_o + 1  / 8] |= 1 << (7 - (1  % 8));  // A
	tgt[bm_o + 12 / 8] |= 1 << (7 - (12 % 8));  // PTR
	tgt[bm_o + 16 / 8] |= 1 << (7 - (16 % 8));  // TXT
	tgt[bm_o + 33 / 8] |= 1 << (7 - (33 % 8));  // SRV
	tgt[bm_o + 47 / 8] |= 1 << (7 - (47 % 8));  // NSEC

	return o;
}

mdns::mdns(const int port, const std::string & host) :
	port(port),
	hostname(host)
{
}

mdns::~mdns()
{
	stop_flag = true;

	if (fd != -1)
		close(fd);

	th->join();
	delete th;
}

bool mdns::begin()
{
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		printf("Socket create failed\n");
		return false;
	}

	sockaddr_in from_addr;
	memset(&from_addr, 0, sizeof(from_addr));
	from_addr.sin_family = AF_INET;
	from_addr.sin_port = htons(5353);
	if (bind(fd, reinterpret_cast<sockaddr *>(&from_addr), sizeof from_addr) == -1) {
		printf("bind socket failed\n");
		return false;
	}

	th = new std::thread(std::ref(*this));

	return true;
}

void mdns::operator()()
{
	unsigned long last = 0;

	sockaddr_in to_addr;
	memset(&to_addr, 0, sizeof(to_addr));
	to_addr.sin_family = AF_INET;
	to_addr.sin_addr.s_addr = inet_addr("224.0.0.251");
	to_addr.sin_port = htons(5353);

	while(!stop_flag) {
		unsigned long now = millis();

		if (now - last <= 1000) {
			vTaskDelay(100 / portTICK_PERIOD_MS);
			continue;
		}

		last = now;

		uint8_t  mdns_buffer[256] { 0 };
		uint16_t ro               { 0 };

		mdns_buffer[ro++] = 0x00;  // transaction id
		mdns_buffer[ro++] = 0x00;

		mdns_buffer[ro++] = 0x84;  // standard query response, no error
		mdns_buffer[ro++] = 0x00;

		mdns_buffer[ro++] = 0x00;  // 0 questions
		mdns_buffer[ro++] = 0x00;

		mdns_buffer[ro++] = 0x00;  // 4 answers
		mdns_buffer[ro++] = 0x04;

		mdns_buffer[ro++] = 0x00;  // 0 authority rr
		mdns_buffer[ro++] = 0x00;
		
		mdns_buffer[ro++] = 0x00;  // 0 additional rr
		mdns_buffer[ro++] = 0x00;

		std::string work      = hostname;
		std::size_t last_char = work.size() - 1;

		if (work[last_char] == '.')
			work.erase(last_char);

		auto name = split(work, ".");

		// PTR record
		ro += add_ptr(&mdns_buffer[ro], name);

		// TXT record
		ro += add_txt(&mdns_buffer[ro], name);

		// SRV record
		ro += add_srv(&mdns_buffer[ro], name, port);

		auto src_addr = WiFi.localIP();

		// A record for the hostname to the ip-address
		uint8_t a[] = { src_addr[0], src_addr[1], src_addr[2], src_addr[3] };  // don't ask
		ro += add_a(&mdns_buffer[ro], name, a);

		if (sendto(fd, mdns_buffer, ro, 0, reinterpret_cast<sockaddr *>(&to_addr), sizeof to_addr) != ro)
			printf("xmit error\n");
	}
}
