// (C) 2022-2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once

#include <atomic>
#include <string>
#include <thread>


class mdns
{
private:
	std::atomic_bool stop_flag { false   };
	int              port      { -1      };
	std::string      hostname;
	std::thread     *th        { nullptr };
	int              fd        { -1      };

public:
	mdns(const int port, const std::string & host);
	mdns(const mdns &) = delete;
	virtual ~mdns();

	bool begin();

	void operator()();
};
