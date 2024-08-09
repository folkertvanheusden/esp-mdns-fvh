// (C) 2022-2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#pragma once

#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


class mdns
{
private:
	std::atomic_bool stop_flag { false   };
	std::mutex       names_lock;
	std::vector<std::pair<int, std::string> > names;
	std::thread     *th        { nullptr };
	int              fd        { -1      };

public:
	mdns();
	mdns(const mdns &) = delete;
	virtual ~mdns();

	void add_name(const int port, const std::string & host);
	bool begin();
	void operator()();
};
