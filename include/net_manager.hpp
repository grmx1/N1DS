#pragma once
#include <iostream>
#include <pcap/pcap.h>

#include "parser.hpp"

class NetManager{

	public:

	pcap_t* session;// = pcap_open_live(if_name.c_str(), 65535, 1, 1000, errbuf);
	struct{

		std::string if_target;
	} input;

	NetManager(const ArgParser &_clargs);
	~NetManager();

	int init();
	int get_header_offset(int link_type);

	private:

	char errbuf[PCAP_ERRBUF_SIZE];

};
