#include "packet_handler.hpp"
#include <iostream>

void pck_handler(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	struct Context* ctx = reinterpret_cast<Context*>(args);
	struct iphdr* ip = (struct iphdr*)(packet + ctx->header_offset);
	struct ethhdr* eth = nullptr;

	std::string log_mesg = "";

	//if ethernet frame
	if(ctx->link_type == DLT_EN10MB){

		eth = (struct ethhdr*)packet;
	}

	if(ctx->blacklist_ptr->count(ip->saddr)){

		char ip_str_buf[INET_ADDRSTRLEN] = {0};

		//parse it to human readable format
		inet_ntop(AF_INET, &(ip->saddr), ip_str_buf, INET_ADDRSTRLEN);

		if(eth != nullptr){

			switch(ntohs(eth->h_proto)){

				case ETH_P_IP:
					log_mesg = "[ALERT] |" + Logger::timenow() + 
						"| Blacklisted address detected on " + ctx->interface + " [" + ip_str_buf + "]\n";
					break;
			}
		}

	}
	std::cout << log_mesg;
}
