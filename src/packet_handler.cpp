#include "packet_handler.hpp"
#include <iostream>

int find_ip(const std::vector<ip_r>* _blacklist_ptr, uint32_t addr){

	const auto &blacklist = *_blacklist_ptr;

	for(int i = 0; i < _blacklist_ptr->size(); i++){

		if((addr & blacklist[i].big_e_mask) == blacklist[i].big_e_net_ip){

			return 1;
		}
	}

	return 0;
}

void pck_handler(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	struct Context* ctx = reinterpret_cast<Context*>(args);
	struct iphdr* ip = (struct iphdr*)(packet + ctx->header_offset);
	struct ethhdr* eth = nullptr;

	std::string log_mesg = "";

	//if ethernet frame
	if(ctx->link_type == DLT_EN10MB){

		eth = (struct ethhdr*)packet;
	}

	if(find_ip(ctx->blacklist_ptr, ip->saddr)){

		char ip_str_buf[INET_ADDRSTRLEN] = {0};

		//parse it to human readable format
		inet_ntop(AF_INET, &(ip->saddr), ip_str_buf, INET_ADDRSTRLEN);

		if(eth != nullptr){

			switch(ntohs(eth->h_proto)){

				case ETH_P_IP:
					log_mesg = "[ALERT] " + Logger::timenow() + 
						" Blacklisted address detected on " + ctx->interface + " [" + ip_str_buf + "]\n";
					break;
			}
		}
	}
	std::cout << log_mesg;
}
