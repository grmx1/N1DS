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

std::string find_proto(int proto){

	switch(proto){

		case 1: return std::format("{:<4}", "ICMP");
		case 6: return std::format("{:<4}", "TCP");
		case 17: return std::format("{:<4}", "UDP");
		case 2: return std::format("{:<4}", "IGMP");
		case 132: return std::format("{:<4}", "SCTP");
		case 47: return std::format("{:<4}", "GRE");
		default: return std::format("{:<4}", "N/A");
	}
}

int RecordTracker::records_size(){

	return records.size();
}

uint16_t RecordTracker::get_port(iphdr* ip_info){

	//this is in 32-bit words so * 4 to get
	//iphdr length in bytes
	int ip_header_len = ip_info->ihl * 4;

	if(ip_info->protocol == IPPROTO_TCP){

		struct tcphdr* tcp = (struct tcphdr*)(ip_info + ip_header_len);
		return tcp->dest;
	}
	else if(ip_info->protocol == IPPROTO_UDP){

		struct udphdr* udp = (struct udphdr*)(ip_info + ip_header_len);
		return udp->dest;
	}

	return 0;
}

void log_alert(){


}

void RecordTracker::insert_record(iphdr* ip_info){

	//map iterator pointing to the list iterator that points to the ip
	auto map_it = r_map.find(ip_info->saddr);

	uint16_t port = get_port(ip_info);

	if(map_it != r_map.end()){

		//list iterator pointing to the ip
		auto ip_r_ptr = map_it->second;

		//move node to the end of the list
		records.splice(records.end(), records, map_it->second);

		ip_r_ptr->proto = ip_info->protocol;

		//check for size of the internal maps to protect against
		//flood-type attacks / scanns filling up memory without
		//increasing records.size()
		if(ip_r_ptr->dst_record[ip_info->daddr] < MAX_MAP_SIZE){

			ip_r_ptr->dst_record[ip_info->daddr] += 1;
		}

		if(ip_r_ptr->ports_record[port] < MAX_MAP_SIZE){

			ip_r_ptr->ports_record[port] += 1;
		}

		ip_r_ptr->last_seen = std::chrono::steady_clock::now();
	}
	else{

		//create local object
		ip_record ip_r;

		ip_r.ip = ip_info->saddr;
		ip_r.proto = ip_info->protocol;

		ip_r.dst_record[ip_info->daddr] += 1;
		ip_r.ports_record[get_port(ip_info)] += 1;

		ip_r.last_seen = std::chrono::steady_clock::now();

		//insert on the tracker data structures
		records.push_back(ip_r);
		r_map[ip_r.ip] = --records.end();
	}

}

void RecordTracker::update_records(){

	auto time_now = std::chrono::steady_clock::now();

	bool old_pck = true;

	while(!records.empty() && old_pck){

		auto duration = time_now - records.front().last_seen;
		auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(duration);

		if(std::chrono::duration<double>(elapsed_sec).count() > 5.0){

			r_map.erase(records.front().ip);
			records.pop_front();
		}
		else{
			old_pck = false;
		}
	}
}

void callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet){

	struct Context* ctx = reinterpret_cast<Context*>(args);
	struct ethhdr* eth = nullptr;

	//if ethernet frame
	if(ctx->link_type == DLT_EN10MB){

		eth = (struct ethhdr*)packet;
	
		//checking for vlan to add propper offset
		if(ntohs(eth->h_proto) == ETH_P_8021Q){

			ctx->header_offset = 18;
		}
	}

	struct iphdr* ip = (struct iphdr*)(packet + ctx->header_offset);

	std::stringstream log_mesg;

	std::string protocol = find_proto((int)ip->protocol);

	//i think idc if it is ehternet at this point but maybe
	//im wrong and this crashes something
	ctx->r_track_ptr->insert_record(ip);
	if(ctx->r_track_ptr->records_size() >= MAX_PCK_RECORD){

		ctx->r_track_ptr->update_records();
	}
/*
	int tempcount = 0;
	for(auto record : ctx->r_track_ptr->records){

		auto time_now = std::chrono::steady_clock::now();
		auto duration = time_now - record.last_seen;
		auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(duration);

		struct in_addr addr;
		addr.s_addr = record.ip;

		std::cout << "Entry " << tempcount++ << std::endl;
		std::cout << "    " << inet_ntoa(addr) << std::endl;
		std::cout << "    " << find_proto((int)record.proto) << std::endl;
		std::cout << "    " << "sec: " << std::chrono::duration<double>(elapsed_sec).count() << std::endl;
		std::cout << "    " << "records size -> " << ctx->r_track_ptr->records.size();
		std::cout << std::endl;
	}
	/*
	if(find_ip(ctx->blacklist_ptr, ip->saddr)){

		char s_ip_str[INET_ADDRSTRLEN] = {0};
		char d_ip_str[INET_ADDRSTRLEN] = {0};

		//parse it to human readable format
		inet_ntop(AF_INET, &(ip->saddr), s_ip_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ip->daddr), d_ip_str, INET_ADDRSTRLEN);

		char src[32];
		char dst[32];

		snprintf(src, sizeof(src), "%-15s", s_ip_str);
		snprintf(dst, sizeof(dst), "%-15s", d_ip_str);

		if(eth != nullptr){

			switch(ntohs(eth->h_proto)){

				case ETH_P_IP:

					
					log_mesg << "[ALERT] " + Logger::timenow() << " " << ctx->interface << " BLACKLISTED SRC: "
						<< src << " DST: " << dst << " PROTO: " << protocol << "\n";
					
					break;
				
				case ETH_P_ARP:

					break;

				case ETH_P_8021Q:
					
					break;

			}
		}
		else{
			log_mesg << "[ALERT] " + Logger::timenow() << " " << ctx->interface << " BLACKLISTED SRC: "
				<< src << " DST: " << dst << " PROTO: " << protocol << " TUNNELED\n";

		}
	}
	*/
	std::cout << log_mesg.str();
}
