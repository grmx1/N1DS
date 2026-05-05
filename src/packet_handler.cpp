#include "packet_handler.hpp"
#include <iostream>

int find_ip(const std::vector<ip_range> &_blacklist, uint32_t addr){

	for(int i = 0; i < _blacklist.size(); i++){

		if((addr & _blacklist[i].big_e_mask) == _blacklist[i].big_e_net_ip){

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

void RecordTracker::eval_ip_record(ip_record &ip_rec, std::array<int, LOG_IP_SIZE> &log_data){

	uint32_t dst_ip = ip_rec.dst_ip;
	uint16_t dst_port = ip_rec.dst_port;

	int vscan_count = ip_rec.dst_record[dst_ip][dst_port];
	int hscan_count = ip_rec.ports_record[dst_port][dst_ip];

	bool flood_proto = (ip_rec.proto == UDP || ip_rec.proto == ICMP);

	//blackisted ip
	if(find_ip(blacklist, ip_rec.ip)){

		log_data[LOG_BLK_ADDR] = ALERT;
	}

	//vertical scan
	if(vscan_count > MAX_VSCAN_CRI){

		log_data[LOG_IP_VSCAN] = CRITICAL;
	}
	else if(vscan_count > MAX_VSCAN_ALR){

		log_data[LOG_IP_VSCAN] = ALERT;
	}
	else if(vscan_count > MAX_VSCAN_NOT){

		log_data[LOG_IP_VSCAN] = NOTICE;
	}
	else{

		log_data[LOG_IP_VSCAN] = NONE;
	}

	//horizontal scan
	if(hscan_count > MAX_HSCAN_CRI){

		log_data[LOG_IP_HSCAN] = CRITICAL;
	}
	else if(hscan_count > MAX_HSCAN_ALR){

		log_data[LOG_IP_HSCAN] = ALERT;
	}
	else if(hscan_count > MAX_HSCAN_NOT){

		log_data[LOG_IP_HSCAN] = NOTICE;
	}
	else{

		log_data[LOG_IP_HSCAN] = NONE;
	}

	//flood attack
	if(!ip_rec.fld_notice && ip_rec.flood_tracker > MAX_FLOOD_NOT && flood_proto){

		log_data[LOG_FLOOD_AT] = NOTICE;
		ip_rec.fld_notice = true;
	}
	else if(!ip_rec.fld_alert && ip_rec.flood_tracker > MAX_FLOOD_ALR && flood_proto){

		log_data[LOG_FLOOD_AT] = ALERT;
		ip_rec.fld_alert = true;
	}
	else if(ip_rec.flood_tracker > MAX_FLOOD_ALR && flood_proto){

		log_data[LOG_FLOOD_AT] = ALERT;
		ip_rec.flood_tracker = 0;
	}
	else{
		log_data[LOG_FLOOD_AT] = NONE;
	}
};

void log_info(){


};

void RecordTracker::insert_record(iphdr* ip_info){

	//map iterator pointing to the list iterator that points to the ip
	auto map_it = r_map.find(ip_info->saddr);

	uint32_t s_addr = ip_info->saddr;
	uint32_t d_addr = ip_info->daddr;
	uint16_t port = get_port(ip_info);

	if(map_it != r_map.end()){

		//list iterator pointing to the ip
		auto ip_r_ptr = map_it->second;

		//move node to the end of the list
		records.splice(records.end(), records, map_it->second);

		ip_r_ptr->dst_ip = s_addr;
		ip_r_ptr->dst_port = port;
		ip_r_ptr->proto = ip_info->protocol;

		ip_r_ptr->flood_tracker += 1;

		//check for size of the internal maps to protect against
		//flood-type attacks / scanns filling up memory without
		//increasing records.size()
		if(ip_r_ptr->dst_record[d_addr][port] < MAX_MAP_SIZE){

			ip_r_ptr->dst_record[d_addr][port] += 1;
		}

		if(ip_r_ptr->ports_record[port][d_addr] < MAX_MAP_SIZE){

			ip_r_ptr->ports_record[port][d_addr] += 1;
		}

		ip_r_ptr->last_seen = std::chrono::steady_clock::now();
	}
	else{

		//create local object
		ip_record ip_r;

		ip_r.ip = s_addr;
		ip_r.dst_ip = d_addr;
		ip_r.dst_port = port;
		ip_r.proto = ip_info->protocol;

		ip_r.flood_tracker = 1;
		ip_r.fld_notice = false;
		ip_r.fld_alert = false;

		ip_r.dst_record[d_addr][port] += 1;
		ip_r.ports_record[port][d_addr] += 1;

		ip_r.last_seen = std::chrono::steady_clock::now();

		//insert on the tracker data structures
		records.push_back(ip_r);
		r_map[ip_r.ip] = --records.end();

		rec_size += 1;
	}

}

void RecordTracker::update_records(){

	static int packet_counter = 0;
	static auto time_last_cleanup = std::chrono::steady_clock::now();

	auto time_now = std::chrono::steady_clock::now();
	packet_counter++;

	bool old_pck = true;

	//trigger the cleanup if we have processed 1000+ packages or if more than 1s has passed
	if(packet_counter >= 1000 || (time_now - time_last_cleanup) >= std::chrono::seconds(1)){

		while(!records.empty() && old_pck){

			auto last_seen_duration = time_now - records.front().last_seen;
			auto elapsed_sec = std::chrono::duration_cast<std::chrono::seconds>(last_seen_duration);

			if(std::chrono::duration<double>(elapsed_sec).count() > 5.0 || rec_size > MAX_REC_SIZE){

				r_map.erase(records.front().ip);
				records.pop_front();
			}
			else{
				old_pck = false;
			}
		}

		time_last_cleanup = time_now;
		packet_counter = 0;
	}
}

//i use initializer list because references cant be reassigned
RecordTracker::RecordTracker(std::ofstream &logfile, std::vector<ip_range> &_blacklist) : logf(logfile), blacklist(_blacklist) {

	rec_size = 0;
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
	ctx->r_track_ptr->update_records(); //internaly checks if it actually has to update the records
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
