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

uint16_t RecordTracker::get_port(iphdr* ip_bytes){

	//this is in 32-bit words so * 4 to get
	//iphdr length in bytes
	int ip_header_len = ip_bytes->ihl * 4;

	if(ip_bytes->protocol == IPPROTO_TCP){

		//                                   casting to a 1 byte primitive
		//                                   for pointer arithmetic
		struct tcphdr* tcp = (struct tcphdr*)((char*)ip_bytes + ip_header_len);
		return tcp->dest;
	}
	else if(ip_bytes->protocol == IPPROTO_UDP){

		struct udphdr* udp = (struct udphdr*)((char*)ip_bytes + ip_header_len);
		return udp->dest;
	}

	return 0;
}

void ip_record::eval_ip_record(std::vector<ip_range> &_blacklist, std::array<int, LOG_IP_SIZE> &log_data){

	//use this static values to not fill the logs once
	//it has been logged that a scan or flood attack is happening
	static int flood_tracker = 0;
	static int flood_alert = 0;
	static int vscan_alert = 0;
	static int hscan_alert = 0;

	int vscan_count = dst_record[dst_ip].size();
	int hscan_count = ports_record[dst_port].size();

	bool flood_proto = (proto == UDP || proto == ICMP);

	//blackisted ip
	if(find_ip(_blacklist, ip)){

		log_data[LOG_BLK_ADDR] = ALERT;
	}
	else{
		log_data[LOG_BLK_ADDR] = NONE;
	}

	//vertical scan
	if(vscan_count > MAX_VSCAN_CRI && vscan_alert < 3){

		log_data[LOG_IP_VSCAN] = CRITICAL;
		vscan_alert = 3;
	}
	else if(vscan_count > MAX_VSCAN_ALR && vscan_alert < 2){

		log_data[LOG_IP_VSCAN] = ALERT;
		vscan_alert = 2;
	}
	else if(vscan_count > MAX_VSCAN_NOT && vscan_alert < 1){

		log_data[LOG_IP_VSCAN] = NOTICE;
		vscan_alert = 1;
	}
	else{

		log_data[LOG_IP_VSCAN] = NONE;
		vscan_alert = 0;
	}

	//horizontal scan
	if(hscan_count > MAX_HSCAN_CRI && hscan_alert < 3){

		log_data[LOG_IP_HSCAN] = CRITICAL;
		hscan_alert = 3;
	}
	else if(hscan_count > MAX_HSCAN_ALR && hscan_alert < 2){

		log_data[LOG_IP_HSCAN] = ALERT;
		hscan_alert = 2;
	}
	else if(hscan_count > MAX_HSCAN_NOT && hscan_alert < 1){

		log_data[LOG_IP_HSCAN] = NOTICE;
		hscan_alert = 1;

	}
	else{

		log_data[LOG_IP_HSCAN] = NONE;
		hscan_alert = 0;
	}

	//flood attack
	if(flood_tracker > MAX_FLOOD_CRI && flood_proto && flood_alert < 3){

		log_data[LOG_FLOOD_AT] = CRITICAL;
		flood_alert = 2;
		flood_tracker = 0;

		//i reset the package counter but set the alert
		//flag to 2 so if the log stays on the tracked
		//it will only notify again after another MAX_FLOOD_CRI
		//amount of packages
	}
	else if(flood_tracker > MAX_FLOOD_ALR && flood_proto && flood_alert < 2){

		log_data[LOG_FLOOD_AT] = ALERT;
		flood_alert = 2;
	}
	else if(flood_tracker > MAX_FLOOD_NOT && flood_proto && flood_alert < 1){

		log_data[LOG_FLOOD_AT] = NOTICE;
		flood_alert = 1;
	}
	else{
		log_data[LOG_FLOOD_AT] = NONE;
	}

	flood_tracker += 1;
};

std::string_view ip_record::get_mesg(int log_code){

	switch(log_code){

		case LOG_BLK_ADDR: return " BLACKLISTED ADDR ";
		case LOG_IP_VSCAN: return " VSCAN DETECTED ";
		case LOG_IP_HSCAN: return " HSCAN DETECTED ";
		case LOG_FLOOD_AT: return " FLOOD DETECTED ";
	}

	return " UNKNOWN LOG CODE ";
}

std::string ip_record::build_log(int log_code, sv log_level, sv _msg_str, sv _src_str, sv _dst_str, sv _proto_str, int flood_count){

	std::stringstream log;

	switch(log_code){

		case LOG_BLK_ADDR:

			log << "\n" << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " PROTO: " << _proto_str <<
			" DPORT: " << ntohs(dst_port);
			break;

		case LOG_IP_VSCAN:

			log << "\n" << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " PROTO: " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " ON " << dst_record[dst_ip].size() << " PORTS";
			break;

		case LOG_IP_HSCAN:

			log << "\n" << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " PROTO: " << _proto_str <<
			" ON PORT " << ntohs(dst_port) << " TO " << ports_record[dst_port].size() << " ADDRESSES";
			break;

		case LOG_FLOOD_AT:

			log << "\n" << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " PROTO: " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " PCK RECIEVED " << flood_tracker_total;
			break;

	}

	return log.str();
}


void ip_record::log_ip_record(const std::array<int, LOG_IP_SIZE> &log_data){

					//maybe i have to cast this to int
	std::string proto_str = find_proto(proto);

	char s_ip_str_buf[INET_ADDRSTRLEN];
	char d_ip_str_buf[INET_ADDRSTRLEN];

	//pass to human readable (presentation)
	inet_ntop(AF_INET, &ip, s_ip_str_buf, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &dst_ip, d_ip_str_buf, INET_ADDRSTRLEN);

	//buffer for formatted presentaton ip/msg
	char src_str[32];
	char dst_str[32];
	char msg_str[128];

	//format it to a fixed size
	snprintf(src_str, sizeof(src_str), "%-15s", s_ip_str_buf);
	snprintf(dst_str, sizeof(dst_str), "%-15s", d_ip_str_buf);

	//i include none just so i dont have to do index + 1 and make it less confusing
	std::array<std::string, 4> log_levels = {"NONE", "NOTICE", "ALERT", "CRITICAL"};

	std::vector<std::string> log_mesgs;

	//i have to create this so the string returned from
	//get_mesg() is not temporary and when it gets converted into
	//a c-style string in snprintf() doesnt point to garbage
	std::string temp_msg;

	int log_code;


	if(log_data[LOG_BLK_ADDR]){

		log_code = LOG_BLK_ADDR;
		temp_msg = get_mesg(LOG_BLK_ADDR);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		//aqui ya esta mal TODO
		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str));
	}
	if(log_data[LOG_IP_VSCAN]){

		log_code = LOG_IP_VSCAN;
		temp_msg = get_mesg(LOG_IP_VSCAN);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str));
	}
	if(log_data[LOG_IP_HSCAN]){

		log_code = LOG_IP_HSCAN;
		temp_msg = get_mesg(LOG_IP_HSCAN);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str));
	}
	if(log_data[LOG_FLOOD_AT]){

		log_code = LOG_FLOOD_AT;
		temp_msg = get_mesg(LOG_FLOOD_AT);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str, flood_tracker_total));
	}

	for(auto log : log_mesgs){

		std::cout << log;
	}

};

ip_record& RecordTracker::insert_record(iphdr* ip_info){

	//map iterator pointing to the list iterator that points to the ip
	auto map_it = r_map.find(ip_info->saddr);

	uint32_t s_addr = ip_info->saddr;
	uint32_t d_addr = ip_info->daddr;
	uint16_t port = get_port(ip_info);

	if(map_it != r_map.end()){

		//list iterator pointing to the ip
		auto ip_rec = map_it->second;

		//move node to the end of the list
		records.splice(records.end(), records, ip_rec);

		ip_rec->dst_ip = d_addr;
		ip_rec->dst_port = port;
		ip_rec->proto = ip_info->protocol;

		ip_rec->flood_tracker_total += 1;

		ip_rec->dst_record[d_addr].insert(port);
		ip_rec->ports_record[port].insert(d_addr);

		ip_rec->last_seen = std::chrono::steady_clock::now();

		return *ip_rec;
	}
	else{

		//create local object
		ip_record ip_r;

		ip_r.ip = s_addr;
		ip_r.dst_ip = d_addr;
		ip_r.dst_port = port;
		ip_r.proto = ip_info->protocol;

		ip_r.flood_tracker_total = 0;

		ip_r.dst_record[d_addr].insert(port);
		ip_r.ports_record[port].insert(d_addr);

		ip_r.last_seen = std::chrono::steady_clock::now();

		//insert on the tracker data structures
		records.push_back(ip_r);

		auto new_iterator = --records.end();
		r_map[ip_r.ip] = new_iterator;

		rec_size += 1;

		return *new_iterator;
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

	//if this is ipv4
	if(ntohs(eth->h_proto) == ETH_P_IP){

		struct iphdr* ip = (struct iphdr*)(packet + ctx->header_offset);

		std::stringstream log_mesg;

		std::string protocol = find_proto((int)ip->protocol);

		std::array<int, LOG_IP_SIZE> log_data;

		//i think idc if it is ehternet at this point but maybe
		//im wrong and this crashes something
		ip_record &ip_rec = ctx->r_track_ptr->insert_record(ip);

		ip_rec.eval_ip_record(ctx->r_track_ptr->blacklist, log_data);
		ip_rec.log_ip_record(log_data);
		ctx->r_track_ptr->update_records(); //internaly checks if it actually has to update the records
	}

}
