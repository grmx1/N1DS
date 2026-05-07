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

//maybe not need tcphdr and udphdr here
void ip_record::eval_ip_record(std::vector<ip_range> &_blacklist, std::array<int, LOG_IP_SIZE> &log_data, tcphdr* tcp_info, udphdr* udp_info){

	//use this static values to not fill the logs once
	//it has been logged that a scan or flood attack is happening
	static int syn_flood_alert = 0;
	static int syn_ack_flood_alert = 0;
	static int unv_flood_alert = 0;
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

	//SYN flood attack
	if(syn_count > MAX_FLOOD_CRI && flood_proto && syn_flood_alert < 3){

		log_data[LOG_FLOOD_AT] = CRITICAL;
		syn_flood_alert = 2;
		syn_count = 0;

		//i reset the package counter but set the alert
		//flag to 2 so if the log stays on the tracked
		//it will only notify again after another MAX_FLOOD_CRI
		//amount of packages
	}
	else if(syn_count > MAX_FLOOD_ALR && flood_proto && syn_flood_alert < 2){

		log_data[LOG_FLOOD_AT] = ALERT;
		syn_flood_alert = 2;
	}
	else if(syn_count > MAX_FLOOD_NOT && flood_proto && syn_flood_alert < 1){

		log_data[LOG_FLOOD_AT] = NOTICE;
		syn_flood_alert = 1;
	}
	else{
		log_data[LOG_FLOOD_AT] = NONE;
	}

	//SYN+ACK flood attack
	if(syn_ack_count > MAX_FLOOD_CRI && flood_proto && syn_ack_flood_alert < 3){

		log_data[LOG_FLOOD_AT] = CRITICAL;
		syn_ack_flood_alert = 2;
		syn_ack_count = 0;
	}
	else if(syn_ack_count > MAX_FLOOD_ALR && flood_proto && syn_ack_flood_alert < 2){

		log_data[LOG_FLOOD_AT] = ALERT;
		syn_ack_flood_alert = 2;
	}
	else if(syn_ack_count > MAX_FLOOD_NOT && flood_proto && syn_ack_flood_alert < 1){

		log_data[LOG_FLOOD_AT] = NOTICE;
		syn_ack_flood_alert = 1;
	}
	else{
		log_data[LOG_FLOOD_AT] = NONE;
	}

	//UNVERIFIED flood attack
	if(unv_count > MAX_FLOOD_CRI && flood_proto && unv_flood_alert < 3){

		log_data[LOG_FLOOD_AT] = CRITICAL;
		unv_flood_alert = 2;
		unv_count = 0;
	}
	else if(unv_count > MAX_FLOOD_ALR && flood_proto && unv_flood_alert < 2){

		log_data[LOG_FLOOD_AT] = ALERT;
		unv_flood_alert = 2;
	}
	else if(unv_count > MAX_FLOOD_NOT && flood_proto && unv_flood_alert < 1){

		log_data[LOG_FLOOD_AT] = NOTICE;
		unv_flood_alert = 1;
	}
	else{
		log_data[LOG_FLOOD_AT] = NONE;
	}
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
			" DPORT: " << ntohs(dst_port) << " PCK RECIEVED " << flood_count;
			break;

	}

	return log.str();
}

void RecordTracker::print_conn_table(){

	std::array<std::string, 3> status_str = {"UNVERIFIED", "SYN_OPEN", "VERIFIED"};

	char d_ip_str_buf[INET_ADDRSTRLEN];
	char s_ip_str_buf[INET_ADDRSTRLEN];

	//buffer for formatted presentaton ip/msg
	char src_str[32];
	char dst_str[32];

	for(auto src : conn_table){

		inet_ntop(AF_INET, &src.first, s_ip_str_buf, INET_ADDRSTRLEN);
		snprintf(src_str, sizeof(src_str), "%-15s", s_ip_str_buf);

		std::cout << src_str << " connections: " << std::endl;

		for(auto dst : src.second){

			inet_ntop(AF_INET, &dst.first, d_ip_str_buf, INET_ADDRSTRLEN);
			snprintf(dst_str, sizeof(dst_str), "%-15s", d_ip_str_buf);

			std::cout << "\n" << "    " << dst_str << " -- state -> " << status_str[static_cast<int>(dst.second)];
		}

		std::cout << std::endl << std::endl;
	}

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

		//VERY IMPORTANT
		//i have to create new entries on this if statement
		//to account for different flood types of attacks as
		//now im sending the flood counter as SYN
		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str, syn_count));
	}

	for(auto log : log_mesgs){

		std::cout << log;
	}
};

int RecordTracker::is_waiting(uint32_t src, uint32_t dst){

	if(conn_table.count(dst) && conn_table[dst].count(src)){

		return 1;
	}

	return 0;
}

int RecordTracker::is_verified(uint32_t src, uint32_t dst){

	if(conn_table.count(src) && conn_table[src].count(dst)){

		return conn_table[src][dst] == TCPSTATE::VERIFIED;
	}
	else if(conn_table.count(dst) && conn_table[dst].count(src)){

		return conn_table[dst][src] == TCPSTATE::VERIFIED;
	}

	return 0;
}

void RecordTracker::remove_conn(uint32_t src, uint32_t dst){

	if(conn_table.count(src) && conn_table[src].count(dst)){

		conn_table[src].erase(dst);

		if(conn_table[src].size() == 0){

			conn_table.erase(src);
		}
	}
	else if(conn_table.count(dst) && conn_table[dst].count(src)){

		conn_table[dst].erase(src);

		if(conn_table[dst].size() == 0){

			conn_table.erase(dst);
		}
	}
}

ip_record& RecordTracker::insert_record(iphdr* ip_info, tcphdr* tcp_info, udphdr* udp_info){

	//map iterator pointing to the list iterator that points to the ip
	auto map_it = r_map.find(ip_info->saddr);
	bool existing = (map_it != r_map.end());

	uint32_t s_addr = ip_info->saddr;
	uint32_t d_addr = ip_info->daddr;
	uint16_t port = 0;
	uint8_t flags = 0;

	if(tcp_info){

		port = tcp_info->dest;
		flags = tcp_info->th_flags;
	}
	else if(udp_info){

		port = udp_info->dest;
	}

	uint16_t hs_port = ntohs(port);

	if(existing == false){

		//create local object
		ip_record ip_r;

		ip_r.ip = s_addr;
		ip_r.dst_ip = d_addr;
		ip_r.dst_port = port;
		ip_r.proto = ip_info->protocol;

		//do i initialize this as 0 ?
		ip_r.syn_count = 0;
		ip_r.unv_count = 0;
		ip_r.syn_ack_count = 0;
		//ip_r.flood_tracker_total = 0;

		ip_r.dst_record[d_addr].insert(port);
		ip_r.ports_record[port].insert(d_addr);

		ip_r.last_seen = std::chrono::steady_clock::now();

		//insert on the tracker data structures
		records.push_back(ip_r);

		auto new_list_iterator = --records.end();
		auto result = r_map.insert({ip_r.ip, new_list_iterator});

		map_it = result.first;

		rec_size += 1;
	}

	//list iterator pointing to the ip
	auto ip_rec = map_it->second;

	if(existing){

		//move node to the end of the list
		records.splice(records.end(), records, ip_rec);
	}

	ip_rec->dst_ip = d_addr;
	ip_rec->dst_port = port;
	ip_rec->proto = ip_info->protocol;

	//ip_rec->flood_tracker_total += 1;

	//check only for system ports to prevent false positives
	if(hs_port < 1024 || tracked_ports.count(hs_port)){

		ip_rec->dst_record[d_addr].insert(port);
	}
	ip_rec->ports_record[port].insert(d_addr);

	//check for flags
	if((flags & TH_SYN) && !(flags & TH_ACK)){

		//we register that s_addr is waiting
		//for SYN ACK from d_addr

		//prevent SYN flood from filling up memory
		if(conn_table[s_addr].size() < 500){

			conn_table[s_addr][d_addr] = TCPSTATE::SYN_OPEN;
		}

		ip_rec->syn_count += 1;
	}
	else if((flags & TH_SYN) && (flags & TH_ACK)){

		//if it is SYN+ACK we look in the list
		//if d_addr is waiting for such connection
		if(is_waiting(s_addr, d_addr)){

			//update state
			conn_table[d_addr][s_addr] = TCPSTATE::VERIFIED;

			//reset counters for both addr
			ip_rec->syn_count = 0;
			ip_rec->unv_count = 0;
			ip_rec->syn_ack_count = 0;

			r_map[d_addr]->syn_count = 0;
			r_map[d_addr]->unv_count = 0;
			r_map[d_addr]->syn_ack_count = 0;

		}
		else{
			ip_rec->syn_ack_count += 1;
		}
	}
	else if(!is_verified(s_addr, d_addr)){ // i should also check for this on new records

		ip_rec->unv_count += 1;
	}

	if((flags & TH_RST) || (flags & TH_FIN)){

		remove_conn(s_addr, d_addr);
	}

	ip_rec->last_seen = std::chrono::steady_clock::now();

	return *ip_rec;

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
RecordTracker::RecordTracker(std::ofstream &logfile, std::vector<ip_range> &_blacklist) : 
	logf(logfile),
	blacklist(_blacklist),
	tracked_ports({

		//databases
		3306, 5432, 6379, 27017, 1433, 1434,
		//remote access
		3389, 5900, 5901, 5902, 5903, 8080, 8443,
		//Development
		2375, 2376, 9000, 9200, 9300, 8000, 8888,
		//Internal services
		2049, 5000, 111
	}){

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

		struct tcphdr* tcp = nullptr;
		struct udphdr* udp = nullptr;

		uint16_t port = 0;

		//ts is in 32bit words * 4 to get bytes
		int ip_hdr_length = ip->ihl * 4;

		if(ip->protocol == IPPROTO_TCP){

			tcp = (struct tcphdr*)((char*)ip + ip_hdr_length);
			port = tcp->dest;
		}
		else if(ip){

			udp = (struct udphdr*)((char*)ip + ip_hdr_length);
			port = udp->dest;
		}


		std::stringstream log_mesg;

		std::string protocol = find_proto((int)ip->protocol);

		std::array<int, LOG_IP_SIZE> log_data;

		//i think idc if it is ehternet at this point but maybe
		//im wrong and this crashes something
		ip_record &ip_rec = ctx->r_track_ptr->insert_record(ip, tcp, udp);

		ip_rec.eval_ip_record(ctx->r_track_ptr->blacklist, log_data, tcp, udp);
		//ip_rec.log_ip_record(log_data);
		ctx->r_track_ptr->print_conn_table();
		ctx->r_track_ptr->update_records(); //internaly checks if it actually has to update the records
	}

}
