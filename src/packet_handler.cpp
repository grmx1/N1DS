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

	int vscan_count = dst_record[dst_ip].size();
	int hscan_count = ports_record[dst_port].size();

	/*
	char s_ip_str_buf[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &ip, s_ip_str_buf, INET_ADDRSTRLEN);

	if(strcmp(s_ip_str_buf, "192.168.1.147") == 0){

		std::cout << "match" << std::endl;
		std::cout << "VSCAN COUNT: " << vscan_count << std::endl;
		std::cout << "HSCAN COUNT: " << hscan_count << " port: " << ntohs(dst_port) << std::endl;
		std::cout << std::endl;

	}
	*/
	//blackisted ip
	if(find_ip(_blacklist, ip)){

		log_data[LOG_BLK_ADDR] = ALERT;
	}
	else{
		log_data[LOG_BLK_ADDR] = NONE;
	}

	//vertical scan
	if((vscan_count > MAX_VSCAN_CRI && vscan_cri == false) || ((vscan_count - last_vscan_log) > MAX_VSCAN_CRI)){

		log_data[LOG_IP_VSCAN] = CRITICAL;
		vscan_cri = true;
		last_vscan_log = vscan_count;
	}
	else if(vscan_count > MAX_VSCAN_ALR && vscan_alr == false){

		log_data[LOG_IP_VSCAN] = ALERT;
		vscan_alr = true;
	}
	else if(vscan_count > MAX_VSCAN_NOT && vscan_not == false){

		log_data[LOG_IP_VSCAN] = NOTICE;
		vscan_not = true;
	}
	else{

		log_data[LOG_IP_VSCAN] = NONE;
	}

	//horizontal scan
	if(hscan_count > MAX_HSCAN_CRI){

		log_data[LOG_IP_HSCAN] = CRITICAL;
		hscan_cri = true;
		last_hscan_log = hscan_count;
	}
	else if(hscan_count > MAX_HSCAN_ALR){

		log_data[LOG_IP_HSCAN] = ALERT;
		hscan_alr = true;
	}
	else if(hscan_count > MAX_HSCAN_NOT){

		log_data[LOG_IP_HSCAN] = NOTICE;
		hscan_not = true;
	}
	else{

		log_data[LOG_IP_HSCAN] = NONE;
	}


	/*
	//horizontal scan
	if((hscan_count > MAX_HSCAN_CRI && hscan_cri == false) || ((hscan_count - last_hscan_log) > MAX_HSCAN_CRI)){

		log_data[LOG_IP_HSCAN] = CRITICAL;
		hscan_cri = true;
		last_hscan_log = hscan_count;
	}
	else if(hscan_count > MAX_HSCAN_ALR && hscan_alr == false){

		log_data[LOG_IP_HSCAN] = ALERT;
		hscan_alr = true;
	}
	else if(hscan_count > MAX_HSCAN_NOT && hscan_not == false){

		log_data[LOG_IP_HSCAN] = NOTICE;
		hscan_not = true;
	}
	else{

		log_data[LOG_IP_HSCAN] = NONE;
	}
*/

	//SYN flood attack
	if(syn_window_count > MAX_FLOOD_CRI && syn_flood_cri == false){

		log_data[LOG_FLOOD_SYN] = CRITICAL;
		syn_flood_cri = true;
	}
	else if(syn_window_count > MAX_FLOOD_ALR && syn_flood_alr == false){

		log_data[LOG_FLOOD_SYN] = ALERT;
		syn_flood_alr = true;
	}
	else if(syn_window_count > MAX_FLOOD_NOT && syn_flood_not == false){

		log_data[LOG_FLOOD_SYN] = NOTICE;
		syn_flood_not = true;
	}
	else{
		log_data[LOG_FLOOD_SYN] = NONE;
	}

	//SYN+ACK flood attack
	if(syn_ack_window_count > MAX_FLOOD_CRI && syn_ack_flood_cri == false){

		log_data[LOG_FLOOD_SACK] = CRITICAL;
		syn_ack_flood_cri = true;
	}
	else if(syn_ack_window_count > MAX_FLOOD_ALR && syn_ack_flood_alr == false){

		log_data[LOG_FLOOD_SACK] = ALERT;
		syn_ack_flood_alr = true;
	}
	else if(syn_ack_window_count > MAX_FLOOD_NOT && syn_ack_flood_not == false){

		log_data[LOG_FLOOD_SACK] = NOTICE;
		syn_ack_flood_not = true;
	}
	else{
		log_data[LOG_FLOOD_SACK] = NONE;
	}

	//UNVERIFIED flood attack
	if(unv_window_count > MAX_FLOOD_CRI && unv_flood_cri == false){

		log_data[LOG_FLOOD_UNV] = CRITICAL;
		unv_flood_cri = true;
	}
	else if(unv_window_count > MAX_FLOOD_ALR && unv_flood_alr == false){

		log_data[LOG_FLOOD_UNV] = ALERT;
		unv_flood_alr = true;
	}
	else if(unv_window_count > MAX_FLOOD_NOT && unv_flood_not == false){

		log_data[LOG_FLOOD_UNV] = NOTICE;
		unv_flood_not = true;
	}
	else{
		log_data[LOG_FLOOD_UNV] = NONE;
	}
};

std::string_view ip_record::get_mesg(int log_code){

	switch(log_code){

		case LOG_BLK_ADDR: return " BLACKLISTED ADDR ";
		case LOG_IP_VSCAN: return " VSCAN DETECTED ";
		case LOG_IP_HSCAN: return " HSCAN DETECTED ";
		case LOG_FLOOD_SYN: return " SYN FLOOD DETECTED ";
		case LOG_FLOOD_SACK: return " SYN-ACK FLOOD DETECTED";
		case LOG_FLOOD_UNV: return " UNVERIFIED FLOOD DETECTED";
	}

	return " UNKNOWN LOG CODE ";
}

std::string ip_record::build_log(int log_code, sv log_level, sv _msg_str, sv _src_str, sv _dst_str, sv _proto_str, int flood_count){

	std::stringstream log;

	switch(log_code){

		case LOG_BLK_ADDR:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << "\n" ;
			break;

		case LOG_IP_VSCAN:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " ON " << dst_record[dst_ip].size() << " (observed)PORTS" << "\n" ;
			break;

		case LOG_IP_HSCAN:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" ON PORT " << ntohs(dst_port) << " TO " << ports_record[dst_port].size() << " ADDRESSES" << "\n" ;
			break;

		case LOG_FLOOD_SYN:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " PCK RECIEVED " << syn_count << "\n" ;
			break;

		case LOG_FLOOD_SACK:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " PCK RECIEVED " << syn_ack_count << "\n" ;
			break;

		case LOG_FLOOD_UNV:

			log << "[" << log_level << "] " << Logger::timenow() << _msg_str <<
			" SRC: " << _src_str << " DST: " << _dst_str << " " << _proto_str <<
			" DPORT: " << ntohs(dst_port) << " PCK RECIEVED " << unv_count << "\n" ;
			break;

	}

	return log.str();
}

void RecordTracker::print_conn_table(){

	std::array<std::string, 3> status_str = {"UNVERIFIED", "SYN_OPEN", "VERIFIED"};

	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];

	std::cout << "\033[2J\033[H";
	std::cout << " CONN TABLE: " << std::endl;
	for(auto src : conn_table){

		inet_ntop(AF_INET, &src.first, src_str, INET_ADDRSTRLEN);

		for(auto dst : src.second){

			inet_ntop(AF_INET, &dst.first, dst_str, INET_ADDRSTRLEN);

			std::cout << "\n" << "    " << src_str << " :" << ntohs(dst.second.s_port) << " --> " << dst_str << " :" << ntohs(dst.second.d_port) << " " << status_str[static_cast<int>(dst.second.state)];
		}

		std::cout << std::endl << std::endl;
	}

}

void ip_record::log_ip_record(const std::array<int, LOG_IP_SIZE> &log_data){

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

		//aqui ya esta mal //TODO //no se que mierda es este comentario
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
	if(log_data[LOG_FLOOD_SYN]){

		log_code = LOG_FLOOD_SYN;
		temp_msg = get_mesg(LOG_FLOOD_SYN);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str, syn_count));
	}
	if(log_data[LOG_FLOOD_SACK]){

		log_code = LOG_FLOOD_SACK;
		temp_msg = get_mesg(LOG_FLOOD_SACK);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str, syn_ack_count));
	}
	if(log_data[LOG_FLOOD_UNV]){

		log_code = LOG_FLOOD_UNV;
		temp_msg = get_mesg(LOG_FLOOD_UNV);
		snprintf(msg_str, sizeof(msg_str), "%-15s", temp_msg);

		log_mesgs.push_back(build_log(log_code, log_levels[log_data[log_code]], temp_msg.c_str(), src_str, dst_str, proto_str, unv_count));
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

		return conn_table[src][dst].state == TCPSTATE::VERIFIED;
	}
	else if(conn_table.count(dst) && conn_table[dst].count(src)){

		return conn_table[dst][src].state == TCPSTATE::VERIFIED;
	}

	return 0;
}

void RecordTracker::remove_conn(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port){

	bool exists_entry_src = (conn_table.count(src_addr) && conn_table[src_addr].count(dst_addr) && conn_table[src_addr][dst_addr].s_port == src_port && conn_table[src_addr][dst_addr].d_port == dst_port);
	bool exists_entry_dst = (conn_table.count(dst_addr) && conn_table[dst_addr].count(src_addr) && conn_table[dst_addr][src_addr].s_port == src_port && conn_table[dst_addr][src_addr].d_port == dst_port);

	if(exists_entry_src){

		conn_table[src_addr].erase(dst_addr);

		if(conn_table[src_addr].size() == 0){

			conn_table.erase(src_addr);
		}
	}
	else if(exists_entry_dst){

		conn_table[dst_addr].erase(src_addr);

		if(conn_table[dst_addr].size() == 0){

			conn_table.erase(dst_addr);
		}
	}
}

ip_record& RecordTracker::insert_record(iphdr* ip_info, tcphdr* tcp_info, udphdr* udp_info){

	//map iterator pointing to the list iterator that points to the ip
	auto map_it = r_map.find(ip_info->saddr);
	bool existing = (map_it != r_map.end());

	uint32_t s_addr = ip_info->saddr;
	uint32_t d_addr = ip_info->daddr;
	uint16_t s_port = 0;
	uint16_t d_port = 0;
	uint8_t flags = 0;

	if(tcp_info){

		s_port = tcp_info->source;
		d_port = tcp_info->dest;
		flags = tcp_info->th_flags;
	}
	else if(udp_info){

		s_port = udp_info->source;
		d_port = udp_info->dest;
	}

	uint16_t hs_d_port = ntohs(d_port);

	if(existing == false){

		//create local object
		ip_record ip_r;

		ip_r.ip = s_addr;
		ip_r.dst_ip = d_addr;
		ip_r.dst_port = d_port;
		ip_r.proto = ip_info->protocol;

		ip_r.syn_count = 0;
		ip_r.unv_count = 0;
		ip_r.syn_ack_count = 0;

		ip_r.dst_record[d_addr].insert(d_port);
		ip_r.ports_record[d_port].insert(d_addr);

		ip_r.syn_window_start = std::chrono::steady_clock::now();
		ip_r.syn_ack_window_start = std::chrono::steady_clock::now();
		ip_r.unv_window_start = std::chrono::steady_clock::now();
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
	ip_rec->dst_port = d_port;
	ip_rec->proto = ip_info->protocol;

	//ip_rec->flood_tracker_total += 1;

	//check only for system ports to prevent false positives
	if(hs_d_port < 1024 || tracked_ports.count(hs_d_port)){

		ip_rec->dst_record[d_addr].insert(d_port);
	}
	ip_rec->ports_record[d_port].insert(d_addr);

	//check for flags
	if((flags & TH_SYN) && !(flags & TH_ACK)){

		//we register that s_addr is waiting
		//for SYN ACK from d_addr

		//prevent SYN flood from filling up memory
		if(conn_table[s_addr].size() < 500){

			conn_table[s_addr][d_addr].state = TCPSTATE::SYN_OPEN;
			conn_table[s_addr][d_addr].s_port = s_port;
			conn_table[s_addr][d_addr].d_port = d_port;
		}

		auto now = std::chrono::steady_clock::now();
		auto elapsed_last_syn = std::chrono::duration_cast<std::chrono::seconds>(now - ip_rec->syn_window_start).count();

		if(elapsed_last_syn >= 1){
			ip_rec->syn_window_start = now;
			ip_rec->syn_flood_cri = false;
			ip_rec->syn_window_count = 0;
		}

		ip_rec->syn_window_count += 1;
		ip_rec->syn_count += 1;
	}
	else if((flags & TH_SYN) && (flags & TH_ACK)){

		//if it is SYN+ACK we look in the list
		//if d_addr is waiting for such connection
		if(is_waiting(s_addr, d_addr)){

			//update state
			conn_table[d_addr][s_addr].state = TCPSTATE::VERIFIED;

		}
		else{

			auto now = std::chrono::steady_clock::now();
			auto elapsed_last_syn_ack = std::chrono::duration_cast<std::chrono::seconds>(now - ip_rec->syn_ack_window_start).count();

			if(elapsed_last_syn_ack >= 1){
				ip_rec->syn_ack_window_start = now;
				ip_rec->syn_ack_flood_cri = false;
				ip_rec->syn_ack_window_count = 0;
			}

			ip_rec->syn_ack_window_count += 1;
			ip_rec->syn_ack_count += 1;
		}
	}
	else if(!is_verified(s_addr, d_addr)){ // i should also check for this on new records

		auto now = std::chrono::steady_clock::now();
		auto elapsed_last_unv = std::chrono::duration_cast<std::chrono::seconds>(now - ip_rec->unv_window_start).count();

		if(elapsed_last_unv >= 1){
			ip_rec->unv_window_start = now;
			ip_rec->unv_flood_cri = false;
			ip_rec->unv_window_count = 0;
		}

		ip_rec->unv_window_count += 1;
		ip_rec->unv_count += 1;
	}

	if((flags & TH_RST) || (flags & TH_FIN)){

		remove_conn(s_addr, d_addr, s_port, d_port);
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
	if(eth && ntohs(eth->h_proto) == ETH_P_IP){

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

		std::array<int, LOG_IP_SIZE> log_data = {0};

		//i think idc if it is ehternet at this point but maybe
		//im wrong and this crashes something
		ip_record &ip_rec = ctx->r_track_ptr->insert_record(ip, tcp, udp);

		ip_rec.eval_ip_record(ctx->r_track_ptr->blacklist, log_data, tcp, udp);
		if(ctx->print_stdout && !ctx->show_conn){

			ip_rec.log_ip_record(log_data);
		}
		if(ctx->show_conn){

			ctx->r_track_ptr->print_conn_table();
		}
		ctx->r_track_ptr->update_records(); //internaly checks if it actually has to update the records
	}

}
