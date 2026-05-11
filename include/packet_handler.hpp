#pragma once

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <utility>
#include <list>
#include <array>
#include <string_view>
#include <unordered_map>
#include <chrono>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "parser.hpp"

//max sizes
#define MAX_REC_SIZE 1e5 //100k max items before update
#define MAX_MAP_SIZE 500

#define MAX_VSCAN_NOT 20
#define MAX_VSCAN_ALR 50
#define MAX_VSCAN_CRI 200

#define MAX_HSCAN_NOT 10
#define MAX_HSCAN_ALR 20
#define MAX_HSCAN_CRI 40

#define MAX_FLOOD_NOT 2000
#define MAX_FLOOD_ALR 8000
#define MAX_FLOOD_CRI 20000

//IP log codes
#define LOG_BLK_ADDR 0 //blacklisted addrs
#define LOG_IP_VSCAN 1 //ip vertical scan
#define LOG_IP_HSCAN 2 //ip horizontal scan
#define LOG_FLOOD_SYN 3 //syn-flood
#define LOG_FLOOD_SACK 4 //syn-ack-flood
#define LOG_FLOOD_UNV 5 //not verified flood
#define LOG_IP_SIZE 6

//log level
#define NONE 0
#define NOTICE 1
#define ALERT 2
#define CRITICAL 3

//protocols
#define ICMP 1
#define ICP 6
#define UDP 17
#define IGMP 2
#define SCTP 132
#define GRE 47

int find_ip(const std::vector<ip_range> &_blacklist, uint32_t addr);

class RecordTracker;
struct Context{

	std::string interface;
	int link_type;
	int header_offset;

	bool show_conn;
	bool print_stdout;

	RecordTracker* r_track_ptr;
};

//we will internally log this and keep
//them as long as their last seen is less
//than 5s ago

enum class TCPSTATE {

	UNVERIFIED,
	SYN_OPEN,
	VERIFIED
};

struct conn_table_data{

	TCPSTATE state;
	uint16_t s_port;
	uint16_t d_port;

};

struct ip_record{

	uint32_t ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t proto;

	int syn_count;
	int unv_count;
	int syn_ack_count;

	int syn_window_count;
	int unv_window_count;
	int syn_ack_window_count;

	                  //ip                           //port    //count
	std::unordered_map<uint32_t, std::unordered_set<uint16_t>> dst_record;
	                  //port                         //ip      //count
	std::unordered_map<uint16_t, std::unordered_set<uint32_t>> ports_record;

	std::chrono::steady_clock::time_point last_seen;

	std::chrono::steady_clock::time_point syn_window_start;
	std::chrono::steady_clock::time_point unv_window_start;
	std::chrono::steady_clock::time_point syn_ack_window_start;

	bool syn_flood_not = false;
	bool syn_flood_alr = false;
	bool syn_flood_cri = false;

	bool syn_ack_flood_not = false;
	bool syn_ack_flood_alr = false;
	bool syn_ack_flood_cri = false;

	bool unv_flood_not = false;
	bool unv_flood_alr = false;
	bool unv_flood_cri = false;


	void eval_ip_record(std::vector<ip_range> &_blacklist, std::array<int, LOG_IP_SIZE> &log_data, tcphdr* tcp_info, udphdr* udp_info);
	void log_ip_record(const std::array<int, LOG_IP_SIZE> &log_data, std::ofstream &logf, bool stdout);
	std::string_view get_mesg(int log_code);

	using sv = std::string_view;
	std::string build_log(int log_code, sv log_level, sv _msg_str, sv _src_str, sv _dst_str, sv _proto_str, int flood_count = 0);

	private:

	bool vscan_not = false;
	bool vscan_alr = false;
	bool vscan_cri = false;

	bool hscan_not = false;
	bool hscan_alr = false;
	bool hscan_cri = false;

	int last_vscan_log = 0;
	int last_hscan_log = 0;

};

//am i using this ?
struct ip_log_params{

	int log_level[LOG_IP_SIZE];
	bool log_codes[LOG_IP_SIZE];
};


class RecordTracker{

	public:

	int rec_size;

	std::ofstream &logf;
	std::vector<ip_range> &blacklist;
	std::unordered_set<uint16_t> tracked_ports; //ports higher than 1023 that are
	                                            //sensitive to be scanned

	ip_record& insert_record(iphdr* ip_info, tcphdr* tcp_info, udphdr* udp_info);

	void log_arp_info();
	void update_records();

	int records_size();

	RecordTracker(std::ofstream &logfile, std::vector<ip_range> &_blacklist);

	void print_conn_table();

	private:

	int is_waiting(uint32_t src, uint32_t dst);
	int is_verified(uint32_t src, uint32_t dst);
	void remove_conn(uint32_t src_addr, uint32_t dst_addr, uint16_t src_port, uint16_t dst_port);

	std::list<ip_record> records;
	std::unordered_map<uint32_t, std::list<ip_record>::iterator> r_map;

	//                opener_ip                   reciever_ip  state
	std::unordered_map<uint32_t, std::unordered_map<uint32_t, conn_table_data>> conn_table;

};

void callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
