#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <fstream>
#include <sstream>
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
#define MAX_VSCAN_ALR 40
#define MAX_VSCAN_CRI 80

#define MAX_HSCAN_NOT 10
#define MAX_HSCAN_ALR 20
#define MAX_HSCAN_CRI 50

#define MAX_FLOOD_NOT 1000
#define MAX_FLOOD_ALR 4000
#define MAX_FLOOD_CRI 8000

//IP log codes
#define LOG_BLK_ADDR 0 //blacklisted addrs
#define LOG_IP_VSCAN 1 //ip vertical scan
#define LOG_IP_HSCAN 2 //ip horizontal scan
#define LOG_FLOOD_AT 3 //flood-DoS attack
#define LOG_IP_SIZE 4

#define LOG_ARP_SCAN 4 //arp scan
#define LOG_ARP_POIS 5 //arp poisoning
#define LOG_ARP_SIZE

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

	RecordTracker* r_track_ptr;
};

//we will internally log this and keep
//them as long as their last seen is less
//than 5s ago

struct ip_record{

	uint32_t ip;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t proto;

	int flood_tracker_total;

	                  //ip                           //port    //count
	std::unordered_map<uint32_t, std::unordered_set<uint16_t>> dst_record;
	                  //port                         //ip      //count
	std::unordered_map<uint16_t, std::unordered_set<uint32_t>> ports_record;

	std::chrono::steady_clock::time_point last_seen;

	void eval_ip_record(std::vector<ip_range> &_blacklist, std::array<int, LOG_IP_SIZE> &log_data);
	void log_ip_record(const std::array<int, LOG_IP_SIZE> &log_data);
	std::string_view get_mesg(int log_code);

	using sv = std::string_view;
	std::string build_log(int log_code, sv log_level, sv _msg_str, sv _src_str, sv _dst_str, sv _proto_str, int flood_count = 0);
};

struct arp_record{

};

struct ip_log_params{

	int log_level[LOG_IP_SIZE];
	bool log_codes[LOG_IP_SIZE];
};

class RecordTracker{

	public:

	int rec_size;

	std::ofstream &logf;
	std::vector<ip_range> &blacklist;
	std::unordered_set<uint16_t> tracked_ports;

	ip_record& insert_record(iphdr* ip_info);

	void log_arp_info();
	void update_records();

	int records_size();

	RecordTracker(std::ofstream &logfile, std::vector<ip_range> &_blacklist);

	private:

	uint16_t get_port(iphdr* ip_bytes);

	std::list<ip_record> records;
	std::unordered_map<uint32_t, std::list<ip_record>::iterator> r_map;

};

void callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
