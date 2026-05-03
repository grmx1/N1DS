#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <fstream>
#include <sstream>
#include <utility>
#include <list>
#include <unordered_map>
#include <chrono>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "parser.hpp"

class RecordTracker;
struct Context{

	std::vector<ip_r>* blacklist_ptr;
	std::ofstream* logf;
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
	uint8_t proto;

	std::unordered_map<uint32_t, int> dst_record;
	std::unordered_map<uint16_t, int> ports_record;
	
	std::chrono::steady_clock::time_point last_seen;
};

struct arp_record{

};

class RecordTracker{

	public:

	void insert_record(iphdr* ip_info);
	void update_records();

	std::list<ip_record> records; //TEMPORARILY MAKING THIS PUBLIC FOR TESTING MAKE PRIVATE AFTER ( ill forget ab this for 20 pushes )

	private:

	uint16_t get_port(iphdr* ip_info);

	void log_alert();
	void log_notice();

	//std::list<ip_record> records;
	std::unordered_map<uint32_t, std::list<ip_record>::iterator> r_map;
};

void callback(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
