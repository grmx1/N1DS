#include <iostream>
#include <pcap/pcap.h>
#include <unordered_set>

#include "parser.hpp"
#include "packet_handler.hpp"
#include "net_manager.hpp"

#define INF_PCAP_LOOP -1

int main(int argc, char* argv[]){

	std::ofstream logfile("/var/log/alerts.log");

	if(!logfile.is_open()){

		std::cerr << "ERR: File {/var/log/alerts.log} could not be opened" << std::endl;
		return 1;
	}

	//command line args
	ArgParser clargs(argc, argv);
	if(clargs.flush_err()){

		return 1;
	}

	NetManager nm(clargs);
	nm.init();

	//black listed ip addresses
	std::vector<ip_range> blacklist;

	RecordTracker r_track(logfile, blacklist);


	if(clargs.flags.blist_name.first){

		int validate_bl = parse_blacklist(clargs.flags.blist_name.second, blacklist);

		if(validate_bl == 1){

			return 1;
		}
	}

	//i will use this co calculate header_offset
	int linktype = pcap_datalink(nm.session);

	Context ctx;
	ctx.interface = clargs.flags.interface.second;
	ctx.link_type = linktype;
	ctx.header_offset = nm.get_header_offset(linktype);
	ctx.r_track_ptr = &r_track;

	pcap_loop(nm.session, INF_PCAP_LOOP, callback, (u_char*)&ctx);

	return 0;
}
