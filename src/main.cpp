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
	std::unordered_set<uint32_t> blacklist;

	int validate_bl = parse_blacklist(clargs.flags.blist_name.second, blacklist);

	if(validate_bl == 1){

		return 1;
	}

	//i will use this co calculate header_offset
	int linktype = pcap_datalink(nm.session);

	Context ctx;
	ctx.blacklist_ptr = &blacklist;
	ctx.logf = &logfile;
	ctx.interface = clargs.flags.interface.second;
	ctx.link_type = linktype;
	ctx.header_offset = nm.get_header_offset(linktype);

	pcap_loop(nm.session, INF_PCAP_LOOP, pck_handler, (u_char*)&ctx);
	//i need to write the callback func and the txt parser to pass both things to pcap_loop();

	return 0;
}
