#include "net_manager.hpp"

NetManager::NetManager(const ArgParser &_clargs){

	session = nullptr;

	if(_clargs.flags.interface.first)
		input.if_target = _clargs.flags.interface.second;

}

NetManager::~NetManager(){

	if(session != nullptr)
		pcap_close(session);
}

int NetManager::init(){

	pcap_if_t* alldevs;
	if(pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR){

		std::cerr << "ERROR: " << errbuf << std::endl;
		std::cerr << "exiting..." << std::endl;

		return 1;
	}

	pcap_if_t* dev = alldevs;

	bool if_exists = false;

	//check if inputted ifce matches a real ifce
	while(dev != nullptr && !if_exists){

		if(dev->name == input.if_target)
			if_exists = true;

		dev = dev->next;
	}

	//the interface not existing gets handled automatically by the error produced
	//on the session being nullptr
	
	session = pcap_open_live(input.if_target.c_str(), 65535, 1, 1000, errbuf);

	if(session == nullptr){
		
		std::cerr << "ERR: " << errbuf << std::endl;
	}

	return 0;
}

int NetManager::get_header_offset(int link_type){

	int offset;

	switch(link_type){

		case DLT_EN10MB:
			offset = 14;
			break;

		case DLT_LINUX_SLL:
			offset = 16;
			break;

		case DLT_RAW:
		case DLT_NULL:
			offset = 0;
			break;

		default:
			offset = 14;
	}

	return offset;
}
