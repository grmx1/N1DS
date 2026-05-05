#pragma once

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <cmath>
#include <unordered_set>
#include <fstream>
#include <unordered_set>
#include <stack>
#include <utility>
#include <arpa/inet.h>

#include <thread>
#include <chrono>

#define FLAG_IF "-i"
#define FLAG_BL "-b"

struct prefix_ip_range{

	int prefix;
	uint32_t net_ip;
};

struct ip_range{

	uint32_t big_e_net_ip;
	uint32_t big_e_mask;
};

//int validate_line(std::string _line, prefix_ip_range &_range);
int validate_line_syx(std::string _line, std::vector<prefix_ip_range> &ranges_vector);
void insert_addrs_from_range(const prefix_ip_range &range, std::unordered_set<uint32_t> &blacklist);
int parse_blacklist(std::string _blist_name, std::vector<ip_range> &_blacklist);


template<typename T>
void progress_bar(T idx, T start, T end, int width){

	//the formula for this mapping is, given 2 ranges (0 -> width) and (start -> end)
	//and a value(idx) to map
	//from the first range to the second:
	//	fst_r1 + (lst_range2 - fst_range2) * ((idx - fst_range1) / (lst_range1 - fst_range1))
	T mapped_value = width * ((double)(idx - start) / (double)(end - start));

	std::cout << "\r\033[K";
	std::cout << "[";
	for(int i = 0; i < width; i++){

		if(i < mapped_value){

			std::cout << "#";
		}
		else{
			std::cout << " ";
		}
	}
	std::cout << "]" << std::flush;
}

class Logger{

	public:

	static std::string timenow();
};

class ArgParser{

	public:

	struct {

		std::pair<bool, std::string> interface;
		std::pair<bool, std::string> blist_name;
	} flags;


	std::string help_mesg = 
	"\nusage: n1ds [-i interface][-b blacklist-path]\n\n"
	"       e.g n1ds -i eth0 -b /usr/share/blacklist.txt\n\n"
	"       blacklist format must be individual, new-line separated, CIDR address ranges\n"
	"       or individual ip addresses\n\n";

	std::stack<std::string> errors;

	ArgParser(int argc, char* argv[]);

	int flush_err();

	private:

	bool req_flags; // true if all required flags are set
	
	//checks if the flag comes with an argument
	int verifyFlag(int _idx, int _arc, std::string errmesg);

};
