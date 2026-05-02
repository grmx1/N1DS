#include "parser.hpp"

int validate_line_syx(std::string _line, std::vector<ip_range> &ranges_vector){

	ip_range range_container;

	int dots = 0; //needs to reach 3
	int fw_slash = 0;
	int chunk_size = 0; //cant be bigger than 2 ( 0 - 1 - 2)
	int chunk_val = 0;
	int mask = 0; //must range 0-32
	
	int cur_char;

	uint32_t address;

	std::string chunk_val_str = ""; // cant be bigger than 255
	std::string address_str = "";

	int return_error = 0;

	for(int i = 0; i < _line.size() && !return_error; i++){

		cur_char = _line[i];

		//commented line so we exit flagging to ignore the line
		if(cur_char == '#'){
			return_error = -1;
		}
		else if(fw_slash){

			if(cur_char > 47 && cur_char < 58){

				chunk_val_str += cur_char;
				chunk_size++;
			}

			if(i + 1 == _line.size()){

				for(int j = 0; j < chunk_size; j++){

					chunk_val += (chunk_val_str[j] - 48) * std::pow(10, chunk_size - 1 - j);
				}
			}

			if(chunk_val > 32){

				return_error = 1;
			}
		}
		else if(cur_char == '/'){
	
			if(dots < 3 || chunk_size < 1) return_error = 1;

			fw_slash = true;
			chunk_size = 0;
			chunk_val = 0;

			chunk_val_str = "";

		}
		else{
			
			if(chunk_size > 3){
				return_error = 1;
			}
			
			if(dots > 3){
				return_error = 1;
			}

			if(cur_char > 47 && cur_char < 58){

				chunk_val_str += cur_char;
				chunk_size++;
			}
			else if(cur_char == '.'){

				for(int j = 0; j < chunk_size; j++){

					//get integer value inside chunk ( x*10^2 y + 10^1 z + 10^0 )
					chunk_val += (chunk_val_str[j] - 48) * std::pow(10, chunk_size - 1 - j);
				}

				chunk_val_str = "";

				chunk_size = 0;
				dots++;
				
				if(chunk_val < 0 || chunk_val > 255){
					return_error = 1;
				}

				chunk_val = 0;
			}
			else{
				return_error = 1;
			}

			if(!return_error){

				address_str += cur_char;
			}
		}
	}
	if(return_error == 0){

		//fill in the data of the struct
		range_container.prefix = chunk_val;
		inet_pton(AF_INET, address_str.c_str(), &range_container.net_ip); //convert network address to big endian
		ranges_vector.push_back(range_container);
	}

	return return_error;
};

void insert_addrs_from_range(const ip_range &range, std::unordered_set<uint32_t> &blacklist){

	struct in_addr info_addr;

	//get ip range given the network addr and mask
	uint32_t host_ip = ntohl(range.net_ip);
	uint32_t mask = (0xFFFFFFFFu << (32 - range.prefix));

	uint32_t range_start = host_ip;
	uint32_t range_end = range_start | ~mask;

	info_addr.s_addr = range.net_ip;
	std::cout << "\r\033[K" << "Loading range " << inet_ntoa(info_addr) << "/" << range.prefix << std::endl;

	//loop from first ip to last
	for(uint32_t i = range_start; i <= range_end; i++){

		progress_bar(i, range_start, range_end, 30);

		//insert every ip into the unordered_set
		blacklist.insert(htonl(i));
	}
}

int parse_blacklist(std::string _blist_name, std::unordered_set<uint32_t> &_blacklist){

	std::string line;
	std::vector<ip_range> ranges;

	int line_num = 1;

	bool errors = false;

	std::ifstream file_bl(_blist_name);

	if(!file_bl.is_open()){

		std::cerr << "ERR: File {" << _blist_name << "} could not be opened" << std::endl;
		return 1;
	}

	while(getline(file_bl, line) && !file_bl.eof()){

		int validated = validate_line_syx(line, ranges);

		if(validated == 1){

			std::cerr << "Syntax error on " << _blist_name << " line " << line_num << std::endl;
			return 1;
		}

		line_num++;
		
	}

	for(const ip_range &ip_r : ranges){

		insert_addrs_from_range(ip_r, _blacklist);
	}
	std::cout << std::endl;

	return 0;
}

std::string Logger::timenow(){

	std::time_t now = std::time(nullptr);

	char buffer[20];
	std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

	return std::string(buffer);
}

int ArgParser::verifyFlag(int _idx, int _argc, std::string errmesg){

	if(_idx + 1 >= _argc){

		errors.push(errmesg);
		return 1;
	}

	return 0;
}

int ArgParser::flush_err(){

	if(errors.empty() && req_flags == false){

		std::cerr << "missing required arguments" << help_mesg << std::endl;
		return 1;
	}
	else if(!errors.empty()){

		while(!errors.empty()){

			std::cerr << errors.top() << std::endl;
			errors.pop();
		}

		std::cerr << help_mesg << std::endl;

		return 1;
	}

	return 0;
}

ArgParser::ArgParser(int argc, char* argv[]){

	int idx = 1;

	req_flags = false;
	int req_flags_rem = 2;

	while(idx < argc){

		//interface
		if(strcmp(argv[idx], FLAG_IF) == 0){
		
			if(verifyFlag(idx, argc, "option -i requires an argument: \'-i <interface>\'") == 0){

				flags.interface.first = true;
				flags.interface.second = argv[++idx];
				req_flags_rem--;
			}
		}
		else if(strcmp(argv[idx], FLAG_BL) == 0){

			if(verifyFlag(idx, argc, "option -b required an argument: \'-b <blacklist-path>\'") == 0){

				flags.blist_name.first = true;
				flags.blist_name.second = argv[++idx];
				req_flags_rem--;
			}
		}

		idx += 1;
	}

	if(req_flags_rem == 0){

		req_flags = true;
	}
}
