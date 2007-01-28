// MungeCap.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

/** Global vars to store command line arguments */
static list<string> input_files;
static string filter;
static string output_file;

static int packet_count = 0;

/** Structure containing info on a single input file */
struct input_file_t {
	pcap_t* fp;
	
	bool eof;
	bool error;
	struct packet_t {
		struct pcap_pkthdr* header;
		u_char* pkt_data;
	} next_packet;
};

static void usage(void) {
	cerr << "Usage: mungecap [-f filter] -w <outfile> <infile> [<infile> [... [<infile> ] ] ]" << endl;;
}

static bool parse_cmdline(int argc, char* argv[]) {
  extern char *optarg;
  extern int   optind;

  int opt;

  while ( (opt = ::getopt(argc, argv, "hf:w:")) != -1) {
	  switch (opt) {
		  case 'w':
			  output_file = optarg;
			  break;

		  case 'f':
			  filter = optarg;
			  break;

		  case 'h':
			  usage();
			  return false;
	  }
  }

  //Remaining arguments are input files
  int in_file_count = argc - optind;

  for (int idx = in_file_count; idx < argc; idx++) {
	  input_files.push_back(argv[idx]);
  }

  if (!input_files.size()) {
	  cerr << "mungecap: No input files specified" << endl;
	  return false;
  }

  if (!output_file.size()) {
	  cerr << "mungecap: No output file specified" << endl;
	  return false;
  }

  return true;
}

static bool read_next_packet(input_file_t& ift) {
	int ret = ::pcap_next_ex(ift.fp,
		&ift.next_packet.header,
		const_cast<const u_char**>(&ift.next_packet.pkt_data));
	if (ret == 1) {
		return true;
	} if (ret == -2) {
		//EOF
		ift.eof = true;
		return true;
	} else if (ret == -1) {
		ift.error = true;
		cerr << "mungecap: Error reading next packet: " << ::pcap_geterr(ift.fp) << endl;
		return true;
	} else {
		cerr << "mungecap: Unexpected retval " << ret << " from pcap_next_ex" << endl;
		return false;
	}
}

static bool open_input_file(const string& file_name, input_file_t& ift) {
	char errbuf[PCAP_ERRBUF_SIZE];

	ift.fp = ::pcap_open_offline(file_name.c_str(),
		errbuf);
	if (ift.fp == NULL) {
		cerr << "Unable to open file " << file_name << ": " << errbuf << endl;
		return false;
	}

	if (filter.length()) {
		struct bpf_program pgm = {0};
		if (::pcap_compile(ift.fp,
			&pgm,
			const_cast<char*>(filter.c_str()),
			1,
			0) == -1) {
			cerr << "Error in filter expression '" << filter << "': " << ::pcap_geterr(ift.fp) << endl;
			return false;
		}

		if (::pcap_setfilter(ift.fp,
			&pgm) == -1) {
			cerr << "Error setting compiled filter on adapter: " << ::pcap_geterr(ift.fp) << endl;
			return false;
		}
	}

	ift.eof = false;
	ift.error = false;

	if (!read_next_packet(ift)) {
		return false;
	}

	return true;
}

static bool open_input_files(const list<string>& file_names, list<input_file_t>& files) {
	for (list<string>::const_iterator iter = file_names.begin();
		iter != file_names.end();
		++iter) {
		input_file_t ift;
		if (!open_input_file(*iter, ift)) {
			return false;
		}

		files.push_back(ift);
	}

	return true;
}

static pcap_dumper_t* open_output_file(const string& filename, input_file_t& ft) {
	pcap_dumper_t* dumper = ::pcap_dump_open(ft.fp, filename.c_str());
	if (!dumper) {
		cerr << "Error opening output file " << filename << ": " << ::pcap_geterr(ft.fp) << endl;
		return NULL;
	}

	return dumper;
}

/*
 * returns TRUE if first argument is earlier than second
 */
static bool is_earlier(timeval& l, timeval& r) {
  if (l.tv_sec > r.tv_sec) {  /* left is later */
    return false;
  } else if (l.tv_sec < r.tv_sec) { /* left is earlier */
    return true;
  } else if (l.tv_usec > r.tv_usec) { /* tv_sec equal, l.usec later */
    return false;
  }
  /* either one < two or one == two
   * either way, return one
   */
  return true;
}

static bool dump_packet(input_file_t& packet_source, pcap_dumper_t* output_file) {
	packet_count++;
	if (packet_count % 10) {
		cout << "Dumping packet " << packet_count << "\r";
	}

	::pcap_dump(reinterpret_cast<u_char*>(output_file),
		packet_source.next_packet.header,
		packet_source.next_packet.pkt_data);

	//Read the next packet for this source
	if (!read_next_packet(packet_source)) {
		return false;
	}

	return true;
}

static bool dump_next_packet(list<input_file_t>& input_files, pcap_dumper_t* output_file) {
	//Find the packet in the input files with the oldest time stamp
	timeval oldest_packet = {LONG_MAX, LONG_MAX};
	list<input_file_t>::iterator oldest_packet_source = input_files.end();

	for (list<input_file_t>::iterator iter = input_files.begin();
		iter != input_files.end();
		++iter) {
		if (iter->eof || iter->error) {
			//Error or EOF; nothing coming from this one
			continue;
		}

		if (is_earlier(iter->next_packet.header->ts, oldest_packet)) {
			//This one is older than oldest_packet
			oldest_packet = iter->next_packet.header->ts;
			oldest_packet_source = iter;
		}
	}

	if (oldest_packet_source == input_files.end()) {
		//We're done
		return false;
	}

	return dump_packet(*oldest_packet_source, output_file);
}

static bool dump_files(list<input_file_t>& input_files, pcap_dumper_t* output_file) {
	packet_count = 0;

	while (dump_next_packet(input_files, output_file)) {
		;
	}

	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	if (!parse_cmdline(argc, argv)) {
		return 1;
	}

	list<input_file_t> input_file_ts;

	if (!open_input_files(input_files, input_file_ts)) {
		return 1;
	}

	pcap_dumper_t* out_file = open_output_file(output_file, *input_file_ts.begin());
	if (!out_file) {
		return 1;
	}

	if (!dump_files(input_file_ts, out_file)) {
		return 1;
	}

	return 0;
}

