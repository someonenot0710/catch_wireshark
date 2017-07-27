/*
 * How to read a packet capture file.
 */

/*
 * Step 1 - Add includes
 */
#include <string>
#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <iomanip>
#include <sstream>
#include <math.h>
#include <stdlib.h>
#include <vector>

using namespace std;

// This is for the it_len value:
struct radiotap_header {
	uint8_t it_rev;
	uint8_t it_pad;
	uint16_t it_len;
};

int main(int argc, char *argv[])
{
	/*
	 * Step 2 - Get a file name
	 */

	string file(argv[1]);

	/*
	 * Step 3 - Create an char array to hold the error.
	 */

	// Note: errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
	//       PCAP_ERRBUF_SIZE is defined as 256.
	// http://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html
	char errbuff[PCAP_ERRBUF_SIZE];
	double last_end=0, start_time=0, end_time=0, airtime=0;
	/*
	 * Step 4 - Open the file and store result in pointer to pcap_t
	 */

	// Use pcap_open_offline
	// http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
	pcap_t * pcap = pcap_open_offline(file.c_str(), errbuff);

	/*
	 * Step 5 - Create a header and a data object
	 */

	// Create a header object:
	// http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
	struct pcap_pkthdr *header;

	// Create a character array using a u_char
	// u_char is defined here:
	// C:\Program Files (x86)\Microsoft SDKs\Windows\v7.0A\Include\WinSock2.h
	// typedef unsigned char   u_char;
	const u_char *packet;

	/*
	 * Step 6 - Loop through packets and print them to screen
	 */
	u_int packetCount = 0;

	while (int returnValue = pcap_next_ex(pcap, &header, &packet) >= 0)
	{
		// Print using printf. See printf reference:
		// http://www.cplusplus.com/reference/clibrary/cstdio/printf/

		// Show the packet number
		printf("Frame #%i\n", ++packetCount);

		// Show the size in bytes of the packet
		printf("Frame size: %d bytes\n", header->len);

		// Show a warning if the length captured is different
		if (header->len != header->caplen)
			printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);

		// Show Epoch Time
		//printf("Epoch Time: %d.%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
		double arrtime = header->ts.tv_sec+header->ts.tv_usec*0.000001;
//		char arrtimec[30];
//		sprintf(arrtimec, "%d.%d", header->ts.tv_sec, header->ts.tv_usec);
//		double arrtime = atof(arrtimec);
		//yibin 
		const u_char *bssid; // character array for BSSID and ESSID
		const u_char *essid;
		int offset = 0;
		struct radiotap_header *rtaphdr;
		rtaphdr = (struct radiotap_header *) packet;
		offset = rtaphdr->it_len;
		/*if(packet[offset] == 0x80){ // subtype 8 for beacon starts at offset 27
		// bssid = packet + offset + 10; // BSSID starts here in beacons
		bssid = packet + 36; // BSSID starts here in beacons
		essid = packet + 64; // ESSID starts here and ends with a simple 0x1
		char *ssid; // Let's make a simple char array of the ESSID
		// let's construct the essid:
		unsigned int i = 0;
		while(essid[i] > 0x1){ // loop through bytes values start with essid[]
		printf("hex char: %x\n",essid[i]); // until we hit the 0x1
		ssid[i] = essid[i]; // ssid[] string
		i++; // here would be good chance to filter with strcmp();
		}
		ssid[i] = '\0'; // terminate the string
		//	printf("ESSID string: %s\n", ssid); // print the string
		//	printf("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n", bssid[0], bssid[1], bssid[2],
		//	bssid[3], bssid[4], bssid[5]);
		}*/
		const u_char *ch;
		// channel
		ch = packet + 26;
		int channel = ch[1] * 256 + ch[0];
		printf("channel: %i GHz\n",channel);
		// ssi
		ch = packet + 30;
		int ssi = ch[0];
		if(ssi>127)
			ssi=0-(256-ssi);
		//cout<<chi<<endl;
		printf("ssi signal: %i\n", ssi);
		// src addr
		ch = packet + 54;
		char src_addr[15]="\0";
		for(int i = 0; i<6; i++)
			sprintf(src_addr,"%s%02x", src_addr, ch[i]);
		printf("src addr: %s\n", src_addr);
		// dst addr
		ch = packet + 42;
        	char dst_addr[15]="\0";
		for(int i=0; i<6; i++)
			sprintf(dst_addr,"%s%02x", dst_addr, ch[i]);
		printf("dst addr: %s\n", dst_addr);	
		// data rate
		ch= packet + 25;
		int datarate=ch[0]*500;
		printf("data rate: %d Kbps\n", datarate);
		double start=0;
                start = arrtime - (double)header->len/(double)(datarate*1000/8);
		printf("%d\n", packetCount);
		if(packetCount==1)
			start_time=start;
		//printf("%f %f\n", last_end, arrtime);
		if(start<last_end)
			airtime+=arrtime-last_end;
		else
			airtime+=(double)header->len/(double)(datarate*1000/8);
		last_end=arrtime;
		end_time=last_end;
		printf("%f\n", (double)header->len/(double)(datarate*1000/8));
                printf("start: %f end: %f\n", start, arrtime);
		printf("airtime: %f\n", airtime);

	        // loop through the packet and print it as hexidecimal representations of octets
	        // We also have a function that does this similarly below: PrintData()
        	/*for (u_int i=0; (i < header->caplen ) ; i++)
	        {
	            // Start printing on the next after every 16 octets
	            if ( (i % 16) == 0) printf("\n");
	 
        	    // Print each octet as hex (x), make sure there is always two characters (.2).
	            printf("%.2x ", packet[i]);
	        }*/
 	
	        // Add two lines between packets
	        printf("\n\n");
	}

	printf("total sample time: %f\n", end_time-start_time);
	printf("airtime: %f\n", airtime);
	printf("free airtime ratio: %.2f\%\n", 100-airtime*100/(end_time-start_time));

}
