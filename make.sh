g++ framelen.cpp -o framelen -I${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/header ${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/*.a -lpcap
g++ ipchange.cpp -o ipchange -I${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/header ${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/*.a -lpcap
