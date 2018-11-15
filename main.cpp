#include "nwheader.h"

#define ERRBUF_SIZE 4096
#define ETH_HDR_SIZE 14

using namespace std;
typedef uint32_t U32;

#pragma pack(1)
typedef struct cbFuncArg{
    pcap_t * packet_handle;
    U8 MacAddr[ETHER_ADDR_LEN];
} cbFuncArg;
#pragma pop()

void print_error(string, char *);
void cbfunc(u_char * usr_args, const struct pcap_pkthdr * packet_header, const U8 * packet);
void packetInjection(cbFuncArg * user_arg, Packet & originPacket);
void GetMyMac(uint8_t * MacAddr, const char * interface);
int isHttp(const unsigned char * data);

int main(void)
{
    char errbuf[ERRBUF_SIZE];
    char * dev;
    pcap_t * packet_handle;
    cbFuncArg argStruct;
    dev = pcap_lookupdev(errbuf);
    GetMyMac(argStruct.MacAddr, dev);

    packet_handle = pcap_open_live(dev, ERRBUF_SIZE, 1, 200, errbuf);
    if(packet_handle == nullptr) print_error("cannot find packet handle", errbuf);
    argStruct.packet_handle = packet_handle;
    pcap_loop(packet_handle, 0, cbfunc, reinterpret_cast<u_char*>(&argStruct));

    pcap_close(packet_handle);
    return 0;
}

void print_error(string errPoint, char * msg){
    cerr << "<<<<< " << errPoint << " >>>>>\n";
    if(msg != nullptr) cout << msg;
    cout << endl;

    exit(1);
}

void cbfunc(u_char * usr_args, const struct pcap_pkthdr * packet_header, const U8 * packet){
    Packet packetobj(packet, static_cast<U32>(packet_header->len));

    if(packetobj.getIpProtocol() == IPPROTO_TCP && isHttp((const U8*)packet))
        packetInjection(reinterpret_cast<cbFuncArg*>(usr_args), packetobj);

}

int isHttp(const unsigned char * data){
#define IP_PROTOCOLFILED_OFFSET 9
#define TCP_HLENFILED_OFFSET 12
#define HOSTOFFSET 16
#define HOSTNAME 6
    uint32_t ipHLen = (data[0] & 0xF) << 2;
    uint8_t ipProtocol = data[IP_PROTOCOLFILED_OFFSET];
    uint32_t tcpDataOffset = ipHLen + (((data[ipHLen + TCP_HLENFILED_OFFSET] & 0xF0) >> 4) << 2);
    int of = 0;


    if(tcpDataOffset > ipHLen && (!memcmp(data + tcpDataOffset, "GET", 3) || !memcmp(data + tcpDataOffset, "POST", 4))){
            if(!memcmp(data + tcpDataOffset + HOSTOFFSET, "Host", 4)) {
               return 1;
            }
    }
    return 0;
}


void packetInjection(cbFuncArg * user_arg, Packet & originPacket){
    Packet rstPacket(originPacket);
    Packet finPacket(originPacket);
    rstPacket.setFlag(TH_RST);
    finPacket.setFlag(TH_FIN);

    finPacket.setIp(originPacket.getDstIpAddr(), originPacket.getSrcIpAddr());
    finPacket.changPort();

    rstPacket.setMacAddr(user_arg->MacAddr, originPacket.getDstMac());
    finPacket.setMacAddr(user_arg->MacAddr, originPacket.getSrcMac());

    finPacket.makeMyPayload();

    finPacket.setNum(NUM_SEQ, originPacket.getNum(NUM_ACK));
    finPacket.setNum(NUM_ACK, originPacket.getNum(NUM_SEQ));

    U8 * finPacketBuf = new U8[finPacket.getPacketSize()];
    U8 * rstPacketBuf = new U8[rstPacket.getPacketSize()];

    finPacket.makePacket(finPacketBuf);
    rstPacket.makePacket(rstPacketBuf);

    finPacket.setChksum(finPacketBuf);
    rstPacket.setChksum(rstPacketBuf);

    pcap_inject(user_arg->packet_handle, rstPacketBuf, rstPacket.getPacketSize());
    pcap_inject(user_arg->packet_handle, finPacketBuf, finPacket.getPacketSize());

    delete[] finPacketBuf;
    delete[] rstPacketBuf;
}

void GetMyMac(uint8_t * MacAddr, const char * interface){
    int nSD;
    struct ifreq sIfReq;
    struct if_nameindex * pIfList;

    pIfList= nullptr;

    if((nSD = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        print_error("Socket descriptor allocation failed\n", nullptr);
    }

    pIfList = if_nameindex();
    for(; *(char*)pIfList != 0; pIfList++){
        if(!strcmp(pIfList->if_name, interface)){
            uint32_t a;
            strncpy(sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE);
            if(ioctl(nSD, SIOCGIFHWADDR, &sIfReq) !=0){
                print_error("failed in ioctl while getting mac address\n", nullptr);
            }
            memcpy(MacAddr, (&sIfReq.ifr_ifru.ifru_hwaddr.sa_data), 6);
            printf("MAC address : ");
            for(a = 0; a < 6; a = a + 1) {
                printf("%02X",  MacAddr[a]);
                if(a < 5) putchar(':');
            }
            puts("");
        }
    }

}
