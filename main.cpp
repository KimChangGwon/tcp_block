#include <nwheader.h>

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
void dump(const U8 * buf, S32 size) ;
void packetInjection(cbFuncArg * user_arg, const Packet & packetobj);
void GetMyMac(uint8_t * MacAddr, const char * interface);



int main(void)
{
    char errbuf[ERRBUF_SIZE];
    char * dev;
    pcap_t * packet_handle;
    cbFuncArg argStruct;
    dev = pcap_lookupdev(errbuf);

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
    if(packetobj.getIpProtocol() == IPPROTO_TCP && packetobj.getSrcIpAddr() == 0xafd52327)
    {
       cout << "injection \n";
       packetInjection(reinterpret_cast<cbFuncArg*>(usr_args) , packetobj);
    }
}

void packetInjection(cbFuncArg * user_arg, const Packet & originPacket){
/*
 Things to do
 4. checksum
 5. confirm that the injection operates properly
 */

    Packet rstPacket(originPacket);
    Packet finPacket(originPacket);

    rstPacket.setFlag(TH_RST);
    finPacket.setFlag(TH_FIN);

    finPacket.setIp(originPacket.getDstIpAddr(), originPacket.getSrcIpAddr());

    rstPacket.setMacAddr(user_arg->MacAddr, originPacket.getDstMac());
    finPacket.setMacAddr(user_arg->MacAddr, originPacket.getSrcMac());

    finPacket.makeMyPayload();

    finPacket.setNum(NUM_SEQ, originPacket.getNum(NUM_ACK));
    finPacket.setNum(NUM_ACK, originPacket.getNum(NUM_SEQ) + finPacket.getpayloadSize());

    cout << "rstPacket --------------------\n";
    //dump((const U8*)(&rstPacket), rstPacket.getPacketSize());
    puts("");
    //pcap_inject(packet_handle, static_cast<void*>(&rstPacket), packetobj.getPacketSize());
   // pcap_inject(packet_handle, static_cast<void*>(&finPacket), packetobj.getPacketSize());
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
void dump(const U8 * buf, S32 size) {
    int i;
    for (i = 0; i < (size >= 48? 48 : size); i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
    cout << endl;
}
