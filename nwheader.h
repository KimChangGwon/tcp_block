#ifndef NWHEADER_H
#define NWHEADER_H

#include <iostream>
#include <cstdint>
#include <libnet.h>
#include <cstdlib>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>
#include <string>

#define NUM_SEQ 0
#define NUM_ACK 1

using namespace std;

typedef uint8_t U8;
typedef uint16_t U16;
typedef uint32_t U32;
typedef int8_t S8;
typedef int16_t S16;
typedef int32_t S32;

class Packet{
public:
    Packet() = default;

    Packet(const U8 * buf, U32 bufSize);
    Packet(const Packet & rhs);

    ~Packet(){ if(this->tcpData != nullptr)   delete[] tcpData; }

    U32 getPacketSize(void) const { return packetSize; }

    const U8 * getSrcMac(void) const { return etherHeader.ether_shost; }
    const U8 * getDstMac(void) const { return etherHeader.ether_dhost; }
    void printDstMac(void) const{
        for(int a = 0; a<ETHER_ADDR_LEN; a=a+1) {
            printf("%02X", etherHeader.ether_dhost[a]);
            if(a < ETHER_ADDR_LEN - 1) cout << ':';
        }
        cout << endl;
    }
    void printSrcMac(void) const{
        for(int a = 0; a<ETHER_ADDR_LEN; a=a+1) {
            printf("%02X", etherHeader.ether_shost[a]);
            if(a < ETHER_ADDR_LEN - 1) cout << ':';
        }
        cout << endl;
    }

    U32 getIpProtocol(void) const { return ipHeader.ip_p; }

    U32 getSrcIpAddr(void) const{ return ntohl(ipHeader.ip_src.s_addr);}
    U32 getDstIpAddr(void) const{ return ntohl(ipHeader.ip_dst.s_addr);}
    U32 getpayloadSize(void) const{ return payloadSize; }
    void setFlag(U8 flag){ this->tcpHeader.th_flags |= flag;  }
    void setIp(U32 srcIp, U32 dstIp){
        this->ipHeader.ip_src.s_addr = htonl(srcIp);
        this->ipHeader.ip_dst.s_addr = htonl(dstIp);
    }
    void setMacAddr(U8 myMac[], const U8 dstMac[]){
        int i;
        for(i = 0; i < ETHER_ADDR_LEN; i++) etherHeader.ether_shost[i] = myMac[i];
        for(i = 0; i < ETHER_ADDR_LEN; i++) etherHeader.ether_dhost[i] = dstMac[i];
    }

    U32 getNum(U8 numType) const { return (numType == NUM_SEQ ? this->tcpHeader.th_seq : this->tcpHeader.th_ack);}

    void setNum(U8 numType, U32 preNum){
        switch(numType){
        case NUM_SEQ:
            this->tcpHeader.th_seq = preNum;
            break;
        case NUM_ACK:
            this->tcpHeader.th_ack = preNum + payloadSize;
            break;
        }
    }

    void makeMyPayload(void){
        if(this->tcpData != nullptr) delete[] this->tcpData;
        string tmpStr = "this is test string";
        tcpData = new U8[tmpStr.size()];
        memcpy(tcpData, tmpStr.c_str(), tmpStr.size());
    }

private:
    U32 packetSize;
    U32 payloadSize;
    struct libnet_ethernet_hdr etherHeader;
    struct libnet_ipv4_hdr ipHeader;
    struct libnet_tcp_hdr tcpHeader;

    U8 * tcpData = nullptr;
};

Packet::Packet(const U8 * buf, U32 bufSize){
    packetSize = bufSize;

    U32 ipOffset = sizeof(struct libnet_ethernet_hdr), tcpOffset;
    memcpy(&etherHeader, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(&(ipHeader), buf + ipOffset, sizeof(struct libnet_ipv4_hdr));

    U32 ipHLen = (static_cast<U32>(ipHeader.ip_hl) << 2);
    tcpOffset = ipOffset + ipHLen;
    memcpy(&tcpHeader, buf + tcpOffset, sizeof(struct libnet_tcp_hdr));

    U32 tcpHLen = (static_cast<U32>(tcpHeader.th_off) << 2);
    if(bufSize > sizeof(struct libnet_ethernet_hdr) + ipHLen + tcpHLen){
        U32 extra = bufSize - (sizeof(struct libnet_ethernet_hdr) + ipHLen +  tcpHLen);
        tcpData = static_cast<U8*>(malloc(sizeof(U8*) * extra));
    }

    payloadSize = packetSize- sizeof(struct libnet_ethernet_hdr) - ipHLen - tcpHLen;
    if(payloadSize > 0){
        tcpData = new U8[payloadSize];
        memcpy(tcpData, buf + packetSize - payloadSize, payloadSize);
    }
}

Packet::Packet(const Packet & rhs){
    payloadSize = rhs.packetSize - sizeof(struct libnet_ethernet_hdr) -
            (static_cast<U32>(rhs.ipHeader.ip_hl) << 2) - (static_cast<U32>(rhs.tcpHeader.th_off) << 2);
    cout << payloadSize << " = payload size\n";

    memcpy(&(this->etherHeader), &(rhs.etherHeader), sizeof(struct libnet_ethernet_hdr));
    memcpy(&(this->ipHeader), &(rhs.ipHeader), sizeof(struct libnet_ipv4_hdr));
    memcpy(&(this->tcpHeader), &(rhs.tcpHeader), sizeof(struct libnet_tcp_hdr));
    if(payloadSize > 0){
        tcpData = new U8[payloadSize];
        memcpy(this->tcpData, rhs.tcpData, sizeof(U8) * payloadSize);
    }
}

#endif // NWHEADER_H
//https://github.com/korczis/libnet/blob/master/include/libnet/libnet-headers.h
