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
#include <vector>

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

    U32 getPacketSize(void) const { return sizeof(struct libnet_ethernet_hdr) + ntohs(ipHeader.ip_len); }

    const U8 * getSrcMac(void) const { return etherHeader.ether_shost; }
    const U8 * getDstMac(void) const { return etherHeader.ether_dhost; }
    U32 getIpProtocol(void) const { return ipHeader.ip_p; }

    U32 getSrcIpAddr(void) const{ return ntohl(ipHeader.ip_src.s_addr);}
    U32 getDstIpAddr(void) const{ return ntohl(ipHeader.ip_dst.s_addr);}
    U32 getpayloadSize(void) const{ return static_cast<U32>(tcpPayload.size()) ; }
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

            this->tcpHeader.th_ack = preNum + getpayloadSize();
            break;
        }
    }

    void setChksum(U8 * packetBuf){
        U32 phsum = 0;
        phsum = ((getSrcIpAddr() & 0xFFFF0000) >> 16) + (getSrcIpAddr() & 0xFFFF) + ((getDstIpAddr()& 0xFFFF0000) >> 16) + ((getDstIpAddr()& 0xFFFF))
                + ipHeader.ip_p + static_cast<U32>((ntohs(ipHeader.ip_len) - (ipHeader.ip_hl << 2)));
        while(phsum > 0xFFFF){
            U8 carry = (phsum &0xFF0000) >> 16;
            phsum = phsum & 0xFFFF;
            phsum += carry;
        }

        U32 offset = sizeof(struct libnet_ethernet_hdr) + static_cast<U32>((ipHeader.ip_hl << 2));
        U32 chksumOffset = offset + 0x10;
        while(offset < sizeof(struct libnet_ethernet_hdr) + ntohs(ipHeader.ip_len)){
            if(offset == chksumOffset){
                offset = offset + 2;
                continue;
            }
            U16 summer = *(packetBuf + (offset++));
            summer <<= 8;
            if(offset < sizeof(struct libnet_ethernet_hdr) + ntohs(ipHeader.ip_len))   summer |= *(packetBuf + (offset++));
            phsum += summer;

            while(phsum > 0xFFFF){
                U8 carry = (phsum & 0xFF0000) >> 16;
                phsum = phsum & 0xFFFF;
                phsum += carry;
            }
        }
        this->tcpHeader.th_sum = phsum & 0xFFFF;
    }

    void makeMyPayload(void){
        if(this->tcpPayload.size() != 0)  {
            tcpPayload.clear();
        }
        U16 ip_len = ntohs(static_cast<U16>(ipHeader.ip_len)) - static_cast<U16>(getpayloadSize());
        string tmpstr = "tcp block";
        tcpPayload = vector<U8>(tmpstr.size());
        for(int a = 0; a<static_cast<U8>(tmpstr.size()); a=a+1) tcpPayload[a] = static_cast<U8>(tmpstr[a]);
        ip_len += static_cast<U16>(getpayloadSize());
        ipHeader.ip_len = htons(ip_len);
    }

    void makePacket(U8 * buf){
        memcpy(buf, reinterpret_cast<U8*>(&(this->etherHeader)), sizeof(struct libnet_ethernet_hdr));
        memcpy(buf + sizeof(struct libnet_ethernet_hdr), reinterpret_cast<U8*>(&(this->ipHeader)), sizeof(struct libnet_ipv4_hdr));
        memcpy(buf + sizeof(struct libnet_ethernet_hdr) + (ipHeader.ip_hl << 2), reinterpret_cast<U8*>(&(this->tcpHeader)), sizeof(struct libnet_tcp_hdr));
        for(U32 a = 0; a < getpayloadSize(); a=a+1){
            *(buf + sizeof(struct libnet_ethernet_hdr) + (ipHeader.ip_hl <<2) + (tcpHeader.th_off << 2) + a) = tcpPayload[a];
        }
    }

private:
#pragma pack(1)
    struct libnet_ethernet_hdr etherHeader;
    struct libnet_ipv4_hdr ipHeader;
    struct libnet_tcp_hdr tcpHeader;
    vector<U8> tcpPayload;
};

Packet::Packet(const U8 * buf, U32 bufSize){
    U32 packetSize = bufSize;
    U32 ipOffset = sizeof(struct libnet_ethernet_hdr), tcpOffset;
    memcpy(&etherHeader, buf, sizeof(struct libnet_ethernet_hdr));
    memcpy(&ipHeader, buf + ipOffset, sizeof(struct libnet_ipv4_hdr));

    U32 ipHLen = (static_cast<U32>(ipHeader.ip_hl) << 2);
    tcpOffset = ipOffset + ipHLen;
    memcpy(&tcpHeader, buf + tcpOffset, sizeof(struct libnet_tcp_hdr));

    U32 tcpHLen = (static_cast<U32>(tcpHeader.th_off) << 2);
    U32 payloadSize = packetSize - sizeof(struct libnet_ethernet_hdr) - ipHLen - tcpHLen;
    if(payloadSize > 0){
        for(U32 a = 0; a < static_cast<U32>(payloadSize); a=a+1) tcpPayload.push_back(*(buf + packetSize - payloadSize + a));
    }
}

Packet::Packet(const Packet & rhs){
    memcpy(&(this->etherHeader), &(rhs.etherHeader), sizeof(struct libnet_ethernet_hdr));
    memcpy(&(this->ipHeader), &(rhs.ipHeader), sizeof(struct libnet_ipv4_hdr));
    memcpy(&(this->tcpHeader), &(rhs.tcpHeader), sizeof(struct libnet_tcp_hdr));

    if(rhs.getpayloadSize() > 0) {
        tcpPayload = vector<U8>(rhs.tcpPayload.begin(), rhs.tcpPayload.end());

    }
}

#endif // NWHEADER_H
//https://github.com/korczis/libnet/blob/master/include/libnet/libnet-headers.h
