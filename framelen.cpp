/*! @file    framelen.cpp
 *  @author  xxxxxxxxxxxxxxxxxxxxxxxxxx (mailto:xxxxxx@mail.ru)
 *  @ingroup
 *  @brief   Модификация длины заголовков pcap
 *
 *  Time-stamp: <>
 *  Time-stamp: <2026/10/12 11:05 agulevich> начало
 *
 *  Сборка:
 *   g++ framelen.cpp -o framelen -I${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/header ${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/*.a -lpcap
 *   https://pcapplusplus.github.io/v1904/Documentation/a01382.html
 *
 *  Для преобразования pcapng в pcap:
 *   $ tshark -r capture.pcapng -F pcap -w capture.pcap
 */

// PcapPlusPlus
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <SipLayer.h>
#include <UdpLayer.h>
// stl
#include <cstdlib>
#include <iomanip>
#include <iostream>
// c
#include <arpa/inet.h>

#define DOUT( LINE ) (std::cout << LINE << '\n')
#define EOUT( LINE ) (std::cerr << LINE << '\n')

int main( int __q, char ** __p )
{
 int ret = EXIT_FAILURE;

 do
 {
  if ( __q < 2 )
  {
   EOUT( "pcap-file expected" );
   break;
  }

  std::string fname = __p[1];

    // открыть pcap-файл для чтения
    pcpp::PcapFileReaderDevice reader( fname );
    if ( !reader.open() )
    {
     EOUT( "Open error: " << std::quoted( fname ) );
     break;
    }

    // прочитать первый (и единственный) пакет из файла
    pcpp::RawPacket rawPacket;
    if (!reader.getNextPacket(rawPacket))
    {
     EOUT( "single frame file expected" );
     break;
    }

    if ( reader.getNextPacket(rawPacket) )
    {
     EOUT( "single frame file expected" );
     break;
    }

    //    if ( parsedPacket.isPacketOfType(pcpp::Ethernet) );

    DOUT( "llsize:" << rawPacket.getFrameLength() );
    uint8_t buff[ 200 ];
    rawPacket.reallocateData( rawPacket.getFrameLength() + sizeof(buff) );
    rawPacket.appendData( buff,sizeof(buff) );

    // преобразовать необработанный пакет в разобранный (parsed) пакет
    pcpp::Packet parsedPacket(&rawPacket);

    if ( auto * const psip = parsedPacket.getLayerOfType< pcpp::SipLayer >() ) // parsedPacket.isPacketOfType(pcpp::UDP) )
    {
     DOUT( "SIP content length: " << psip->getContentLength() );
     psip->setContentLength( psip->getContentLength() + sizeof(buff) );

     // проверить, является ли пакет пакетом IPv4
     if ( auto * const pip = parsedPacket.getLayerOfType<pcpp::IPv4Layer>() )
     {
      // извлечь IP-адреса источника и назначения
      pcpp::IPv4Address srcIP = pip->getSrcIPv4Address();
      pcpp::IPv4Address destIP = pip->getDstIPv4Address();

      auto * const piphdr = pip->getIPv4Header();
      // напечатать IP-адреса источника и назначения
      DOUT( "SIP: " << srcIP << ", DIP: " << destIP << ", iplen: " << ntohs(piphdr->totalLength) );

      piphdr->totalLength = ntohs( htons( piphdr->totalLength ) + sizeof(buff) );
     }

     if ( auto * const pudp = parsedPacket.getLayerOfType<pcpp::UdpLayer>() ) // parsedPacket.isPacketOfType(pcpp::UDP) )
     {
      auto * const pudphdr = pudp->getUdpHeader();
      DOUT( "SPORT: " << pudp->getSrcPort() << ", DPORT: " << pudp->getDstPort() << ", udplen: " << ntohs(pudphdr->length) );

      pudphdr->length = htons( ntohs(pudphdr->length) + sizeof(buff) );
      pudphdr->portDst = 0;
      pudp->calculateChecksum( true );
     }
    }

    // Читаем пакет и меняем поле len

    fname = "modified.cap";
    pcpp::PcapFileWriterDevice writerDev( fname );
    if ( !writerDev.open() )
    {
     EOUT( "write error: " << std::quoted( fname) );
     break;
    }

    DOUT( "gen file: " << std::quoted( fname ) );

    //        rawPacket.setLength(3000);
        writerDev.writePacket(rawPacket);
        //    }

        writerDev.close();

    // закрыть файл
    reader.close();

    ret = EXIT_SUCCESS;
 } while ( 0 );

 return ret;

}

/* Local variables: */
/*  coding: koi8-r  */
/* end:             */
