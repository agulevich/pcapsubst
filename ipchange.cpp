/*! @file    ipchange.cpp
 *  @author  xxxxxxxxxxxxxxxxxxxxxxxxxx (mailto:xxxxxx@mail.ru)
 *  @ingroup
 *  @brief   Подмена IP в cap-файле
 *
 *  Time-stamp: <>
 *  Time-stamp: <2026/10/13 11:44 agulevich> начало
 *
 *  Сборка:
 *   g++ ipchange.cpp -o ipchange -I${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/header ${HOME}/killme/PcapPlusPlus/{Packet++,Common++,Pcap++}/*.a -lpcap
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
#include <string>
// c
#include <arpa/inet.h>

#define DOUT( LINE ) (std::cout << LINE << '\n')
#define EOUT( LINE ) (std::cerr << LINE << '\n')

struct SPair
{
 uint32_t match;
 uint32_t target;
};

bool
ParseIP( std::string const __in,uint32_t & __out )
{
 in_addr addr;
 if ( inet_pton( AF_INET,__in.c_str(),&addr) <= 0 ) return false;
 __out = addr.s_addr;
 return true;
}

bool
ParsePair( std::string const & __in,SPair & __out )
{
 bool ret = {};

 do
 {
  auto pos = __in.find( ':' );
  if ( pos == std::string::npos ) break;

  std::string str = __in.substr( 0,pos );
  if ( !ParseIP( str,__out.match ) )
  {
   EOUT( "failed to parse: " << str );
   break;
  }

  str = __in.substr( pos + 1 );
  if ( !ParseIP(str,__out.target ) )
  {
   EOUT( "failed to parse: " << str );
   break;
  }

  ret = true;
 } while ( 0 );

 return ret;
}

int main( int __q, char ** __p )
{
 int ret = EXIT_FAILURE;

 do
 {
  if ( __q < 2 )
  {
   EOUT( "expected: " << __p[0] << " {FNAME} {IP:SUBST} [{IP:SUBST}...]" );
   break;
  }

  std::string fname = *++__p;

  __q -= 2;
  SPair subst[ __q ];

  auto MatchFunc
  =
  [&]( uint32_t ip ) -> SPair const *
  {
   for ( auto const & it : subst )
    if ( it.match == ip ) return &it;

   return {};
  };

  ++__p;
  int i = 0;
  for ( i = 0 ; i < __q ; ++i,++__p )
   if ( !ParsePair( *__p,subst[i] ) )
    break;

  if ( i != __q ) break;

    // открыть pcap-файл для чтения
    pcpp::PcapFileReaderDevice reader( fname );
    if ( !reader.open() )
    {
     EOUT( "Open error: " << std::quoted( fname ) );
     break;
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

     SPair const * pmatch;
    // прочитать первый (и единственный) пакет из файла
    pcpp::RawPacket rawPacket;
    int matchedcount = {};
    bool ismatched;
    for ( i = 0 ; reader.getNextPacket(rawPacket) ; ++i )
    {
     //    if ( parsedPacket.isPacketOfType(pcpp::Ethernet) );

     //     DOUT( "llsize:" << rawPacket.getFrameLength() );

     // преобразовать необработанный пакет в разобранный (parsed) пакет
     pcpp::Packet parsedPacket(&rawPacket);

      if ( auto * const pip = parsedPacket.getLayerOfType<pcpp::IPv4Layer>() )
      {
       // извлечь IP-адреса источника и назначения
       pcpp::IPv4Address srcIP  = pip->getSrcIPv4Address();
       pcpp::IPv4Address destIP = pip->getDstIPv4Address();

       auto * const piphdr = pip->getIPv4Header();
       // напечатать IP-адреса источника и назначения
       //       DOUT( "SIP: " << srcIP << ", DIP: " << destIP << ", iplen: " << ntohs(piphdr->totalLength) );


       if ( (pmatch = MatchFunc( piphdr->ipSrc )) )
       {
        piphdr->ipSrc = pmatch->target;
        ismatched = true;
       }

       if ( (pmatch = MatchFunc( piphdr->ipDst )) )
       {
        piphdr->ipDst = pmatch->target;
        ismatched = true;
       }

       if ( ismatched )
       {
        ++matchedcount;
        ismatched = {};
       }

      } /* IPv4 layer */

      // if ( auto * const pudp = parsedPacket.getLayerOfType<pcpp::UdpLayer>() ) // parsedPacket.isPacketOfType(pcpp::UDP) )
      // {
      //  auto * const pudphdr = pudp->getUdpHeader();
      //  DOUT( "SPORT: " << pudp->getSrcPort() << ", DPORT: " << pudp->getDstPort() << ", udplen: " << ntohs(pudphdr->length) );
      // }

      writerDev.writePacket(rawPacket);
         //    }
    } /* writer */

    writerDev.close();

    // закрыть файл
    reader.close();

    DOUT( "done, total count: " << i << ", matched: " << matchedcount );

    ret = EXIT_SUCCESS;
 } while ( 0 );

 return ret;

}

/* Local variables: */
/*  coding: koi8-r  */
/* end:             */
