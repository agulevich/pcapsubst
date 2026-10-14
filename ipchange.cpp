/*! @file    ipchange.cpp
 *  @author  xxxxxxxxxxxxxxxxxxxxxxxxxx (mailto:xxxxxx@mail.ru)
 *  @ingroup
 *  @brief   Подмена IP,MAC и строк в cap-файле
 *
 *  Time-stamp: <>
 *  Time-stamp: <2026/10/13 11:44 agulevich> начало
 *
 *  Сборка:
 *   ./make.sh
 *   https://pcapplusplus.github.io/v1904/Documentation/a01382.html
 *
 *  Для преобразования pcapng в pcap:
 *   $ tshark -r capture.pcapng -F xpbcap -w capture.pcap
 *
 *  Запуск:
 *   ./ipchange /tmp/in.cap -o -t /tmp/out.cap 10.10.43.4:172.18.12.12 's~8634423301~801~' 's~8634663302~802~' 's~10.10.43.4~172.18.12.12~' 'm~00:30:64:3b:04:a7~ff:ff:ff:ff:ff:ff~'
 */

// PcapPlusPlus
#include <EthLayer.h>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>
#include <SipLayer.h>
#include <UdpLayer.h>
// stl
#include <algorithm>
#include <array>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <string>
// c
#include <arpa/inet.h>

#define DOUT( LINE ) (std::cout << LINE << '\n')
#define EOUT( LINE ) (std::cerr << LINE << '\n')

using mac_t = std::array< uint8_t,6 >;

template< typename TVAL >
struct TValSubst
{
 using val_t = TVAL;

 val_t match;
 val_t target;

 bool Apply( val_t & SUBJ ) const;
}; /* struct TValSubst */

using SModIP  = TValSubst< uint32_t >;   /*!< @brief Замена IP */
using SModSTR = TValSubst< std::string >;/*!< @brief Замена строки */
using SModMAC = TValSubst< mac_t >;   /*!< @brief Замена MAC */

bool
ParseIP( std::string const __in,uint32_t & __out )
{
 in_addr addr;
 if ( inet_pton( AF_INET,__in.c_str(),&addr) <= 0 ) return false;
 __out = addr.s_addr;
 return true;
}

bool
ParsePair( std::string const & __in,SModIP & __out )
{
 bool ret = {};

 do
 {
  auto pos = __in.find( ':' );
  if ( pos == std::string::npos )
  {
   EOUT( "subst IP lost" );
   break;
  }

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

bool
_SplitBySym( char const * __prefix,std::string const & __in,std::string & __out1,std::string & __out2 )
{
 bool ret = {};

 do
 {
  if ( __in.empty() )
  {
   EOUT( "empty " << __prefix << " subst" );
   break;
  }

  char const delim   = __in[0];
  if ( *__in.rbegin() != delim )
  {
   EOUT( "unexpected format" );
   break;
  }

  auto const posmid = __in.find( delim,1 );
  if ( posmid == std::string::npos )
  {
   EOUT( "empty " << __prefix << " delimiter lost" );
   break;
  }

  __out1  = __in.substr( 1,posmid - 1 );
  if ( __out1.empty() )
  {
   EOUT( "empty " << __prefix << " match" );
   break;
  }

  __out2 = __in.substr( posmid + 1,__in.length() - 2 - posmid );

  ret = true;
 } while ( 0 );

 return ret;
}

bool
ParsePair( std::string const & __in,SModSTR & __out )
{
 return _SplitBySym( "string",__in,__out.match,__out.target );
}

bool
_ReadMAC( std::string const & __src, mac_t & __out )
{
 unsigned bnum    = {};
 uint8_t  byte    = {};
 unsigned symnum  = {};

 auto const bytefill
 =
 [&]( uint8_t val ) -> bool
 {
  bool ret = {};

  do
  {
   if ( symnum > 1 ) break;

   if ( !symnum ) byte = val;
   else
   {
    byte <<= 4;
    byte |= val;
   }

   ++symnum;
   ret = true;
  } while ( 0 );

  return ret;
 };

 auto const bytestore
 =
 [&]( void ) -> bool
 {
  if ( bnum < 6 )
  {
   __out[ bnum++ ] = byte;
   return true;
  }

  return false;
 };

 for ( char ch : __src )
 {
  switch ( ch )
  {
   default:
    break;

   case ':':
    bytestore();
    symnum = 0;
    continue;

   case '0' ... '9':
    if ( bytefill( ch - '0' ) ) continue;
    break;

   case 'a' ... 'f':
    if ( bytefill( ch - 'a' + 0xa ) ) continue;
    break;

   case 'A' ... 'F':
    if ( bytefill( ch - 'A' + 0xa ) ) continue;
    break;
  } /* switch ( ch ) */

  symnum = 0;
  break;
 }

 if ( symnum ) bytestore();

 return bnum == 6;
}

bool
ParsePair( std::string const & __in,SModMAC & __out )
{
 bool ret = {};

 do
 {
  std::string strmatch;
  std::string strtarget;

  if ( !_SplitBySym( "string",__in,strmatch,strtarget ) ) break;

  if ( !_ReadMAC( strmatch,__out.match) )
  {
   EOUT( "match MAC expected" );
   break;
  }

  if ( !_ReadMAC( strtarget,__out.target) )
  {
   EOUT( "target MAC expected" );
   break;
  }

  ret = true;
 } while ( 0 );

 return ret;
}

template< typename TVAL >
bool
TValSubst< TVAL >
::Apply( TVAL & __ ) const
{
 if ( this->match != __ ) return false;

 __ = this->target;
 return true;
}

template<>
bool
TValSubst< std::string >
::Apply( std::string & __ ) const
{
 bool   ret = {};

 auto const tlen = this->target.length();
 for ( size_t pos = {} ;; )
 {
  pos = __.find( this->match,pos );
  if ( pos == std::string::npos ) break;

  __.replace( pos,this->match.length(),this->target );
  pos += tlen;

  ret = true;
 } /* for */
 return ret;
}

template< typename TLIST >
bool
ApplyFunc( TLIST const & __list,typename TLIST::value_type::val_t & __val )
{
 bool ret = {};
 for ( auto it : __list )
  if ( it.Apply( __val ) ) ret = true;

 return ret;
};

int main( int __q, char ** __p )
{
 int ret = EXIT_FAILURE;

 do
 {
  if ( __q < 2 )
  {
   EOUT( "expected: " << __p[0] << " {FPATHIN} [-o {FPATHOUT}] [-t] [{IP:SUBST} ...] [{s~STR~SUBST~} ...] [{m~MAC~SUBST~~}]" );
   break;
  }

  __q -= 2;

  std::string fpathin    = *++__p;
  std::string fnameout   = "modified.cap";
  bool        tsact      = {};

  std::list< SModIP >  ipsubst;
  std::list< SModSTR > strsubst;
  std::list< SModMAC > ethsubst;

  auto FPathOutParse
  =
  [&]( char const * pch ) -> bool
  {
   fnameout = pch;
   return true;
  };

  int          i = 0;
  char         ch;
  char const * pch;
  std::function<bool(char const *)> parsearg;

  for ( i = 0,++__p; i < __q ; ++i,++__p )
  {
   pch = *__p;
   if ( parsearg )
   {
    if ( !parsearg( pch ) ) break;
    parsearg = {};
    continue;
   }

   if ( !*pch ) continue;

   switch ( (ch = *pch) )
   {
    default:
     EOUT( "unexpected ARGV: \"" << pch << '"' );
     pch = {}; // ошибка
     break;

    case 's' :
     if ( ParsePair( ++pch,(strsubst.emplace_back(),strsubst.back()) ) ) break;
     pch = {}; // ошибка
     break;

    case 'm' :
     if ( ParsePair( ++pch,(ethsubst.emplace_back(),ethsubst.back()) ) ) break;
     pch = {}; // ошибка
     break;

    case 'i' :
     ++pch;
     // [[fallthrough]]
    case '0'...'9' :
     if ( ParsePair( pch,(ipsubst.emplace_back(),ipsubst.back()) ) ) break;
     pch = {}; // ошибка
     break;

    case '-' : // opts
     switch ( ( ch = *++pch ) )
     {
      default:
       break;

      case 't':
      case 'T':
       tsact = true;
       continue;

      case 'o':
      case 'O':
       if ( *++pch == '\0' )
       {
        parsearg = FPathOutParse;
        continue;
       }

       if ( (ch=*pch++) != '=' && ch != ':' )
       {
        EOUT( "expected OFILE" );
        pch = {};
        break;
       }

       FPathOutParse( pch );
       continue;
     } /* switch ( ( ch = *++pch ) ) */
     break;
   } /* switch ( (ch = *pch) ) */

   if ( !pch ) break; // ошибка
  }

  if ( i != __q ) break;

  // открыть pcap-файл для чтения
  pcpp::PcapFileReaderDevice reader( fpathin );
  if ( !reader.open() )
  {
   EOUT( "Open error: " << std::quoted( fpathin ) );
   break;
  }

  // Читаем пакет и меняем поле len

  pcpp::PcapFileWriterDevice writerDev( fnameout );
  if ( !writerDev.open() )
  {
   EOUT( "write error: " << std::quoted( fnameout) );
   break;
  }

  DOUT( "gen file: " << std::quoted( fnameout ) );
  if ( tsact )
   DOUT( "TS actuating mode" );

  // прочитать первый (и единственный) пакет из файла
  pcpp::RawPacket   rawPacket;
  int               matchedcount = {};
  bool              ismatched;
  timespec          ts;
  std::time_t const startsec     = std::time( {} );
  long              deltasec     = {};
  unsigned          ploadsize;
  std::string       pload;
  int               rawdelta     = {};
  unsigned          packetnumber = {};

  for ( packetnumber = 0 ; reader.getNextPacket(rawPacket) ; ++packetnumber )
  {
   if ( !deltasec )
   {
    ts = rawPacket.getPacketTimeStamp();

    deltasec  = startsec;
    deltasec -= ts.tv_sec;
    DOUT( "delta: " << deltasec << " s" );
    //      DOUT( "local TS: " << std::put_time(std::localtime(&ts.tv_sec), "%c%Z") );
   }

   if ( tsact )
   {
    ts = rawPacket.getPacketTimeStamp();

    ts.tv_sec += deltasec;
    if ( !rawPacket.setPacketTimeStamp( ts ) ) EOUT( "feailed to set TS" );
   }

   for ( ;; )
   {
    if ( strsubst.empty() ) break;

    pcpp::Packet parsedPacket( &rawPacket );

    switch ( 0 ) default:
    {
     auto * const pudp = parsedPacket.getLayerOfType<pcpp::UdpLayer>();

     if ( !pudp ) break;

     auto * const pudphdr   = pudp->getUdpHeader();
     auto * const prawpload = pudp->getLayerPayload();

     if ( rawdelta )
     { // была подмена
      std::copy_n( pload.data(),pload.size(),(char*)prawpload );

      if ( auto * const pip = parsedPacket.getLayerOfType<pcpp::IPv4Layer>() )
      {
       auto * const piphdr = pip->getIPv4Header();
       piphdr->totalLength = ntohs( htons( piphdr->totalLength ) + rawdelta );

       auto * const pudphdr = pudp->getUdpHeader();
       pudphdr->length = htons( ntohs(pudphdr->length) + rawdelta );

       pudp->calculateChecksum( true );
      }

      rawdelta = {}; // изменение размера отработано
      break;
     }

     ploadsize = pudp->getLayerPayloadSize();
     pload.assign( (char*)prawpload,ploadsize );

     if ( !ApplyFunc( strsubst,pload ) ) break;

     //     DOUT( "SPORT: " << pudp->getSrcPort() << ", DPORT: " << pudp->getDstPort() << ", pktlen: " << ntohs(pudphdr->length) << ", ploadsize: " <<  );
     // uint8_t * pload = pudp->getLayerPayload();
     // for ( int i = 0 ; i < pudp->getDataLen() ; ++i,++pload )
     //  *pload = '-';

     ismatched = true;
     rawdelta  = ((ssize_t)pload.length() - ploadsize);
     if ( !rawdelta )
     {
      std::copy_n( pload.data(),ploadsize,(char*)prawpload );
      pload.clear();
      break; // удалось без изменения размера, значит ничего больше делать не нужно
     }

    // длина изменилась - всё нужно пересчитать
     DOUT( "pnum: " << packetnumber << ", ploaddelta: " << rawdelta );

     //     rawPacket.reallocateData( rawPacket.getFrameLength() + rawdelta );

     if ( rawdelta < 0 ) rawPacket.removeData( rawPacket.getRawDataLen() + rawdelta,(unsigned)-rawdelta );
     else
     {
      uint8_t const buff[ rawdelta ] = {};
      rawPacket.appendData( buff,sizeof(buff) );
     }

     continue; // rawdelta стал знаком того, что нужно пересчитать все поля
    } /* switch ( 0 ) default: */

    if ( !ipsubst.empty() )
     if ( auto * const pip = parsedPacket.getLayerOfType<pcpp::IPv4Layer>() )
     {
      auto * const piphdr = pip->getIPv4Header();

      if ( ApplyFunc( ipsubst,piphdr->ipSrc ) ) ismatched = true;
      if ( ApplyFunc( ipsubst,piphdr->ipDst ))  ismatched = true;

      if ( ismatched )
      {
       ++matchedcount;
       ismatched = {};
      }

     } /* IPv4 layer */

    if ( !ethsubst.empty() )
     if ( auto * const peth = parsedPacket.getLayerOfType<pcpp::EthLayer>() )
     {
      auto * const pethhdr = peth->getEthHeader();

      if ( ApplyFunc( ethsubst,*reinterpret_cast<mac_t*>( pethhdr->srcMac ) ) ) ismatched = true;
      if ( ApplyFunc( ethsubst,*reinterpret_cast<mac_t*>( pethhdr->dstMac ) ) ) ismatched = true;
     }

    break;
   } /* for modify */

   writerDev.writePacket(rawPacket);
  } /* writer */

  writerDev.close();

  // закрыть файл
  reader.close();

  DOUT( "done\ntotal count: " << packetnumber );
  if ( !ipsubst.empty() )
   DOUT( "matched: " << matchedcount );

  ret = EXIT_SUCCESS;
 } while ( 0 );

 return ret;

}

/* Local variables: */
/*  coding: koi8-r  */
/* end:             */
