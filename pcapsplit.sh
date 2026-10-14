#! /bin/bash
#
# @file    pcapsplit.sh
# @author  xxxxxxxxxxxxxxxxxxxxxxxxxx (mailto:xxxxxx@mail.ru)
# @ingroup
# @brief   Разделение pcap-файла на части
#
# Time-stamp: <>
# Time-stamp: <2026/10/12 10:02 agulevich> начало

die()
{
 echo "$@" >&2
 exit 1
}


editcap -t 460050000 --discard-packet-comments /tmp/gud_in1.cap /tmp/gud_out1.cap

#Пересчитать контрольные суммы (обязательно после смены IP):
for i in output*
do
 sed 's~DGW-1_08~Photon-A:985~g;s~172\.18\.1\.116~10\.10\.40\.3~g;s~172\.18\.1\.115~10\.10\.40\.57~g' "$i" > "sed-$i"
 tcprewrite --infile="sed-$i" --outfile="fixed-$i" --fixcsum
done

# склеить пакеты
mergecap -I none -a fixed-* -w result.pcap

# Local variables:
#  coding: koi8-r
# end:
