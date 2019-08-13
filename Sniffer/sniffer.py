# -*- coding:utf-8 -*-
import socket
from struct import *
import datetime
import pcapy
import sys
import threading
import time

def main(argv):
    choice=int(input("请输入 ：\n1 离线工作模式\n2 在线工作模式\n"))
    if choice==1:
        pcapfile=input("请输入pcap文件名:\n")
        cap=pcapy.open_offline(pcapfile)
    if choice==2:
        devices = pcapy.findalldevs()
        print ("可用网卡:")
        for d in devices :
            print (d)   
        dev = input("请输入要监听的网卡:\n")
        print ("正在监听网卡 " + dev)
        cap = pcapy.open_live(dev, 65536 , 1 , 100)
    myfilter=input('请输入过滤表达式:\n')
    cap.setfilter(myfilter)
    t1=threading.Thread(target=loop,args=(cap,),name='LoopThread1')
    #t2=threading.Thread(target=loop,args=(cap,),name='LoopThread2')
    t1.start()
    #t2.start()
    t1.join()
    #t2.join()

def loop(cap):
    print ('thread %s is running...' % threading.current_thread().name)
    packetnum=0
    while(1) :
        (header, packet) = cap.next()

        try:
            print('第 %d 个数据包'%packetnum)
            parse_packet(packet)
            packetnum=packetnum+1
            
            
        except:
            continue
 
#转成冒号形式mac
def eth_addr (a) :
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % ((a[0]) , (a[1]) , (a[2]), (a[3]), (a[4]) , (a[5]))
    return b
 
#解析数据包
def parse_packet(packet) :
     
    #以太帧解析
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ('目标MAC : ' + eth_addr(packet[0:6]) + ' 源MAC : ' + eth_addr(packet[6:12]) + ' 协议类型 : ' + str(eth_protocol))
 
    #IP包
    if eth_protocol == 8 :
        print('IP报文')

        ip_header = packet[eth_length:20+eth_length]
         
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
 
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
 
        iph_length = ihl * 4
 
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
 
        print ('版本: ' + str(version) + ' IP 首部长度 : ' + str(ihl) + ' TTL : ' + str(ttl) + ' 协议类型 : ' + str(protocol) + ' 源地址 : ' + str(s_addr) + ' 目的地址 : ' + str(d_addr))
 
        #TCP 
        if protocol == 6 :
            print('TCP报文')
            t = iph_length + eth_length
            tcp_header = packet[t:t+20]
 
            tcph = unpack('!HHLLBBHHH' , tcp_header)
             
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
             
            print ('源端口 : ' + str(source_port) + ' 目的端口 : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
             
            h_size = eth_length + iph_length + tcph_length * 4
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print ('报文数据：' + str(data)+'\n')
 
        #ICMP
        elif protocol == 1 :
            print('ICMP报文')

            u = iph_length + eth_length
            icmph_length = 4
            icmp_header = packet[u:u+icmph_length]
 
            icmph = unpack('!BBH' , icmp_header)
             
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
             
            print ('类型 : ' + str(icmp_type) + ' Code : ' + str(code) + ' 校验值 : ' + str(checksum))
             
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print ('报文数据：' + str(data)+'\n')
 
        #UDP 
        elif protocol == 17 :
            print('UDP报文')

            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+udph_length]
 
            udph = unpack('!HHHH' , udp_header)
             
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]
             
            print ('源端口 : ' + str(source_port) + ' 目的端口 : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
             
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
             
            data = packet[h_size:]
             
            print ('报文数据：' + str(data)+'\n')
 
        #IGMP
        elif protocol==2:
            
            print('IGMP报文')
            u = iph_length + eth_length
            igmph_length = 4
            igmp_header = packet[u:u+4]         
            igmph = unpack('!BBH' , igmp_header)
            igmp_type = igmph[0]
            maxresptime = igmph[1]
            checksum = igmph[2]

            print ('类型 : ' + str(igmp_type) + ' 最大响应时间 : ' + str(maxresptime) + ' 校验值 : ' + str(checksum))

            h_size = eth_length + iph_length + igmph_length
            data_size = len(packet) - h_size

            #get data from the packet
            data = packet[h_size:]

            print ('组播地址: ' + data)

        else :
            print ('其他协议')
    else:#arp
        print("arp报文")
        arp_header=packet[eth_length:eth_length+28]
        arph = unpack('!HHBBH6s4s6s4s' , arp_header)
        op=arph[4]
        e_sender=arph[5]
        ip_sender=arph[6]
        e_dst=arph[7]
        ip_dst=arph[8]
        print("操作："+str(op)+' 发送方以太网地址：'+str(eth_addr(e_sender))+' 发送方的IP地址：'+str(socket.inet_ntoa(ip_sender))+' 接收方的以太网地址：'+str(eth_addr(e_dst))+' 接收方的IP地址：'+str(socket.inet_ntoa(ip_dst))+'\n')


if __name__ == "__main__":
    main(sys.argv)