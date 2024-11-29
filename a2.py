from struct import *
import sys

GLOBAL_HEADER = 24
PACKET_HEADER = 16
PACKET_DATA = 14

ETH = 14
IP = 20
GLOBAL_FORMAT = '<IHHIIII'


class IP_Header:
    src_ip = None #<type 'str'>
    dst_ip = None #<type 'str'>
    ip_header_len = None #<type 'int'>
    total_len = None    #<type 'int'>

    
    def __init__(self):
        self.src_ip = None
        self.dst_ip = None
        self.ip_header_len = 0
        self.total_len = 0
    
    def ip_set(self,src_ip,dst_ip):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
    
    def header_len_set(self,length):
        self.ip_header_len = length
    
    def total_len_set(self, length):
        self.total_len = length    
        
    def get_IP(self,buffer1,buffer2):
        src_addr = unpack('BBBB',buffer1)
        dst_addr = unpack('BBBB',buffer2)
        s_ip = str(src_addr[0])+'.'+str(src_addr[1])+'.'+str(src_addr[2])+'.'+str(src_addr[3])
        d_ip = str(dst_addr[0])+'.'+str(dst_addr[1])+'.'+str(dst_addr[2])+'.'+str(dst_addr[3])
        self.ip_set(s_ip, d_ip)
        
    def get_header_len(self,value):
        length = (value & 15)*4
        self.header_len_set(length)

    def get_total_len(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        length = num1+num2+num3+num4
        self.total_len_set(length)
 
class TCP_Header:
    src_port = 0
    dst_port = 0
    seq_num = 0
    ack_num = 0
    data_offset = 0
    flags = {}
    window_size =0
    checksum = 0
    ugp = 0
    
    def __init__(self):
        self.src_port = 0
        self.dst_port = 0
        self.seq_num = 0
        self.ack_num = 0
        self.data_offset = 0
        self.flags = {}
        self.window_size =0
        self.checksum = 0
        self.ugp = 0
    
    def src_port_set(self, src):
        self.src_port = src
        
    def dst_port_set(self,dst):
        self.dst_port = dst
        
    def seq_num_set(self,seq):
        self.seq_num = seq
        
    def ack_num_set(self,ack):
        self.ack_num = ack
        
    def data_offset_set(self,data_offset):
        self.data_offset = data_offset
        
    def flags_set(self,ack, rst, syn, fin):
        self.flags["ACK"] = ack
        self.flags["RST"] = rst
        self.flags["SYN"] = syn
        self.flags["FIN"] = fin
    
    def win_size_set(self,size):
        self.window_size = size
        
    def get_src_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.src_port_set(port)
        #print(self.src_port)
        return None
    
    def get_dst_port(self,buffer):
        num1 = ((buffer[0]&240)>>4)*16*16*16
        num2 = (buffer[0]&15)*16*16
        num3 = ((buffer[1]&240)>>4)*16
        num4 = (buffer[1]&15)
        port = num1+num2+num3+num4
        self.dst_port_set(port)
        #print(self.dst_port)
        return None
    
    def get_seq_num(self,buffer):
        seq = unpack(">I",buffer)[0]
        self.seq_num_set(seq)
        #print(seq)
        return None
    
    def get_ack_num(self,buffer):
        ack = unpack('>I',buffer)[0]
        self.ack_num_set(ack)
        return None
    
    def get_flags(self,buffer):
        value = unpack("B",buffer)[0]
        fin = value & 1
        syn = (value & 2)>>1
        rst = (value & 4)>>2
        ack = (value & 16)>>4
        self.flags_set(ack, rst, syn, fin)
        return None
    
    def get_window_size(self,buffer1, buffer2):
        buffer = buffer2+buffer1
        size = unpack('H',buffer)[0]
        self.win_size_set(size)
        return None
        
    def get_data_offset(self,buffer):
        value = unpack("B",buffer)[0]
        length = ((value & 240)>>4)*4
        self.data_offset_set(length)
        #print(self.data_offset)
        return None
    
    def relative_seq_num(self,orig_num):
        if(self.seq_num>=orig_num):
            relative_seq = self.seq_num - orig_num
            self.seq_num_set(relative_seq)
        #print(self.seq_num)
        
    def relative_ack_num(self,orig_num):
        if(self.ack_num>=orig_num):
            relative_ack = self.ack_num-orig_num+1
            self.ack_num_set(relative_ack)
   

class packet():
    
    #pcap_hd_info = None
    IP_header = None
    TCP_header = None
    timestamp = 0
    packet_No = 0
    RTT_value = 0
    RTT_flag = False
    buffer = None
    size = 0
    
    
    def __init__(self):
        self.ip = IP_Header()
        self.tcp = TCP_Header()
        #self.pcap_hd_info = pcap_ph_info()
        self.timestamp = 0
        self.packet_No =0
        self.RTT_value = 0.0
        self.RTT_flag = False
        self.buffer = None
        
    def timestamp_set(self,buffer1,buffer2,orig_time):
        seconds = unpack('I',buffer1)[0]
        microseconds = unpack('<I',buffer2)[0]
        self.timestamp = round(seconds+microseconds*0.000001-orig_time,6)
        #print(self.timestamp,self.packet_No)
    def packet_No_set(self,number):
        self.packet_No = number
        #print(self.packet_No)

    def setSize(self,s):
        self.size = s
        
    def get_RTT_value(self,p):
        rtt = p.timestamp-self.timestamp
        self.RTT_value = round(rtt,8)



def getpackhead(data):
    ts_sec = data[0:4]
    ts_usec = data[4:8]
    incl_len = data[8:12]
    orig_len = data[12:16]
    
    return ts_sec, ts_usec, incl_len, orig_len

def getIPhead(data):
    length = data[0]
    totalLength = data[2:4]
    flags = data[6]
    ttl = data[8]
    protocol = data[9]
    src = data[12:16]
    dest = data[16:20]

    return length, totalLength, flags, ttl, protocol, src, dest


def getTCPhead(data):
    src_port = data[0:2]
    dst_port = data[2:4]
    seq_num = data[4:8]
    ack_num = data[8:12] 
    flags = data[13:14]
    window_size1 = data[14:15]
    window_size2 = data[15:16]
    checksum = data[16:18]
    urg_pointer = data[18:20]
    data_offset = (data[12] >> 4) * 4 

    return src_port, dst_port, seq_num, ack_num, flags, window_size1, window_size2, checksum, urg_pointer, data_offset


def getInfo(cap: str):
    packets = []
    origTime = 0

    with open(cap, 'rb') as cap:
        glob = cap.read(GLOBAL_HEADER)
        magicNum, versionMaj, versionMin, thiszone, sigfigs, snaplen, network = unpack(GLOBAL_FORMAT, glob)
        if magicNum == 0xA1B2C3D4:
            end = '<'
        elif magicNum == 0xD4C3B2A1:
            end = '>'
        else:
            print("Unknown byte order")
            exit(1)
        
        while True:
            p = packet()
            p.packet_No_set(len(packets)+1)
            packhead = cap.read(PACKET_HEADER)

            if not packhead:
                break
            
            ##############
            # Packet header

            ts_sec, ts_usec, incl_len, orig_len = getpackhead(packhead)

            if len(packets) == 0:
                sec = unpack('I', ts_sec)[0]
                usec = unpack('I', ts_usec)[0]
                origTime = sec+usec*0.000001

            # Get timestamp
            p.timestamp_set(ts_sec, ts_usec, origTime)

            # Packet data
            incl_len = unpack(end + 'I', incl_len)[0]
            packdata = cap.read(incl_len) # Read entire packet data
            
            ###########
            # IP header

            ipdata = packdata[ETH:IP+ETH] # skip eth header

            vihl, totalLength, flags, ttl, protocol, srcip, destip = getIPhead(ipdata)

            # ip total len
            headerlen = (vihl & 0x0F)*4
            p.ip.header_len_set(headerlen)
            p.ip.get_total_len(totalLength)

            # Get source and destination ip
            p.ip.get_IP(srcip, destip)

            ############
            # TCP header

            src_port, dst_port, seq_num, ack_num, tflags, window_size1, window_size2, checksum, urg_pointer, data_offset = getTCPhead(packdata[IP+ETH:])

            # src port
            p.tcp.get_src_port(src_port)

            # dst port
            p.tcp.get_dst_port(dst_port)

            # sequence number
            p.tcp.get_seq_num(seq_num)

            # ack number
            p.tcp.get_ack_num(ack_num)

            # window size
            p.tcp.get_window_size(window_size1, window_size2)
            
            # offset
            p.tcp.data_offset_set(data_offset)

            # flags
            p.tcp.get_flags(tflags)

            # size
            p.setSize(p.ip.total_len - (p.ip.ip_header_len + p.tcp.data_offset))

            packets.append(p)

    return packets

def getStatus(packets):
    syn = 0
    fin = 0  
    reset = 0 
    end = 0
    
    for packet in packets:
        flags = packet.tcp.flags
        if flags['SYN'] == 1:
            syn += 1
        if flags['FIN'] == 1:
            fin += 1
            end = packet.timestamp
        if flags['RST'] == 1:
            reset += 1
    
    r = 'S%dF%d' % (syn,fin)
    
    if reset:
        r += '/R'
        
    return r, end, reset

def count(traffic, c, connections):
    s2d = 0
    d2s = 0
    sbd = 0
    dbs = 0

    i=0
    for t in traffic[c]:
        if t[0] != connections[c][1].ip.src_ip: # if source ip from traffic equals source ip in c
            s2d+=1
            sbd += connections[c][i].size 
        else:
            d2s+=1
            dbs += connections[c][i].size

        i+=1

    return s2d, d2s, sbd, dbs

def connTup(packet):
    src_ip = packet.ip.src_ip
    dst_ip = packet.ip.dst_ip
    src_port = packet.tcp.src_port
    dst_port = packet.tcp.dst_port

    flip = False

    tup = (src_ip, str(src_port), dst_ip, str(dst_port))
    direction = (tup[0], tup[2], flip)
    key = tuple(sorted(tup))

    return key, direction
    
def getConns(packets):
    connections = {}
    traffic = {}
    complete = 0
    for p in packets:
        key, direction = connTup(p)
        

        if key not in connections:
            connections[key] = []
            traffic[key] = []

        connections[key].append(p)
        traffic[key].append(direction)

    print()
    print()
    print()
    print()
    print()
    print('A) Total number of connections:', len(connections))
    print('________________________________________________')
    print()

    print("B) Connection's details")
    print()
    n=1
    reset = 0
    complete = []
    for c in connections:
        status, end, r = getStatus(connections[c])
        if r:
            reset+=1
        s2d, d2s, sbd, dbs = count(traffic, c, connections)

        
        print('Connection %d:'% n)
        comp = output(c, status, connections[c][0].timestamp, end, s2d, d2s, sbd, dbs, traffic)
        if comp:
            complete.append({c:connections[c]})

        if n != len(connections):
            print('++++++++++++++++++++++++++++++++')

        n+=1

    return complete, reset, len(connections)
        

def output(c, status, start, end, s2d, d2s, sbd, dbs, traffic):
    srcip = traffic[c][0][0]
    dstip = traffic[c][0][1]
    srcport = c[0]
    dstport = c[3]

    print('Source Address:', srcip)
    print('Destination Address:', dstip)
    print('Source Port:', srcport)
    print('Destination Port:', dstport)
    print('Status:', status)
    if status[2:4] == 'F0':
        return False
    print('Start time:', start, 'seconds')
    print('End Time:', end, 'seconds')
    print("Duration:", round(end-start,6), 'seconds')
    print("Number of packets sent from Source to Destination:", s2d)
    print("Number of packets sent from Destination to Source:", d2s)
    print("Total number of packets:", s2d+d2s)
    print("Number of data bytes sent from Source to Destination:", sbd)
    print("Number of data bytes sent from Destination to Source:", dbs)
    print("Total number of data bytes:", sbd+dbs)
    print('END')
    return True

def general(complete, reset, conns):
    print('________________________________________________')
    print()
    print('C) General')
    print()
    print('Total number of complete TCP connections:',len(complete))
    print('Number of reset TCP connections:',reset)
    print('Number of TCP connections that were still open when the trace capture ended:',conns-len(complete))
    print('________________________________________________')


def TCPcomplete(complete):
    durations = []
    rtts = []
    sendt = {}
    packsperconn = []
    winsizes = []
    s= None # first SYN

    for i in complete:
        for c in i:
            _,end,_ = getStatus(i[c]) # last fin timestamp
            start = i[c][0].timestamp # first packet
            duration = end - start
            durations.append(duration)

            for p in i[c]:
                winsizes.append(p.tcp.window_size) # win size

                seq = p.tcp.seq_num
                ack = p.tcp.ack_num
                t = p.timestamp

                if p.tcp.flags['SYN'] and s is None: 
                    s = seq
                    sendt[s] = t
                
                if s is not None: # continue unless waiting for ack
                    if p.tcp.flags['ACK'] == 1: # continue unless ack is found
                        # rtt = current time - time of first SYN
                        rtt = t-sendt[s]
                        rtts.append(rtt)
                        # remove first SYN
                        del sendt[s]
                        s = None
                
            packsperconn.append(len(i[c]))

    mind = min(durations)
    meand = sum(durations) / len(durations)
    maxd = max(durations)

    minrtt = min(rtts)
    meanrtt = sum(rtts) / len(rtts)
    maxrtt = max(rtts)
    
    minp = min(packsperconn)
    meanp = sum(packsperconn) / len(packsperconn)
    maxp = max(packsperconn)

    minwin = min(winsizes)
    meanwin = sum(winsizes) / len(winsizes)
    maxwin = max(winsizes)

    return mind, meand, maxd, minp, meanp, maxp, minwin, meanwin, maxwin, minrtt, meanrtt, maxrtt

def dout(mind, meand, maxd, minp, meanp, maxp, minwin, meanwin, maxwin, minrtt, meanrtt, maxrtt):
    print()
    print('D) Complete TCP connections')
    print()
    print('Minimum time duration:', round(mind,6), 'seconds')
    print('Mean time duration:', round(meand, 6), 'seconds')
    print('Maximum time duration:', round(maxd, 6), 'seconds')
    print()
    print('Minimum RTT value:', round(minrtt,6))
    print('Mean RTT value:', round(meanrtt,6))
    print('Maximum RTT value:', round(maxrtt,6))
    print()
    print('Minimum number of packets including both send/received:', minp)
    print('Mean number of packets including both send/received:', meanp)
    print('Maximum number of packets including both send/received:', maxp)
    print()
    print('Minimum receive window size including both send/received:', minwin, 'bytes')
    print('Mean receive window size including both send/received:', round(meanwin,6), 'bytes')
    print('Maximum receive window size including both send/received:', maxwin, 'bytes')
    print('________________________________________________')
    print()
    print()
    print()
    print()
    print()


def main():
    if len(sys.argv) > 1:
        capfile = sys.argv[1]
    else:
        print('Missing .cap file argument in stdin')
        return
    # A and B
    packets = getInfo(capfile)
    complete, reset, numconns = getConns(packets)
    # C
    general(complete, reset, numconns)
    # D
    mind, meand, maxd, minp, meanp, maxp, minwin, meanwin, maxwin, minrtt, meanrtt, maxrtt = TCPcomplete(complete)
    dout(mind, meand, maxd, minp, meanp, maxp, minwin, meanwin, maxwin, minrtt, meanrtt, maxrtt)


if __name__ == '__main__':
    main()