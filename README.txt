Author NetlinkID: alexandergarrettt

DESCRIPTION:
a2.py is a tool for analyzing .cap capture files

USAGE:
Navigate to same directory that a2.py is stored.
To use call, use python3 and pass your website through stdin:

 % python3 a2.py {your wireshark capture}.cap

Smart Client will print 
A) Total number of connections:
B) Connections' details:
Connection 1:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:
(Only if the connection is complete provide the following information)
Start time:
End Time:
Duration:
Number of packets sent from Source to Destination:
Number of packets sent from Destination to Source:
Total number of packets:
Number of data bytes sent from Source to Destination:
Number of data bytes sent from Destination to Source:
Total number of data bytes:
END
...
Connection N:
......
C) General
Total number of complete TCP connections:
Number of reset TCP connections:
Number of TCP connections that were still open when the trace capture ended:
D) Complete TCP connections:
Minimum time duration:
Mean time duration:
Maximum time duration:
Minimum RTT value:
Mean RTT value:
Maximum RTT value:
Minimum number of packets including both send/received:
Mean number of packets including both send/received:
Maximum number of packets including both send/received:
Minimum receive window size including both send/received:
Mean receive window size including both send/received:
Maximum receive window size including both send/re
