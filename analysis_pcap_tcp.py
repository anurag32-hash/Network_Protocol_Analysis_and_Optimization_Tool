import collections
import dpkt
import struct


class Packet:

    def __init__(self):
        self.headerSize = ''
        self.srcIP = ''
        self.destIP = ''
        self.srcPort = ''
        self.destPort = ''
        self.syn = ''
        self.ack = ''
        self.windowSize = ''
        self.seqNum = ''
        self.ackNum = ''
        self.size = ''
        self.ts = 0
        self.mss = ''
        self.isValid = False

    def extract(self, packet, timestamp):
        if len(packet) > 56:
            self.isValid = True
            self.headerSize = str(struct.unpack(">B", packet[46:47])[0])
            self.destIP = str(struct.unpack(">B", packet[30:31])[0]) + "." + \
                          str(struct.unpack(">B", packet[31:32])[0]) + "." + \
                          str(struct.unpack(">B", packet[32:33])[0]) + "." + str(struct.unpack(">B", packet[33:34])[0])
            self.srcPort = str(struct.unpack(">H", packet[34:36])[0])

            temp = "{0:16b}".format(int(str(struct.unpack(">H", packet[46:48])[0])))
            self.syn = temp[14]
            self.ack = temp[11]
            self.srcIP = str(struct.unpack(">B", packet[26:27])[0]) + "." + \
                         str(struct.unpack(">B", packet[27:28])[0]) + "." + \
                         str(struct.unpack(">B", packet[28:29])[0]) + "." + str(struct.unpack(">B", packet[29:30])[0])
            self.seqNum = str(struct.unpack(">I", packet[38:42])[0])
            self.ackNum = str(struct.unpack(">I", packet[42:46])[0])
            self.destPort = str(struct.unpack(">H", packet[36:38])[0])
            self.windowSize = str(struct.unpack(">H", packet[48:50])[0])
            self.size = len(packet)
            self.ts = timestamp
            self.mss = str(struct.unpack(">H", packet[56:58])[0])

    def getHeaderSize(self):
        return self.headerSize

    def getSrcIP(self):
        return self.srcIP

    def getDestIP(self):
        return self.destIP

    def getSrcPort(self):
        return self.srcPort

    def getDestPort(self):
        return self.destPort

    def getSyn(self):
        return self.syn

    def getAck(self):
        return self.ack

    def getSeqNum(self):
        return self.seqNum

    def getAckNum(self):
        return self.ackNum

    def getWindowSize(self):
        return self.windowSize

    def getSize(self):
        return self.size

    def getTimeStamp(self):
        return self.ts

    def getMSS(self):
        return self.mss

    def getIsValid(self):
        return self.isValid


def getTCPnum(packets):
    TCPnum = 0
    for i in range(len(packets)):
        if packets[i].getSyn() == '1' and packets[i].getAck() == '1':
            TCPnum += 1
    return TCPnum


def segregatePackets(packets):
    TCPconnections = collections.defaultdict(list)
    for i in range(len(packets)):
        key = str(int(packets[i].getDestPort()) + int(packets[i].getSrcPort()))
        TCPconnections[key].append(packets[i])
    return TCPconnections


def getCWND(TCPconnections):
    for key in TCPconnections:
        nums = TCPconnections[key]
        res = []

        for i in range(len(nums)):
            if nums[i].getSrcIP() == '130.245.145.12' and nums[i].getDestIP() == '128.208.2.198':
                seq = nums[i].getSeqNum()
            elif nums[i].getDestIP() == '130.245.145.12' and nums[i].getSrcIP() == '128.208.2.198':
                if int(nums[i].getAckNum()) - int(seq) != 1:
                    res.append(int(seq) - int(nums[i].getAckNum()))

        res = res[:10]

        print('For port', nums[0].getSrcPort(), 'first 10 congestion window sizes are:')
        for j in range(len(res)):
            print(res[j])
        print('')


def getRetransmissionNum(TCPconnections):
    for key in TCPconnections:
        nums = TCPconnections[key]

        seq = collections.defaultdict(int)
        ack = collections.defaultdict(int)

        for i in range(len(nums)):
            if nums[i].getSrcIP() == '130.245.145.12' and nums[i].getDestIP() == '128.208.2.198':
                seq[nums[i].getSeqNum()] += 1
            elif nums[i].getDestIP() == '130.245.145.12' and nums[i].getSrcIP() == '128.208.2.198':
                ack[nums[i].getAckNum()] += 1

        timeout = 0
        tripleAck = 0

        for s in seq.keys():
            if s in ack and ack[s] > 2:
                tripleAck += seq[s] - 1
            else:
                timeout += seq[s] - 1

        print('For port', nums[0].getSrcPort() + ':')
        print('Retransmissions due to Triple Duplicate Ack:', tripleAck)
        print('Retransmissions due to Timeout:', timeout)

        print('')


if __name__ == '__main__':
    file = open('assignment2.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)

    packets = []

    for timeStamp, record in pcap:
        packet = Packet()
        packet.extract(record, timeStamp)
        if packet.getIsValid() == True:
            packets.append(packet)

    res = getTCPnum(packets)
    print('Total Number of TCP Connections initiated from the sender:', res, '\n')

    TCPconnections = segregatePackets(packets)

    getCWND(TCPconnections)
    getRetransmissionNum(TCPconnections)
