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
        self.request = ''
        self.response = ''
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
            try:
                self.request = str((struct.unpack(">s", packet[66:67])[0]).decode('utf-8')) + str((struct.unpack(">s", packet[67:68])[0]).decode('utf-8')) + str((
            struct.unpack(">s", packet[68:69])[0]).decode('utf-8'))
                self.response = str((struct.unpack(">s", packet[66:67])[0]).decode('utf-8')) + str((
            struct.unpack(">s", packet[67:68])[0]).decode('utf-8')) + str((struct.unpack(">s", packet[68:69])[0]).decode('utf-8')) + str((
            struct.unpack(">s", packet[69:70])[0]).decode('utf-8'))
            except:
                pass

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

    def getRequest(self):
        return self.request

    def getResponse(self):
        return self.response


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


def reassemble(packets):
    q = collections.deque()
    res = {}

    for i in range(len(packets)):
        if packets[i].getRequest() == 'GET':
            q.append(packets[i])
        elif packets[i].getResponse() == 'HTTP':
            p = q.popleft()
            res[p] = packets[i]

    for key in res:
        print("GET REQUEST " + key.getSrcIP() + " " + key.getDestIP() + " " + key.getSeqNum() + " " + key.getAckNum())
        print("HTTP RESPONSE " + res[key].getSrcIP() + " " + res[key].getDestIP() + " " + res[key].getSeqNum() + " " +
              res[key].getAckNum())


def getData(packets):
    totalPayload = 0
    TCPconns = getTCPnum(packets)

    for i in range(len(packets)):
        totalPayload += packets[i].getSize()

    http = ''
    if TCPconns > 6:
        http = 'HTTP 1.0'
    elif 2 <= TCPconns <= 6:
        http = 'HTTP 1.1'
    else:
        http = 'HTTP 2.0'

    print("HTTP Type:", http)
    print("No of TCP connections:", TCPconns)
    print("Total Time Taken:", packets[-1].getTimeStamp() - packets[0].getTimeStamp())
    print("Number of Packets:", len(packets))
    print("Raw Data Size:", totalPayload)
    print('')


if __name__ == '__main__':
    file = open('http_1080_vipul.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)

    packets1 = []

    for timeStamp, record in pcap:
        packet = Packet()
        packet.extract(record, timeStamp)
        if packet.getIsValid() == True:
            packets1.append(packet)

    file = open('tcp_1081.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)

    packets2 = []

    for timeStamp, record in pcap:
        packet = Packet()
        packet.extract(record, timeStamp)
        if packet.getIsValid():
            packets2.append(packet)

    file = open('tcp_1082.pcap', 'rb')
    pcap = dpkt.pcap.Reader(file)

    packets3 = []

    for timeStamp, record in pcap:
        packet = Packet()
        packet.extract(record, timeStamp)
        if packet.getIsValid():
            packets3.append(packet)

    reassemble(packets1)
    print('')
    getData(packets1)
    getData(packets2)
    getData(packets3)
