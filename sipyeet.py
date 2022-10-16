#!/usr/bin/env python3

from scapy.all import IP, UDP, TCP, send, conf
import argparse
import string
from random import choices, randint



parser = argparse.ArgumentParser()
parser.add_argument("-sp", type=int, default=5060, help="The source port")
parser.add_argument("-dp", type=int, default=5060, help="The destination port")
parser.add_argument("-tt", action="store_true", help="Transport TCP")
parser.add_argument("-dst", default="127.0.0.2", help="The destination IP")
parser.add_argument("-src", action="store_true", help="The source IP")
parser.add_argument("-c", type=int, default=1, help="Packet count per destination")

parser.add_argument("-fuser", type=str, default="yeet", help="SIP FROM User")
parser.add_argument("-tuser", type=str, default="yoink", help="SIP TO User")

parser.add_argument("--rfc2543", action="store_false", help="Stick to SIP/1.0 instead of 2.0 (RFC 3261)")

# Flow related arguments
parser.add_argument("--dry-run", action="store_true", help="Don't actually send packets.")
parser.add_argument("-v", action="store_true", help="Be more verbose about the yeetage.")

parser.parse_args()
args = parser.parse_args()

sourcePort = args.sp
sourceIp = False
destinationPort = args.dp
destinationIp = args.dst

def printd(s):
    if args.v:
        print(s)        

sipVersion = "2.0"
sipTag = ''.join(choices(string.ascii_letters + string.digits, k=32))
sipBranch = ''.join(choices(string.ascii_letters + string.digits, k=32))
sipCallId = ''.join(choices(string.ascii_lowercase + string.digits, k=32))
# This + SIP method would meet RFC3261 8.1.1.5 CSeq requirements
# But for now let's keep packet size deterministic.
#sipCSeq = randint(1, 2**31-1)
sipCSeq = randint(1000,9999)


# Try to figure out the sourceIp
if args.src:
    # Well that was easy! User kindly provided one!
    sourceIp = args.src
    printd("User provided source address: {0}".format(sourceIp))
else:
    # Ooof. Let's scrounge the interfaces and take the address of the one with default gw
    sourceIp = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0'][0]    
    if not sourceIp:
        # Big ooof. No adapter with default gw either, default to loopback
        printd("Couldn't figure out source address. Defaulting to loopback.")
        sourceIp = "127.0.0.1"
    else:
        printd("Dark blockchain AI figured out source address: {0}".format(sourceIp))

ip=IP(src=sourceIp, dst=destinationIp)

if not args.rfc2543:
    sipBranch = ("z9hG4bK{0}".format(sipBranch))
    sipVersion = "1.0"

if args.tt:
    transport = "tcp"
else:
    transport = "udp"

myPayload=(
    'OPTIONS sip:{0}:{1};transport={6} SIP/{12}\r\n'
    'Via: SIP/2.0/{7} {2}:{3};branch={8}\r\n'
    'From: \"{4}\"<sip:{4}@{2}:{3}>;tag={9}\r\n'
    'To: \"{5}\" <sip:{5}@{0}:{1}>\r\n'
    'Call-ID: {10}\r\n'
    'CSeq: {11} OPTIONS\r\n'
    'Content-Length: 0\r\n\r\n').format(destinationIp, destinationPort, sourceIp, sourcePort, 
        args.fuser, args.tuser, transport, transport.upper(), sipBranch, sipTag, sipCallId, sipCSeq, sipVersion)

printd("Payload to be yeeted:")
printd(myPayload)

if not args.dry_run:
    if transport=="tcp":
        # TCP SYN
        TCP_SYN=TCP(sport=sourcePort, dport=destinationPort, flags="S", seq=100)
        TCP_SYNACK=sr1(ip/TCP_SYN)

        # TCP SYN+ACK
        myAck = TCP_SYNACK.seq + 1
        TCP_ACK=TCP(sport=sourcePort, dport=destinationPort, flags="A", seq=101, ack=myAck)
        send(ip/TCP_ACK)

        TCP_PUSH=TCP(sport=sourcePort, dport=destinationPort, flags="PA", seq=101, ack=myAck)
        send(ip/TCP_PUSH/myPayload,count=args.c)
    else:
        UDP_PUSH=UDP(sport=sourcePort, dport=destinationPort)
        send(ip/UDP_PUSH/myPayload,count=args.c)
else:
    print("Dry run. No SIP UAs where harmed in the process of generating this message 🙃")
