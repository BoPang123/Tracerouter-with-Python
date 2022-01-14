# --coding:utf-8--

import socket
import os
import struct
import time
import select

# ICMP echo_request
TYPE_ECHO_REQUEST = 8
CODE_ECHO_REQUEST_DEFAULT = 0
# ICMP echo_reply
TYPE_ECHO_REPLY = 0
CODE_ECHO_REPLY_DEFAULT = 0
# ICMP overtime
TYPE_ICMP_OVERTIME = 11
CODE_TTL_OVERTIME = 0
# ICMP unreachable
TYPE_ICMP_UNREACHED = 3

MAX_HOPS = 30  # set max hops-30
TRIES = 3  # detect 3 times


# checksum

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count + 1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    answer = socket.htons(answer)

    return answer
# construct ICMP datagram
def build_packet():
    my_checksum = 0
    my_id = os.getpid()
    my_seq = 1
    my_header = struct.pack("bbHHh", TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST_DEFAULT, my_checksum, my_id, my_seq)
    my_data = struct.pack("d", time.time())
    package = my_header + my_data
    my_checksum = checksum(package)
    my_checksum = socket.htons(my_checksum)
    my_header = struct.pack("bbHHh", TYPE_ECHO_REQUEST, CODE_ECHO_REQUEST_DEFAULT, my_checksum, my_id, 1)
    ip_package = my_header + my_data
    return ip_package


def main(hostname):
    print("routing {0}[{1}](max hops = 30, detect tries = 3)".format(hostname, socket.gethostbyname(hostname)))
    for ttl in range(1, MAX_HOPS):
        print("%2d" % ttl, end="")
        for tries in range(0, TRIES):
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
            icmp_socket.settimeout(TIMEOUT)
            icmp_package = build_packet()
            icmp_socket.sendto(icmp_package, (hostname, 0))
            start_time = time.time()
            select.select([icmp_socket], [], [], TIMEOUT)
            end_time = time.time()
            # compute time of receiving
            during_time = end_time - start_time
            if during_time >= TIMEOUT or during_time == 0:
                print("    *    ", end="")
            else:
                print(" %4.0f ms " % (during_time * 1000), end="")
            if tries >= TRIES - 1:
                try:
                    ip_package, ip_info = icmp_socket.recvfrom(1024)
                except socket.timeout:
                    print(" request time out")
                else:
                    # extract ICMP header from IP datagram
                    icmp_header = ip_package[20:28]

                    # unpack ICMP header
                    Type, Code, Checksum, ID, Sequence = struct.unpack("bbHHh", icmp_header)
                    try:
                        host_info = socket.gethostbyaddr(ip_info[0])
                    except socket.error as e:
                        output = '{0}'.format(ip_info[0])
                    else:
                        output= '{0} ({1})'.format(ip_info[0], host_info[0])

                    if Type == TYPE_ICMP_UNREACHED:
                        print("Wrong!unreachable destination!")
                        break
                    elif Type == TYPE_ICMP_OVERTIME:
                        try:
                            host = socket.gethostbyaddr(output)
                            print(host)
                        except Exception as e:
                            #print(e)
                            pass
                        print(" %s" % output)
                        continue
                    elif Type == 0:  # type_echo
                        print(" %s" % output)
                        print("program run over!")
                        return
                    else:
                        print("request timeout")
                        print("program run wrongly!")
                        return


if __name__ == "__main__":
    while True:
        try:
            hostName = input("please input a hostname address:")
            global TIMEOUT
            TIMEOUT = int(input("Input timeout you want: "))
            main(hostName)
            break
        except Exception as error:
            print(error)
            continue