#!/usr/bin/python3
import socket
from pyrad.packet import AuthPacket
from pyrad.dictionary import Dictionary
import logging
import hashlib
import threading
import time
import json
from pyMAuthN import *


# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("RADIUS Server")
adminfile = '/etc/rad/admin.json'
urlfile='/etc/rad/url.conf'

import ipaddress
import bisect

def ip_matches_any(ip, ip_or_cidr_list):
    if '*' in ip_or_cidr_list:
        return True
    ip_obj = ipaddress.ip_address(ip)
    exact_ips = set()
    cidr_list = []

    for entry in ip_or_cidr_list:
        try:
            if '/' in entry:
                cidr_list.append(ipaddress.ip_network(entry, strict=False))
            else:
                exact_ips.add(ipaddress.ip_address(entry))
        except ValueError:
            continue  # skip invalid entries

    if ip_obj in exact_ips:
        return True

    # Sort by network address and prefix length
    cidr_list.sort(key=lambda net: (net.network_address, -net.prefixlen))

    # Binary search using bisect
    cidr_net_addrs = [net.network_address for net in cidr_list]
    pos = bisect.bisect_right(cidr_net_addrs, ip_obj)

    # Check previous and current pos for containment
    for idx in [pos - 1, pos]:
        if 0 <= idx < len(cidr_list) and ip_obj in cidr_list[idx]:
            return True

    return False

# Custom authentication function (simulates up to 10-minute delay if needed)
def custom_auth(username, client_ip):
    logger.info(f"Passing to custom auth: username={username}, client_ip={client_ip}")
    # Simulate potential long delay (e.g., external validation)
    #time.sleep(6)  # 10 minutes for testing; replace with real logic if variable
    fl = open(adminfile, 'r')
    adminlist = json.load(fl)
    fl.close()
    ul=open(urlfile,'r')
    customurl=ul.read()
    ul.close()
    if username in adminlist and ip_matches_any(client_ip, adminlist.get(username)):
        try:
            return verifyUser(customurl, username, 'RADIUS Auth to '+client_ip)
        except:
            return False
    return False

def compute_reply_authenticator(code, pkt_id, length, request_authenticator, attributes, secret):
    """Compute the Response Authenticator as per RADIUS spec."""
    md5_hash = hashlib.md5()
    md5_hash.update(bytes([code, pkt_id]) + length.to_bytes(2, 'big'))
    md5_hash.update(request_authenticator)
    md5_hash.update(attributes)
    md5_hash.update(secret.encode('utf-8'))
    return md5_hash.digest()

def process_packet(data, addr, sock):
    dictionary = Dictionary("/etc/rad/dictionary")
    SHARED_SECRET = "anysecret"

    try:
        # Parse incoming packet
        pkt = AuthPacket(packet=data, dict=dictionary)
        logger.debug(f"Parsed packet: code={pkt.code}, id={pkt.id}, authenticator={pkt.authenticator.hex()}")

        # Handle Access-Request (code 1)
        if pkt.code == 1:  # Access-Request
            username = pkt["User-Name"][0] if "User-Name" in pkt else "unknown"
            client_ip = addr[0]
            logger.info(f"Received request: username={username}, client_ip={client_ip}")

            # Handle follow-up requests with State (from challenges)
            if "State" in pkt:
                logger.info(f"Received follow-up with State: {pkt['State'][0]}")
                # Keepalive thread is already running; wait for final response

            else:

                # Perform authentication
                auth_result = custom_auth(username, client_ip)

                # Send final response
                reply_code = 2 if auth_result else 3  # 2 = Accept, 3 = Reject
                reply = AuthPacket(code=reply_code, id=pkt.id, dict=dictionary)
                reply.authenticator = pkt.authenticator

                if auth_result:
                    reply["Service-Type"] = "Login"
                    reply.AddAttribute("Cisco-AVPair", "shell:priv-lvl=15")
                    reply["Reply-Message"] = "Admin access granted"
                else:
                    reply["Reply-Message"] = "Authentication failed"

                reply_data = reply.ReplyPacket()
                length = len(reply_data)
                attributes = reply_data[20:]
                reply_authenticator = compute_reply_authenticator(
                    reply_code, pkt.id, length, pkt.authenticator, attributes, SHARED_SECRET
                )
                reply_data = reply_data[:4] + reply_authenticator + reply_data[20:]

                sock.sendto(reply_data, addr)
                logger.info(f"Sent {'Accept' if auth_result else 'Reject'} to {addr}")

        else:
            logger.debug(f"Ignoring non-Access-Request packet: code={pkt.code}")

    except Exception as e:
        logger.error(f"Error processing packet from {addr}: {e}", exc_info=True)

def run_server():
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 1812))
    logger.info("RADIUS Server starting on 0.0.0.0:1812...")

    while True:
        data, addr = sock.recvfrom(4096)
        logger.debug(f"Received packet from {addr}, length={len(data)}")
        tr = threading.Thread(target=process_packet, args=(data, addr, sock))
        tr.start()

if __name__ == "__main__":
    run_server()
