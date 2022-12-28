from socket import socket
from sys import argv
from scapy.all import *
from datetime import datetime, timedelta
from requests import post
from dotenv import dotenv_values
from hashlib import sha256
import json

config = dotenv_values(".env")
endpoint = config["ENDPOINT"]
time_gap_seconds = int(config["TIME_GAP_SECONDS"])

last_update = datetime.now()

def hash_func(text):
    if text is None or len(text) == 0:
        return None
    h = sha256()
    h.update(str.encode(text))
    return h.hexdigest()

def load_cred():
    with open("zdevice.json") as file:
        return json.load(file)

def send_payload(scans):
    body = {
        "cred": load_cred(),
        "payload": {
            "ts": int(datetime.now().timestamp()),
            "sum_rssi": sum([scan[4] for scan in scans]),
            "n_devices": len(scans),
            "scans": scans
        },
        "tag": "rssi"
    }
    res = post(f"{endpoint}/api/publish", json=body)
    scans.clear()
    return res.json()

def create_scan(package):
    rssi = package[RadioTap].dBm_AntSignal
    src_mac = hash_func(package[Dot11].addr2)
    # flags, duration_id, sequence_ctr, source_mac_addr, RSSI, channel, payload_size
    return [0, 0, 0, src_mac, rssi, 0, 0]

def prn(scans: list):
    def callback(package):
        if not (package.haslayer(Dot11ProbeReq)):           # verify if is probe request
            return
        scan = create_scan(package)
        print("scan:", scan)
        scans.append(scan)
        global last_update
        if last_update + timedelta(seconds=time_gap_seconds) < datetime.now():
            print("send scans:", scans)
            res = send_payload(scans)
            print("server response:", res)
            last_update = datetime.now()
    return callback

def main():
    if len(argv) <= 1:
        # list net cards
        addrs = socket.if_nameindex()
        print(f'{len(addrs)} nets')
        for k, v in addrs:
            print(f' > {k}: {v}')
    else:
        # sniff on selected net card (iface)
        iface = argv[1]
        scans = []
        sniff(
            iface=iface,            # selected net card
            prn=prn(scans),
            monitor=True,
            store=0
        )

if __name__ == "__main__":
    main()