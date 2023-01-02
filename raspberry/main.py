from socket import socket
from sys import argv
from scapy.all import *
from datetime import datetime, timedelta
from requests import post
from dotenv import dotenv_values
from hashlib import sha256
import json
import zdm

config = dotenv_values(".env")
endpoint = config["ENDPOINT"]
mode = config["MODE"]
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


def send_payload(scans, cred, device: zdm.ZDMClient = None):
    body = {
        "cred": cred,
        "payload": {
            "ts": int(datetime.now().timestamp()),
            "sum_rssi": sum([scan[4] for scan in scans]),
            "n_devices": len(scans),
            "scans": scans
        },
        "tag": "rssi"
    }
    if device is not None:
        device.publish(body['payload'], body['tag'])
        res = "OK"
    else:
        try:
            res = post(f"{endpoint}/api/device_interoperability/publish", json=body).json()
        except:
            res = "SERVER ERROR"
    scans.clear()
    return res

def create_scan(package):
    rssi = package[RadioTap].dBm_AntSignal
    src_mac = hash_func(package[Dot11].addr2)
    # flags, duration_id, sequence_ctr, source_mac_addr, RSSI, channel, payload_size
    return [0, 0, 0, src_mac, rssi, 0, 0]

def prn(scans: list, cred, device: zdm.ZDMClient = None):
    def callback(package):
        if not (package.haslayer(Dot11ProbeReq)):           # verify if is probe request
            return
        scan = create_scan(package)
        print("scan:", scan)
        scans.append(scan)
        global last_update
        if last_update + timedelta(seconds=time_gap_seconds) < datetime.now():
            print("send scans:", scans)
            res = send_payload(scans, cred, device)
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
        cred = load_cred()
        device = None
        if mode == "DIRECT":
            credential = zdm.Credentials(cred)
            device = zdm.ZDMClient(credential)
            device.connect()
        sniff(
            iface=iface,                    # selected net card
            prn=prn(scans, cred, device),
            monitor=True,
            store=0
        )

if __name__ == "__main__":
    main()