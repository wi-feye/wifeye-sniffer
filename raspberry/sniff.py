from socket import socket
from sys import argv
from scapy.all import *
from datetime import datetime

def prn(package):
    if not (package.haslayer(Dot11ProbeReq)):           # verify if is probe request
        return
    time = datetime.fromtimestamp(package.time)
    rssi = package[RadioTap].dBm_AntSignal
    src_mac = package[Dot11].addr2
    ap_mac = package[Dot11].addr1                       # useless because is all F
    try:
        ssid = package[Dot11].info.decode("utf-8") 
    except Exception:
        ssid = ''
    print(f'time: {time}', f'rssi: {rssi:2}dBm', f'src: {src_mac}', f'ap: {ap_mac}', f'ssid: {ssid}', sep='\t')
    # format and send information with zdm
    # format body to send to zdm:
    # {
    #   "ts": timestamp in milliseconds
    #   "sum_rssi": rssi sum
    #   "n_devices": scan list
    #   "scans": [
    #       [0, 0, 0, hash_sha256(mac_address), rssi, 0, 0] # flags, duration_id, sequence_ctr, source_mac_addr, RSSI, channel, payload_size
    #   ]
    # }

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
        sniff(
            iface=iface,            # selected net card
            prn=prn,
            monitor=True,
            store=0
        )

if __name__ == "__main__":
    main()