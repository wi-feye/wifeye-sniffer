# Raspberry-pi sniffer

## Prerequisite

Install requirements using command:
```
pip3 install -r requirements.txt
```

Download **zdevice.json** from zerynth cloud account related to zerynth device and place it on raspberry directory.

Set environment variables on file **.env**:
- ENDPOINT: server endpoint
- TIME_GAP_SECONDS: gap of time in seconds to store scans before send them to the endpoint server

## Run
To set device to monitor mode run script:
```
./monitor_mode_mac.sh
```
or 
```
./monitor_mode_linux.sh
```
according device operative system.
To run the sniffer launch command:
```
python3 main.py <NETCARD>
```
The command:
```
python3 main.py
```
list the available netcards inside the curent device.
