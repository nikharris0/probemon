# probemon
A simple command line tool for monitoring and logging 802.11 probe frames

I decided to build this simple python script using scapy so that I could record 802.11 probe frames over a long period of time. This was specifically useful in my use case: proving that a person or device was present at a given location at a given time.

## Usage

```
usage: probemon.py [-h] [-i INTERFACE] [-t TIME] [-o OUTPUT] [-b MAX_BYTES]
                   [-c MAX_BACKUPS] [-d DELIMITER] [-f] [-s] [-r] [-D] [-l]
                   [-x MQTT_BROKER] [-u MQTT_USER] [-p MQTT_PASSWORD]
                   [-m MQTT_TOPIC] [-P FILENAME]

a command line tool for logging 802.11 probe request frames

optional arguments:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        capture interface
  -t TIME, --time TIME  output time format (unix, iso)
  -b MAX_BYTES, --max-bytes MAX_BYTES
                        maximum log size in bytes before rotating
  -c MAX_BACKUPS, --max-backups MAX_BACKUPS
                        maximum number of log files to keep
  -d DELIMITER, --delimiter DELIMITER
                        output field delimiter
  -f, --mac-info        include MAC address manufacturer
  -s, --ssid            include probe SSID in output
  -r, --rssi            include rssi in output
  -D, --debug           enable debug output
  -l, --log             enable scrolling live view of the logfile
  -P FILENAME, --pid FILENAME
                        save PID to file
  -x MQTT_BROKER, --mqtt-broker MQTT_BROKER
                        mqtt broker server
  -u MQTT_USER, --mqtt-user MQTT_USER
                        mqtt user
  -p MQTT_PASSWORD, --mqtt-password MQTT_PASSWORD
                        mqtt password
  -m MQTT_TOPIC, --mqtt-topic MQTT_TOPIC
                        mqtt topic
```

## systemd Service-File Example

```
[Unit]
Description=Probemon MQTT Service

[Service]
PIDFile=/run/probemon.pid
RemainAfterExit=no
Restart=on-failure
RestartSec=5s
ExecStart=/root/python/probemon/probemon.py -i mon0 --mac-info --ssid --rssi --mqtt-broker IP --mqtt-user USERNAME --mqtt-password PASSWORD --mqtt-topic TOPIC  --pid /run/probemon.pid
StandardOutput=null

[Install]
WantedBy=multi-user.target
Alias=probemon.servic
```
