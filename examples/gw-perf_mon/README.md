Performance Monitor
==
Performance Monitor is an NF that stores and displays information about incoming packets regarding specific 
request types (GET/POST) and then sends them to another NF. The request type can be specified 
with a command-line argument. 

In certain cases, the performance monitor 
will display nothing for URL and host. This means that the specific packet
contained no information regarding to the specific request type.

Compilation and Execution
--
```
cd examples
make
cd gw-perf_mon
./go.sh SERVICE_ID -d DESTINATION_ID [-r REQUEST_TYPE]
```

Example of Execution
---
To test the performance monitor, two different pcap files have been added 
to the collection that specifically contains GET requests only. These 
can be located in ```examples/speed_tester/pcap```. They are 
```web_small.pcap``` and ```web_big.pcap```. 


App Specific Arguments
--
  - `-d <destination_id>`: Service ID to send packets to, e.g. `-d 2`
    sends packets to the NF using service ID 2
  - `-r <request_type>`: Specific request type (GET/POST) within a packet to parse for
    (default is GET) 

Config File Support
--
This NF supports the NF generating arguments from a config file. For
additional reading, see [Examples.md](../../docs/Examples.md)

See `../example_config.json` for all possible options that can be set.