MTD Initial commit is located in : https://github.com/deivanai/mtd_sdn_floodlight/blob/master/src/main/java/net/floodlightcontroller/mtd/mtd.java
 
Project Goal : 

Minimum working model : 
1. With simple topology of two hosts connected to single switch. Controller maintains the real to virtual mappings and host attachments. when one host ping other with virtual IP address, ping is successful without both the host learning other's real IP address. 
we should be able to inspect the openflow messages using wireshark and test ping with mininet.
Its assumed that DNS request is already intercepted and host enquiring through domain names have already got only the virtual IP address for the destination.

Enhancements : 
1. Add random algorithm to dynamically select virtual IP address
2. Add mechanism to learn and update host attachments to a switch
3. Add mechanism to expire the flow rules and update new set up virtual IP for known hosts.
4. Add mechanism for authorized access using real IP address 
5. Stretch goal - add mechanism for DNS request interception.

