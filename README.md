# Security tools
Tools for Ethical Hacking

## Arp spoofer

The arp spoofer is used to become the man in the middle between a computer and the router this makes every packet that the router send to a computer to go through
your computer first and vice versa.
Then to do this we sent response ARP packets to both computer and router giving their ip but our mac address, so when one of then will send packet to one another
it will use the attacker MAC sending packet to him

## Code injector

The code injector inject some html code inside the html of a page that the victim is trying to access. To do this we use the arp spoofer to become the man in
the middle and modify the packets as then pass in our computer

## DNS spoofer

DNS spoofer is used to return the wrong IP in a DNS request. To achieve this we use the arp spoofer to become the man in the middle and change the ip
field in the packets that are returning from the DNS servers to victim computer
