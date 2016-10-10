# MyFirstRyuNetwork
First Ryu Network Implementation
---------------------------------

With this short Ryu Application you may overview different useful tricks, like matching Ipv4 addresses, or getting the UDP/TCP of a packet for debugging.

As this application manages an "in-progress" network testbed, the details of the topology will be added later.

L.
---------------------------------

The exp4.py Ryu App worked over a topology including only one OVSK switch.

The exp4-twoSwitches.py does just that. I'm figuring out the best way to handle mutiple forwarding paths with a single app file.
