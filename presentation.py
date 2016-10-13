import logging

class Presentation(object):
    """A simple presentation class"""
	
    def __init__(self):
        """initialization."""
        super(Presentation, self).__init__()
        self.name = 'presentation'

    def address(self, pkt):
        """Print info about packet's addresses"""
        _src = pkt.src
        _dst = pkt.dst
        print ("Source: %s, Destination: %s" % (_src,_dst))
        return   

    def showPkt(self, dpid, src, dst, in_port):
        """Print detailed information about a packet"""
        print
        print ("---> Pkt in handler: dpid %s, src: %s, dst: %s, port: %s" % (dpid, src, dst, in_port))
        print
        return

    def boot(self):
        """Marks the start of the experiment"""
        print("---> Starting Simple Switch custom")
        return

    def flowAdded(self, dp, in_port=0, ip_dst=0):
        """Show information about added flows"""
        print
        print ("---> Flow added: datapath %s, in_port: %s, dst: %s" % (dp, in_port, ip_dst))
        print
