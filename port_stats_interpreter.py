from operator import attrgetter
import math
import threading
import subprocess

PATH_TO_LOG = "/home/lsanabria/tarballs/ryu/ryu/app/log/"
EGRESS_THRESHOLD = 10e6

class myPlotThread(threading.Thread):
    """Plotting data from a file"""
    
    def __init__(self, filename):
        threading.Thread.__init__(self)
        self.filename = filename
        
    def run(self):
        """Calling the function that is actually going to plot"""
        
        self._call_plotter(self.filename)
    
    def _call_plotter(self, filename):
        """Calling feedgnuplot and pointing it to the file path"""
        
        dpid = int(filename)
        filename = str(PATH_TO_LOG) + str(filename) + ".dat"
        cmd = "while true; do tail " + str(filename) + " | awk '{print $1, $2}'; sleep 1; done | feedgnuplot --xlabel PortStatResponseNo --ylabel pkt_tx --nodomain --nodataid  --stream --title DPID-" + str(dpid) + " --legend 0 GW2 --legend 1 GW1"
        try:
            subprocess.call([str(cmd)], shell=True)
        except (KeyboardInterrupt, SystemExit):
            print "Feedgnuplot killed"

class myDataDumperThread (threading.Thread):
    """Handling the dump of data to a file"""
    
    def __init__(self, filename):
        threading.Thread.__init__(self)
        self.filename = filename
        self.output_file = None
    
    def run(self):
        """Calling the function to create the file at threading.Thread.start()"""
        
        self.output_file = self._createFile(self.filename)
    
    def _createFile(self, name):
        """Creating the file for dumping at init"""
        
        f = open(str(PATH_TO_LOG) + str(name) + ".dat", 'a+', 0)
        return f
    
    def _get_file(self):
        """File getter"""
        
        assert(self.output_file)
        return self.output_file

class PortStatsInterpreter(object):
    """A class for determining the output rate for a port"""
    
    def __init__(self, plot_stream=False):
        """Initialization"""
        
        super(PortStatsInterpreter, self).__init__()
        self.name = 'PortStatsInterpreter'
        self.plot_stream = plot_stream
        self.congestion_table = {}
        self.observed_dpid = []
        self.tx_bytes_of_port = {}
        self.tx_packets_of_port = {}
        self.rate_of_port = {}
        self.prev_tx_bytes_of_port = {}
        self.set_of_file_dumpers = {}
        self.set_of_plotters = {}
        
        self.set_boot = {}
        self.boot_tx_packets_of_port = {}

    
    def update_port_output_rate(self, sleep_time, dpid, body=0):
        """Updating the observed output rate of a port"""
        
        if dpid not in self.observed_dpid:
            self.observed_dpid.append(dpid)
            self.rate_of_port.setdefault(dpid, {})
            self.tx_bytes_of_port.setdefault(dpid, {})
            self.tx_packets_of_port.setdefault(dpid, {})
            self.set_boot.setdefault(dpid, False)
            self.boot_tx_packets_of_port.setdefault(dpid, {})
            self.prev_tx_bytes_of_port.setdefault(dpid, {})
            self.congestion_table.setdefault(dpid, {})
            self.set_of_file_dumpers[dpid] = myDataDumperThread(str(dpid))
            self.set_of_file_dumpers[dpid].start()
            self.set_of_plotters[dpid] = myPlotThread(str(dpid))
            if self.plot_stream:
                self.set_of_plotters[dpid].start()
            
        if body:
            for stat in sorted(body, key=attrgetter('port_no')):
                """
                print("dpid: %s, port: %s, rx_packets: %s, rx_bytes: %s, rx_errors: %s, tx_packets: %s, tx_bytes: %s, tx_errors: %s" % (dpid, stat.port_no, stat.rx_packets, stat.rx_bytes, stat.rx_errors, stat.tx_packets, stat.tx_bytes, stat.tx_errors))
                """
                if self.set_boot[dpid] == False:
                    self.boot_tx_packets_of_port[dpid][stat.port_no] = stat.tx_packets
                
                self.tx_packets_of_port[dpid][stat.port_no] = stat.tx_packets - self.boot_tx_packets_of_port[dpid][stat.port_no]
                self.tx_bytes_of_port[dpid][stat.port_no] = stat.tx_bytes
                self.congestion_table[dpid].setdefault(stat.port_no, False)
        
        self.set_boot[dpid] = True
        
        if not self.prev_tx_bytes_of_port[dpid]:
            for port in self.tx_bytes_of_port[dpid]:
                self.prev_tx_bytes_of_port[dpid][port] = self.tx_bytes_of_port[dpid][port]
            print("---> Registering the dpid for the first time")
            return
        
        dump_file = self.set_of_file_dumpers[dpid]._get_file()
        for port in self.tx_bytes_of_port[dpid]:
            _new = self.tx_bytes_of_port[dpid][port]
            _old = self.prev_tx_bytes_of_port[dpid][port]
            _new_rate = 0
            if _old != _new:
                _new_rate = abs(_new - _old) / sleep_time * 8
                self.prev_tx_bytes_of_port[dpid][port] = self.tx_bytes_of_port[dpid][port]
            self.rate_of_port[dpid][port] = _new_rate
            print("dpid: [%s]: current rate port [%s]: %s bps" % (str(dpid), str(port), self.rate_of_port[dpid][port]))
            
            if port <= 2:
                dump_file.write(str(self.tx_packets_of_port[dpid][port]) + ' ')
                #dump_file.write(str(self.rate_of_port[dpid][port]) + ' ')
            
            if _new_rate >= EGRESS_THRESHOLD:
                """Marking port as congested"""
                self.congestion_table[dpid][port] = True
            else:
                self.congestion_table[dpid][port] = False
        print
        dump_file.write("\n")
            
        
"""Private methods"""    

    
    
    
    