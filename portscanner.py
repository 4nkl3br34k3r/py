#dependencias: python-setuptools, python-nmap
import optparse
import nmap

def nmapScan(tgtHost, tgtPort):
    nScan = nmap.PortScanner()
    nScan.scan(tgtHost, tgtPort)
    state = nScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print " [*] " + tgtHost + " tcp/" + tgtPort + " " +state

def main():
    parser = optparse.OptionParser('usage %prog '+ '-H <host> -p <porta>')
    parser.add_option('-H', dest = 'tgtHost', type='string', help='especifique o host')
    parser.add_option('-p', dest = 'tgtPort', type='string', help='especifique a[s] porta[s] separadas por virgula')
    (options, args) = parser.parse_args()
    if (options.tgtHost == None) | (options.tgtHost == 'localhost') | (options.tgtPort == None):
        print parser.usage
        exit(0)
    else:
        tgtHost = options.tgtHost
        tgtPorts = str(options.tgtPort).split(',')
    
    for tgtPort in tgtPorts:
        nmapScan(tgtHost,tgtPort)

if __name__ == '__main__':
    main()
    
    
                                   