import pcap #pypcap 라이브러리
import sys

wlan_name = sys.argv[1]
sniffer = pcap.pcap(name= wlan_name, promisc=True, immediate=True, timeout_ms=50)

print("BSSID\t\t\tSSID\n")
airodump_mini=[]
list_value=[]
for ts, pkt in sniffer:
    if pkt[24:34].hex() == '80000000ffffffffffff':
        list_value.append(":".join('%02X' % i for i in pkt[40:46]))
        
        ssid_len_hex= pkt[61:62].hex()
        ssid_len = 60+int(ssid_len_hex,16)+2
        ssid = pkt[62:ssid_len].decode('utf-8',errors='ignore')

        list_value.append(ssid)
        if len(airodump_mini) == 0:
            airodump_mini = [list_value]
            print("\t".join(i for i in airodump_mini[-1]))
        else:
            for y in range(len(airodump_mini)):
                if list_value not in airodump_mini:
                    airodump_mini.append(list_value)
                    print("\t".join(i for i in airodump_mini[-1]))
                    break
                
         
        list_value=[]


