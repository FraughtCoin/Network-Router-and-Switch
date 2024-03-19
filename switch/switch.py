#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

cam_table = {}
interfaces_vlan = {}
trunk_interfaces_type = {}

priority = 0
own_bridge_id = 0
root_bridge_id = 0
root_path_cost = 0
root_port = 0

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    global priority
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global root_port

    while True:
        if own_bridge_id == root_bridge_id:
            for i in trunk_interfaces_type:
                trunk_interfaces_type[i] = 'D'

        if own_bridge_id == root_bridge_id:
            for i in trunk_interfaces_type:
                packet = create_bdpu_packet(root_bridge_id, own_bridge_id, i)
                send_to_link(i, packet, 52)

        time.sleep(1)

def create_bdpu_packet(root, sender, port):
    global priority
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global root_port

    packet = b'\x01\x80\xc2\x00\x00\x00' # dest mac
    packet += get_switch_mac() # src mac

    
    packet += int.to_bytes(52, 2, 'little') # llc length
    packet += b'\x42\x42\x03' # llc header

    packet += int.to_bytes(0, 4, 'big') # bpdu header

    packet += b'\x00' # flags
    packet += int.to_bytes(root, 8, 'big') # root bridge id
    packet += int.to_bytes(root_path_cost, 4, 'big') # root path cost
    packet += int.to_bytes(sender, 8, 'big') # bridge id
    packet += int.to_bytes(port, 2, 'big') # port id
    packet += int.to_bytes(0, 8, 'big') # restul de chestii

    return packet


def main():
    global priority
    global own_bridge_id
    global root_bridge_id
    global root_path_cost
    global root_port

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    config_file = open("configs/switch" + str(switch_id) + ".cfg")
    priority = int(config_file.readline())

    for i in range(num_interfaces):
        line = config_file.readline().replace('\n', '')
        x = line.split(" ")
        interfaces_vlan[i] = x[1]
    
    for i in interfaces:
        if interfaces_vlan[i] == 'T':
            trunk_interfaces_type[i] = 'B'
    own_bridge_id = priority
    root_bridge_id = priority
    root_path_cost = 0

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()



    while True:
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        cam_table[src_mac] = interface

        if interfaces_vlan[interface] == 'T':
            # received from trunk
            if dest_mac != "ff.ff.ff.ff.ff.ff":
                if dest_mac in cam_table:
                    if interfaces_vlan[cam_table[dest_mac]] == 'T':
                        # sending on trunk
                        if trunk_interfaces_type[cam_table[dest_mac]] == 'D':
                            send_to_link(cam_table[dest_mac], data, length)
                    else:
                        # sendindg on acces, removing vlan tag
                        tag = data[12:16]
                        unttaged_frame = data[:12] + data[16:]
                        if int.from_bytes(tag[2:4], byteorder='big') == int(interfaces_vlan[cam_table[dest_mac]]):
                            send_to_link(cam_table[dest_mac], unttaged_frame, length - 4)

                elif dest_mac == "01:80:c2:00:00:00":
                    # STP BPDU
                    if int.from_bytes(data[22:30], 'big') < root_bridge_id:
                        old_root_bridge = root_bridge_id
                        
                        root_bridge_id = int.from_bytes(data[22:30], 'big')
                        root_path_cost += 10
                        root_port = interface

                        if old_root_bridge == own_bridge_id:
                            for i in trunk_interfaces_type:
                                if i != interface:
                                    trunk_interfaces_type[i] = 'B'
                        
                        if trunk_interfaces_type[interface] == 'B':
                            trunk_interfaces_type[interface] = 'D'

                        data = data[:30] + int.to_bytes(root_path_cost, 4, 'big') + data[34:]
                        data = data[:34] + int.to_bytes(own_bridge_id, 8, 'big') + data[42:]
                        for i in trunk_interfaces_type:
                            if i != interface:
                                send_to_link(i, data, 52)
                    
                    elif int.from_bytes(data[22:30], 'big') == root_bridge_id:
                        if interface == root_port and int.from_bytes(data[30:34], 'big') + 10 < root_path_cost:
                            root_path_cost = int.from_bytes(data[30:34], 'big') + 10
                        elif interface != root_port:
                            if int.from_bytes(data[30:34], 'big') > root_path_cost:
                                if trunk_interfaces_type[interface] != 'D':
                                    trunk_interfaces_type[interface] = 'D'
                    
                    elif int.from_bytes(data[22:30], 'big') == own_bridge_id:
                        trunk_interfaces_type[interface] = 'B'
   
                    if own_bridge_id == root_bridge_id:
                        for i in trunk_interfaces_type:
                            trunk_interfaces_type[i] = 'D'

                
                else:     
                    for i in interfaces:
                        if i != interface:
                            if interfaces_vlan[i] == 'T':
                                # sending on trunk
                                if trunk_interfaces_type[i] == 'D':
                                    send_to_link(i, data, length)
                            else:
                                # sending on acces, removing vlan tag
                                tag = data[12:16]
                                unttaged_frame = data[:12] + data[16:]
                                if int.from_bytes(tag[2:4], byteorder='big') == int(interfaces_vlan[i]):
                                    send_to_link(i, unttaged_frame, length - 4)

            else:
                for i in interfaces:
                    if i != interface:
                        if interfaces_vlan[i] == 'T':
                            # sending on trunk
                            if trunk_interfaces_type[i] == 'D':
                                send_to_link(i, data, length)
                        else:
                            # sending on acces, removing vlan tag                          
                            tag = data[12:16]
                            unttaged_frame = data[:12] + data[16:]
                            if int.from_bytes(tag[2:4], byteorder='big') == int(interfaces_vlan[i]):
                                send_to_link(i, unttaged_frame, length - 4)



        else:
            # receiving on trunk
            if dest_mac != "ff.ff.ff.ff.ff.ff":
                if dest_mac in cam_table:
                    if interfaces_vlan[cam_table[dest_mac]] == 'T':
                        # sending on trunk, adding 802.1q tag
                        if trunk_interfaces_type[cam_table[dest_mac]] == 'D':
                            tagged_frame = data[:12] + create_vlan_tag(int(interfaces_vlan[interface])) + data[12:]
                            send_to_link(cam_table[dest_mac], tagged_frame, length + 4)
                    else:
                        # seding if on same vlan
                        if interfaces_vlan[interface] == interfaces_vlan[cam_table[dest_mac]]:
                            send_to_link(cam_table[dest_mac], data, length)
                
                else:
                    # flood
                    for i in interfaces:
                        if i != interface:
                            if interfaces_vlan[i] == 'T':
                                # sending on trunk, add 802.1q header
                                if trunk_interfaces_type[i] == 'D':
                                    tagged_frame = data[:12] + create_vlan_tag(int(interfaces_vlan[interface])) + data[12:]
                                    send_to_link(i, tagged_frame, length + 4)
                            else:
                                # sending if same vlan
                                if interfaces_vlan[interface] == interfaces_vlan[i]:
                                    send_to_link(i, data, length)


            else:
                #flood
                for i in interfaces:
                    if i != interface:
                        if interfaces_vlan[i] == 'T':
                            # sending on trunk, add 802.1q header
                            if trunk_interfaces_type[i] == 'D':
                                tagged_frame = data[:12] + create_vlan_tag(int(interfaces_vlan[interface])) + data[12:]
                                send_to_link(i, tagged_frame, length + 4)
                        else:
                            # sending if same vlan
                            if interfaces_vlan[interface] == interfaces_vlan[i]:
                                send_to_link(i, data, length)


if __name__ == "__main__":
    main()
