import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, TCP, IP, conf
from scapy.all import IFACES
import os
import threading
import signal

# Global flag to stop sniffing
stop_sniffing = False

def packet_callback(packet):
    # Check if the packet has TCP layer
    if TCP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dport
        
        # Print the packet info to the terminal
        print(f"IP {ip_src} -> {ip_dst} | TCP {tcp_sport} -> {tcp_dport}")

def sniff_thread(iface):
    global stop_sniffing
    while not stop_sniffing:
        sniff(iface=iface, filter="tcp", prn=packet_callback, store=0, timeout=1)

def start_sniffer():
    global stop_sniffing
    iface = iface_combobox.get()
    if iface:
        result_box.insert(tk.END, f"Starting network sniffer on interface {iface}...\n")
        stop_sniffing = False
        # Start sniffing in a new thread
        global sniffing_thread
        sniffing_thread = threading.Thread(target=lambda: sniff_thread(iface))
        sniffing_thread.start()
    else:
        result_box.insert(tk.END, "Please select an interface.\n")

def stop_sniffer():
    global stop_sniffing
    stop_sniffing = True
    if sniffing_thread.is_alive():
        sniffing_thread.join()
    result_box.insert(tk.END, "Stopped network sniffer.\n")

def main():
    global iface_combobox, result_box, sniffing_thread

    if os.name == 'nt':
        conf.use_pcap = True

    # Create the main window
    root = tk.Tk()
    root.title("Sniffer By Achref")

    # Interface selection
    tk.Label(root, text="Select Network Interface:").pack(pady=5)
    
    interfaces = [iface.name for iface in IFACES.values()]
    iface_combobox = ttk.Combobox(root, values=interfaces)
    iface_combobox.pack(pady=5)

    # Start button
    start_button = tk.Button(root, text="Start Sniffing", command=start_sniffer)
    start_button.pack(pady=10)

    # Stop button
    stop_button = tk.Button(root, text="Stop Sniffing", command=stop_sniffer)
    stop_button.pack(pady=10)

    # Results box
    result_box = tk.Text(root, height=10, width=80)
    result_box.pack(pady=10)

    # Run the main event loop
    root.mainloop()

if __name__ == "__main__":
    main()
