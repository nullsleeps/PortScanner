import socket
import threading
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END

def scan_port(ip, port, output):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((ip, port)) == 0:
                output.append(f"Port {port} is open\n")
    except Exception as e:
        output.append(f"Error scanning port {port}: {e}\n")

def scan_ports(ip, start_port, end_port, output_field):
    output = []

    def worker(port):
        scan_port(ip, port, output)

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    output_field.delete(1.0, END)
    output_field.insert(END, "".join(output))

def start_scan(ip_entry, start_port_entry, end_port_entry, output_field):
    ip = ip_entry.get()
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        if start_port > end_port or start_port < 1 or end_port > 65535:
            raise ValueError
    except ValueError:
        output_field.delete(1.0, END)
        output_field.insert(END, "Invalid port range. Please enter valid integers between 1 and 65535.\n")
        return

    output_field.delete(1.0, END)
    output_field.insert(END, f"Scanning {ip} from port {start_port} to {end_port}...\n")
    threading.Thread(target=scan_ports, args=(ip, start_port, end_port, output_field)).start()

def create_gui():
    root = Tk()
    root.title(" NullSleep's Advanced Port Scanner :p")
    root.geometry("500x400")

    Label(root, text="Target IP Address: ").grid(row=0, column=0, padx=10, pady=10, sticky="w")
    ip_entry = Entry(root, width=30)
    ip_entry.grid(row=0, column=1, padx=10, pady=10, columnspan=2)

    Label(root, text="Start Port:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
    start_port_entry = Entry(root, width=10)
    start_port_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")

    Label(root, text="End Port:").grid(row=1, column=2, padx=10, pady=10, sticky="w")
    end_port_entry = Entry(root, width=10)
    end_port_entry.grid(row=1, column=3, padx=10, pady=10, sticky="w")

    Label(root, text="Scan Results:").grid(row=2, column=0, padx=10, pady=10, sticky="nw")
    output_field = Text(root, height=15, width=60, wrap="word")
    output_field.grid(row=2, column=1, columnspan=3, padx=10, pady=10)

    scrollbar = Scrollbar(root, command=output_field.yview)
    output_field.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(row=2, column=4, sticky="ns")

    Button(root, text="Start Scan", command=lambda: start_scan(ip_entry, start_port_entry, end_port_entry, output_field)).grid(row=3, column=1, columnspan=2, pady=20)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
