import socket
import threading
from tkinter import Tk, Label, Entry, Button, Text, Scrollbar, END


def scan_port(ip, port, result_list):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex((ip, port)) == 0:
                result_list.append(f"Port {port} is open\n")
    except Exception as e:
        result_list.append(f"Error scanning port {port}: {e}\n")


def scan_ports(ip, start_port, end_port, result_list, on_complete):
    def worker(port):
        scan_port(ip, port, result_list)

    threads = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=worker, args=(port,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    on_complete()


def update_output(output_field, result_list):
    while result_list:
        output_field.insert(END, result_list.pop(0))
        output_field.see(END)


def start_scan(ip_entry, start_port_entry, end_port_entry, output_field):
    ip = ip_entry.get().strip()
    try:
        start_port = int(start_port_entry.get().strip())
        end_port = int(end_port_entry.get().strip())
        if start_port > end_port or start_port < 1 or end_port > 65535:
            raise ValueError
    except ValueError:
        output_field.delete(1.0, END)
        output_field.insert(END, "Invalid port range. Please enter integers between 1 and 65535.\n")
        return

    output_field.delete(1.0, END)
    output_field.insert(END, f"Scanning {ip} from port {start_port} to {end_port}...\n")
    output_field.see(END)

    result_list = []

    def on_complete():
        output_field.insert(END, "Scan completed.\n")
        output_field.see(END)

    def monitor_results():
        update_output(output_field, result_list)
        if threading.active_count() > 1:
            output_field.after(100, monitor_results)

    threading.Thread(target=scan_ports, args=(ip, start_port, end_port, result_list, on_complete)).start()
    monitor_results()


def toggle_dark_mode(root, widgets, is_dark_mode):
    if not is_dark_mode[0]:
        root.configure(bg="black")
        for widget in widgets:
            widget.configure(bg="black")
            if isinstance(widget, (Label, Button)):
                widget.configure(fg="lime")
            elif isinstance(widget, (Entry, Text)):
                widget.configure(fg="lime", insertbackground="lime")
        is_dark_mode[0] = True
    else:
        root.configure(bg="white")
        for widget in widgets:
            widget.configure(bg="white")
            if isinstance(widget, (Label, Button)):
                widget.configure(fg="black")
            elif isinstance(widget, (Entry, Text)):
                widget.configure(fg="black", insertbackground="black")
        is_dark_mode[0] = False


def create_gui():
    root = Tk()
    root.title("Advanced Port Scanner")
    root.geometry("800x600")

    is_dark_mode = [False]

    label_ip = Label(root, text="Target IP Address:")
    ip_entry = Entry(root, width=30)
    label_start_port = Label(root, text="Start Port:")
    start_port_entry = Entry(root, width=10)
    label_end_port = Label(root, text="End Port:")
    end_port_entry = Entry(root, width=10)
    label_results = Label(root, text="Scan Results:")
    output_field = Text(root, height=15, width=70, wrap="word")
    scrollbar = Scrollbar(root, command=output_field.yview)
    output_field.configure(yscrollcommand=scrollbar.set)
    start_button = Button(
        root,
        text="Start Scan",
        command=lambda: start_scan(ip_entry, start_port_entry, end_port_entry, output_field),
    )
    toggle_button = Button(
        root,
        text="Toggle Hakr Mode",
        command=lambda: toggle_dark_mode(
            root,
            [label_ip, ip_entry, label_start_port, start_port_entry, label_end_port, end_port_entry, label_results, output_field, start_button, toggle_button],
            is_dark_mode,
        ),
    )

    label_ip.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    ip_entry.grid(row=0, column=1, padx=10, pady=10, columnspan=2)
    label_start_port.grid(row=1, column=0, padx=10, pady=10, sticky="w")
    start_port_entry.grid(row=1, column=1, padx=10, pady=10, sticky="w")
    label_end_port.grid(row=1, column=2, padx=10, pady=10, sticky="w")
    end_port_entry.grid(row=1, column=3, padx=10, pady=10, sticky="w")
    label_results.grid(row=2, column=0, padx=10, pady=10, sticky="nw")
    output_field.grid(row=2, column=1, columnspan=3, padx=10, pady=10)
    scrollbar.grid(row=2, column=4, sticky="ns")
    start_button.grid(row=3, column=1, columnspan=2, pady=20)
    toggle_button.grid(row=4, column=1, columnspan=2, pady=10)

    root.mainloop()


if __name__ == "__main__":
    create_gui()
