import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, Menu
import subprocess
import platform
import threading
import time
import datetime
import os

# Constants
DEFAULT_CHECK_INTERVAL = 10  # seconds
UPDATE_INTERVAL = 2000  # milliseconds
IP_FILE = "ips.txt"
LOG_FILE = "monitor.log"
HIGHLIGHT_DURATION = 5  # seconds

class Device:
    def __init__(self, ip):
        self.ip = ip
        self.status = "Unknown"
        self.last_checked = "Never"
        self.highlight = False

    def ping(self):
        system = platform.system()
        if system == "Windows":
            command = ["ping", "-n", "1", self.ip]
        else:
            command = ["ping", "-c", "1", self.ip]
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        new_status = "Up" if result.returncode == 0 else "Down"
        self.last_checked = datetime.datetime.now().strftime("%H:%M:%S")
        if new_status != self.status:
            self.status = new_status
            self.highlight = True
            return True
        self.status = new_status
        return False

class Monitor:
    def __init__(self):
        self.devices = []
        self.lock = threading.Lock()
        self.check_interval = DEFAULT_CHECK_INTERVAL
        self.log_file = LOG_FILE

    def add_device(self, ip):
        if not self.is_valid_ip(ip):
            return False
        device = Device(ip)
        with self.lock:
            self.devices.append(device)
        self.save_ips()
        return True

    def remove_device(self, ip):
        with self.lock:
            self.devices = [d for d in self.devices if d.ip != ip]
        self.save_ips()

    def edit_device(self, old_ip, new_ip):
        if not self.is_valid_ip(new_ip):
            return False
        with self.lock:
            for device in self.devices:
                if device.ip == old_ip:
                    device.ip = new_ip
                    device.status = "Unknown"
                    device.last_checked = "Never"
                    break
        self.save_ips()
        return True

    def monitor(self):
        while True:
            with self.lock:
                for device in self.devices:
                    old_status = device.status
                    changed = device.ping()
                    if changed:
                        self.log_status_change(device.ip, device.status)
            time.sleep(self.check_interval)

    def log_status_change(self, ip, status):
        log_message = f"{datetime.datetime.now()} - {ip} changed to {status}\n"
        with open(self.log_file, "a") as f:
            f.write(log_message)

    def load_ips(self):
        if os.path.exists(IP_FILE):
            with open(IP_FILE, "r") as f:
                ips = [line.strip() for line in f if line.strip()]
            for ip in ips:
                self.add_device(ip)

    def save_ips(self):
        with open(IP_FILE, "w") as f:
            for device in self.devices:
                f.write(f"{device.ip}\n")

    @staticmethod
    def is_valid_ip(ip):
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        for part in parts:
            if not part.isdigit() or not 0 <= int(part) <= 255:
                return False
        return True

class App:
    def __init__(self, root):
        self.monitor = Monitor()
        self.monitor.load_ips()
        self.root = root
        self.root.title("Enhanced Network Monitoring Tool")
        self.highlight_enabled = tk.BooleanVar(value=True)

        # Menu
        menubar = Menu(root)
        root.config(menu=menubar)
        settings_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Set Check Interval", command=self.set_interval)
        settings_menu.add_checkbutton(label="Highlight Status Changes", variable=self.highlight_enabled)

        # Treeview
        self.tree = ttk.Treeview(root, columns=("IP", "Status", "Last Checked"), show="headings")
        self.tree.heading("IP", text="IP Address", command=lambda: self.sort_column("IP"))
        self.tree.heading("Status", text="Status", command=lambda: self.sort_column("Status"))
        self.tree.heading("Last Checked", text="Last Checked", command=lambda: self.sort_column("Last Checked"))
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Buttons
        button_frame = tk.Frame(root)
        button_frame.pack(fill=tk.X)
        tk.Button(button_frame, text="Add Device", command=self.add_device).pack(side=tk.LEFT)
        tk.Button(button_frame, text="Remove Device", command=self.remove_device).pack(side=tk.LEFT)
        tk.Button(button_frame, text="Edit Device", command=self.edit_device).pack(side=tk.LEFT)
        tk.Button(button_frame, text="View Logs", command=self.view_logs).pack(side=tk.LEFT)

        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor.monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Schedule UI updates
        self.update_ui()

    def sort_column(self, col):
        with self.monitor.lock:
            items = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
            items.sort()
            for index, (val, k) in enumerate(items):
                self.tree.move(k, '', index)

    def update_ui(self):
        with self.monitor.lock:
            for item in self.tree.get_children():
                self.tree.delete(item)
            for device in self.monitor.devices:
                item = self.tree.insert("", "end", values=(device.ip, device.status, device.last_checked))
                if device.highlight and self.highlight_enabled.get():
                    self.tree.item(item, tags=("highlight",))
                    device.highlight = False
                    self.root.after(HIGHLIGHT_DURATION * 1000, lambda i=item: self.tree.item(i, tags=()))
        self.tree.tag_configure("highlight", background="yellow")
        self.root.after(UPDATE_INTERVAL, self.update_ui)

    def add_device(self):
        ip = simpledialog.askstring("Add Device", "Enter IP Address:")
        if ip and self.monitor.add_device(ip):
            messagebox.showinfo("Success", f"Added {ip}")
        elif ip:
            messagebox.showerror("Error", "Invalid IP address")

    def remove_device(self):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0])["values"][0]
            self.monitor.remove_device(ip)
            messagebox.showinfo("Success", f"Removed {ip}")
        else:
            messagebox.showwarning("Warning", "No device selected")

    def edit_device(self):
        selected = self.tree.selection()
        if selected:
            old_ip = self.tree.item(selected[0])["values"][0]
            new_ip = simpledialog.askstring("Edit Device", f"Edit IP Address (current: {old_ip}):")
            if new_ip and self.monitor.edit_device(old_ip, new_ip):
                messagebox.showinfo("Success", f"Changed {old_ip} to {new_ip}")
            elif new_ip:
                messagebox.showerror("Error", "Invalid IP address")
        else:
            messagebox.showwarning("Warning", "No device selected")

    def set_interval(self):
        interval = simpledialog.askinteger("Check Interval", "Enter interval in seconds:", minvalue=1, initialvalue=self.monitor.check_interval)
        if interval:
            self.monitor.check_interval = interval
            messagebox.showinfo("Success", f"Check interval set to {interval} seconds")

    def view_logs(self):
        log_window = tk.Toplevel(self.root)
        log_window.title("Logs")
        text = tk.Text(log_window, height=20, width=60)
        text.pack(fill=tk.BOTH, expand=True)
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as f:
                text.insert(tk.END, f.read())
        tk.Button(log_window, text="Clear Logs", command=lambda: self.clear_logs(text)).pack()

    def clear_logs(self, text_widget):
        if messagebox.askyesno("Confirm", "Clear all logs?"):
            with open(LOG_FILE, "w"):
                pass
            text_widget.delete(1.0, tk.END)
            messagebox.showinfo("Success", "Logs cleared")

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("600x400")
    app = App(root)
    root.mainloop()
