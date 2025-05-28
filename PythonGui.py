import tkinter as tk
from tkinter import ttk  # Προσθήκη του ttk import
from tkinter import messagebox, scrolledtext, simpledialog
import subprocess
import threading
from PIL import Image, ImageTk
import psutil
import time
import re
from datetime import datetime
import os

# -----------Δημιουργία του κύριου παραθύρου---------------------
window = tk.Tk()
window.title("System Management Tool")
window.geometry("800x600")

# Φόρτωση εικόνας φόντου

try:
    original_image = Image.open("pngkey.com-linux-png-2373210.png")
except Exception as e:
    print(f"Error loading background image: {e}")
    original_image = None

# Δημιουργία canvas και scrollbar

canvas = tk.Canvas(window)
scrollbar = ttk.Scrollbar(window, orient="vertical", command=canvas.yview)
scrollable_frame = ttk.Frame(canvas)

# Διαμόρφωση του canvas
canvas.configure(yscrollcommand=scrollbar.set)

# Συνάρτηση για προσαρμογή του scrollable region


def configure_scroll_region(event):
    canvas.configure(scrollregion=canvas.bbox("all"))


# Συνάρτηση για συγχρονισμό του scroll με το mousewheel


def on_mousewheel(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)),
"units")


# Συνάρτηση για το resize της εικόνας


def resize_image(event=None):
    global original_image, background_label, photo

    if original_image is None:
        return

    if event is not None:
        width = event.width
        height = event.height
    else:
        width = window.winfo_width()
        height = window.winfo_height()

    if width > 1 and height > 1:
        try:
            resized_image = original_image.resize(
                (width, height), Image.Resampling.LANCZOS
            )
            photo = ImageTk.PhotoImage(resized_image)
            background_label.configure(image=photo)
            background_label.image = photo
        except Exception as e:
            print(f"Error resizing image: {e}")


# Φόρτωση και αρχική προσαρμογή εικόνας


original_image = Image.open("pngkey.com-linux-png-2373210.png")
photo = ImageTk.PhotoImage(original_image.resize(
    (800,
600), Image.Resampling.LANCZOS))

# ΣΕ ΑΥΤΟ:
if original_image:
    photo = ImageTk.PhotoImage(
        original_image.resize((800,
600), Image.Resampling.LANCZOS)
    )
    # Δημιουργία background label
    background_label = tk.Label(window, image=photo)
    background_label.place(x=0, y=0, relwidth=1, relheight=1)
    background_label.image = photo

    # Bind το resize event
    window.bind("<Configure>", resize_image)

# Τοποθέτηση των widgets
canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# --------------Class_Tooltip------------------------


class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind("<Enter>", self.on_enter)
        self.widget.bind("<Leave>", self.on_leave)

    def on_enter(self, event):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 20
        y += self.widget.winfo_rooty() + 20

        self.tooltip = tk.Toplevel()
        self.tooltip.wm_overrideredirect(True)
        self.tooltip.wm_geometry(f"+{x}+{y}")

        label = tk.Label(
            self.tooltip,
            text=self.text,
            background="yellow",
            foreground="black",
            relief="solid",
            borderwidth=1,
            font=("Arial",
9),
        )
        label.pack()

    def on_leave(self, event):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None


def on_enter(event):
    event.widget.config(bg="#000000")  # Μαύρο όταν ποντίκι πάνω


def on_leave(event):
    event.widget.config(bg="#333333")  # Γκρι όταν ποντίκι φεύγει


# --------------Change_ip--------------------------


def change_ip():
    def run_change_ip(new_ip):
        interface = "wlan0"  # Το interface που θες
        try:
            # Κατέβασε το interface
            subprocess.run([
    "sudo",
    "ip",
    "link",
    "set",
                           interface,
    "down"
], check=True)
            # Αλλάξε IP
            subprocess.run(
                [
    "sudo",
    "ip",
    "addr",
    "add", new_ip,
    "dev", interface
], check=True
            )
            # Άναψε το interface
            subprocess.run([
    "sudo",
    "ip",
    "link",
    "set",
                           interface,
    "up"
], check=True)
            messagebox.showinfo("Success", f"IP changed to {new_ip}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to change IP: {e}")

    new_ip = simpledialog.askstring(
        "Change IP",
"Enter new IP address with subnet (e.g. 192.168.1.100/24):"
    )
    if new_ip:
        threading.Thread(target=run_change_ip, args=(new_ip,)).start()


# -------------Update-------------------------------


def full_update():
    global button1
    def run_update():
        # Αλλάζουμε το κείμενο κουμπιού για ένδειξη
        button1.config(text="Updating...")
        process = subprocess.Popen(
            [
    "sudo",
    "apt",
    "update"
],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for line in process.stdout:
            print(line.strip())  # Ενημέρωση κονσόλας σε πραγματικό χρόνο
        process.wait()
        if process.returncode == 0:
            process2 = subprocess.Popen(
                [
    "sudo",
    "apt",
    "upgrade",
    "-y"
],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for line2 in process2.stdout:
                print(line2.strip())
            process2.wait()
            if process2.returncode == 0:
                messagebox.showinfo("Success",
"Update & Upgrade completed!")
            else:
                messagebox.showerror("Error",
"Upgrade failed!")
        else:
            messagebox.showerror("Error",
"Update failed!")
        # Επαναφορά κειμένου κουμπιού
        button1.config(text="Full Update")

    threading.Thread(target=run_update).start()


# ---------Upgrade-------------------------------


def full_upgrade():
    def run_full_upgrade():
        button2 = tk.Button(window, text="Full Upgrade")
        process = subprocess.Popen(
            [
    "sudo",
    "apt",
    "full-upgrade",
    "-y"
],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in process.stdout:
            print(line.strip())  # Τυπώνει κάθε γραμμή σε πραγματικό χρόνο
        process.wait()
        if process.returncode == 0:
            messagebox.showinfo("Success",
"Full Upgrade completed!")
        else:
            messagebox.showerror("Error",
"Full Upgrade failed!")
        button2.config(text="Full Upgrade")  # Επαναφορά κειμένου κουμπιού

    threading.Thread(target=run_full_upgrade).start()


# ----Change_Mac---------------


def change_mac():
    def run_change_mac(new_mac):
        interface = "wlan0"
        try:
            subprocess.run([
    "sudo",
    "ip",
    "link",
    "set",
                           interface,
    "down"
], check=True)
            subprocess.run(
                [
    "sudo",
    "ip",
    "link",
    "set", interface,
    "address", new_mac
], check=True
            )
            subprocess.run([
    "sudo",
    "ip",
    "link",
    "set",
                           interface,
    "up"
], check=True)
            messagebox.showinfo("Success", f"MAC changed to {new_mac}")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to change MAC: {e}")

    new_mac = simpledialog.askstring("Change MAC",
"Enter new MAC address:")
    if new_mac:
        threading.Thread(target=run_change_mac, args=(new_mac,)).start()


# --------Repair_System-----------


def repair_system():
    def run_repair():
        button5 = tk.Button(window, text="Repair System")
        try:
            subprocess.run([
    "sudo",
    "dpkg",
    "--configure",
    "-a"
], check=True)
            subprocess.run([
    "sudo",
    "apt",
    "-f",
    "install",
    "-y"
], check=True)
            subprocess.run([
    "sudo",
    "apt",
    "autoremove",
    "--purge",
    "-y"
], check=True)
            subprocess.run([
    "sudo",
    "apt",
    "clean"
], check=True)
            messagebox.showinfo(
                "Repair",
"System repair completed successfully.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Repair failed: {e}")
        button5.config(text="Repair System")

    threading.Thread(target=run_repair).start()


# ----------clean_system---------------


def clean_system():
    level = simpledialog.askstring(
        "System Cleaner",
"Level of cleanup:\n1 = Safe\n2 = Aggressive\n3 = Full Risky"
    )
    if not level:
        return

    def run_clean():
        button6 = tk.Button(window, text="Clean System")
        try:
            subprocess.run([
    "sudo",
    "apt",
    "autoremove",
    "-y"
], check=True)
            subprocess.run([
    "sudo",
    "apt",
    "autoclean"
], check=True)
            if level == "2":
                subprocess.run([
    "sudo",
    "apt",
    "clean"
], check=True)
            elif level == "3":
                subprocess.run(
                    [
    "sudo",
    "rm",
    "-rf",
    "/var/cache/apt/archives/*"
], check=True
                )
                subprocess.run(
                    [
    "sudo",
    "journalctl",
    "--vacuum-time=1d"
], check=True)
            messagebox.showinfo("Cleanup", f"Cleanup level {level} completed.")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Cleanup failed: {e}")
        button6.config(text="Clean System")

    threading.Thread(target=run_clean).start()


# ---------------system_info-------------------


def show_system_info():
    def load_info():
        try:
            cpu = subprocess.check_output(
                "top -bn1 | grep 'Cpu(s)'", shell=True, text=True
            ).strip()
            mem = subprocess.check_output(
                "free -h", shell=True, text=True).strip()
            disk = subprocess.check_output(
                "df -h /", shell=True, text=True).strip()
            uptime = subprocess.check_output(
                "uptime -p", shell=True, text=True).strip()
            kernel = subprocess.check_output(
                "uname -r", shell=True, text=True).strip()
            ip = subprocess.check_output(
                "ip -brief addr", shell=True, text=True
            ).strip()
            swap = subprocess.check_output(
                "swapon --show", shell=True, text=True
            ).strip()
            users = subprocess.check_output(
                "who", shell=True, text=True).strip()
            firewall = subprocess.check_output(
                "sudo ufw status", shell=True, text=True
            ).strip()
            packages = subprocess.check_output(
                "dpkg -l | wc -l", shell=True).strip()

            # Προσπαθούμε να διαβάσουμε θερμοκρασία CPU (πχ από
            # /sys/class/thermal/thermal_zone0/temp)
            try:
                temp_raw = subprocess.check_output(
                    "cat /sys/class/thermal/thermal_zone0/temp", shell=True, text=True
                ).strip()
                cpu_temp = f"{int(temp_raw) / 1000:.1f} °C"
            except Exception:
                cpu_temp = "N/A"

            info_text = (
                f"📊 CPU Usage:\n{cpu}\n\n"
                f"🌡️ CPU Temperature:\n{cpu_temp}\n\n"
                f"🧠 RAM:\n{mem}\n\n"
                f"💽 Disk Usage (/):\n{disk}\n\n"
                f"⏱️ Uptime:\n{uptime}\n\n"
                f"🧬 Kernel Version:\n{kernel}\n\n"
                f"🌐 Network Interfaces:\n{ip}\n\n"
                f"🔄 Swap Info:\n{swap}\n\n"
                f"👥 Logged-in Users:\n{users}\n\n"
                f"🔥 Firewall Status (ufw):\n{firewall}\n\n"
                f"📦 Installed Packages:\n{packages}"
            )

            text_widget.config(state="normal")
            text_widget.delete(1.0, tk.END)
            text_widget.insert(tk.END, info_text)
            text_widget.config(state="disabled")
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to retrieve system info:\n{e}")

    def refresh():
        threading.Thread(target=load_info).start()

    info_win = tk.Toplevel(window)
    info_win.title("System Info")
    info_win.geometry("600x500")

    # Scrollable Text widget
    text_widget = scrolledtext.ScrolledText(
        info_win, wrap=tk.WORD, font=("Consolas",
10)
    )
    text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
    text_widget.config(state="disabled")

    # Κουμπί ανανέωσης
    refresh_btn = tk.Button(info_win, text="Ανανέωση", command=refresh)
    refresh_btn.pack(pady=5)

    refresh()  # Φορτώνουμε info πρώτη φορά

    # Κλήση για να φορτώσουν τα δεδομένα μόλις ανοίξει το παράθυρο
    threading.Thread(target=load_info).start()


# -----------firewall-----------------
def check_firewall_status():
    """Ελέγχει την κατάσταση του UFW firewall"""
    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            capture_output=True,
            text=True,
            check=True
        )
        status_output = result.stdout.strip().lower()
        return "status: active" in status_output
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False

def update_firewall_button_text(button):
    if check_firewall_status():
        button.config(text=" Firewall ON", bg="lightgreen", fg="darkgreen")
    else:
        button.config(text=" Firewall OFF", bg="lightcoral", fg="darkred")
        
def create_firewall_gui():
    """Δημιουργεί το GUI για έλεγχο firewall"""
    root = tk.Tk()
    root.title("Έλεγχος Firewall")
    root.geometry("300x180")

    firewall_button = tk.Button(
        root,
        text="Έλεγχος...",
        font=("Arial", 12, "bold"),
        width=20,
        height=2,
        command=lambda: toggle_firewall(firewall_button)
    )
    firewall_button.pack(pady=20)

    refresh_button = tk.Button(
        root,
        text="🔄 Ανανέωση",
        command=lambda: update_firewall_button_text(firewall_button)
    )
    refresh_button.pack()

    update_firewall_button_text(firewall_button)

    root.mainloop()

# Εκτέλεση αν τρέχεις το αρχείο απευθείας
if __name__ == "__main__":
    create_firewall_gui()



# ------------------------------------------------------------------


def open_network_options():
    """Κύρια συνάρτηση για άνοιγμα του Network Manager"""
    try:
        network_manager = NetworkManager()
        return network_manager.window
    except Exception as e:
        messagebox.showerror(
    "Σφάλμα", f"Αποτυχία εκκίνησης Network Manager: {e}")
        return None


class NetworkManager:
    def __init__(self):
        self.setup_gui()

    def setup_gui(self):
        self.window = tk.Tk()
        self.window.title("🌐 Network Manager Pro")
        self.window.geometry("800x700")
        self.window.configure(bg="#2c3e50")
        self.window.resizable(True, True)

        container = tk.Frame(self.window, bg="#2c3e50")
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg="#2c3e50", highlightthickness=0)
        self.canvas.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
    container,
    orient="vertical",
     command=self.canvas.yview)
        scrollbar.pack(side="right", fill="y")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.scrollable_frame = tk.Frame(self.canvas, bg="#2c3e50")
        self.scrollable_window = self.canvas.create_window(
            (0, 0), window=self.scrollable_frame, anchor="nw")

        self.scrollable_frame.bind(
    "<Configure>", lambda e: self.canvas.configure(
        scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", self.resize_canvas)
        self.scrollable_frame.bind("<Enter>", self._bind_to_mousewheel)
        self.scrollable_frame.bind("<Leave>", self._unbind_from_mousewheel)

        self.setup_styles()
        self.create_header()
        self.populate_demo_content()

    def resize_canvas(self, event):
        self.canvas.itemconfig(self.scrollable_window, width=event.width)

    def _bind_to_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

    def _unbind_from_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Arial", 12), padding=10)
        style.configure(
    "Header.TLabel",
    background="#2c3e50",
    foreground="#ecf0f1",
    font=(
        "Arial",
        16,
         "bold"))
        style.configure(
    "Section.TLabel",
    background="#34495e",
    foreground="#ecf0f1",
    font=(
        "Arial",
        12,
         "bold"))
        style.configure("Custom.TButton", padding=(10, 5), font=("Arial", 10))
        style.configure("Success.TButton", background="#27ae60")
        style.configure("Danger.TButton", background="#e74c3c")
        style.configure("Warning.TButton", background="#f39c12")

    def create_header(self):
        header_frame = tk.Frame(self.scrollable_frame, bg="#2c3e50", height=80)
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="🌐 Network Manager Pro",
            font=("Arial", 18, "bold"),
            bg="#2c3e50",
            fg="#ecf0f1",
        )
        title_label.pack(side="left", pady=20)

        nm_button = ttk.Button(
            header_frame,
            text="🔧 Network Manager",
            style="Custom.TButton",
            command=self.launch_network_manager,
        )
        nm_button.pack(side="right", pady=20)

    def launch_network_manager(self):
        messagebox.showinfo("Network Manager",
     "Άνοιγμα Network Manager GUI... (υπό ανάπτυξη)")

    def populate_demo_content(self):
        for i in range(30):
            btn = ttk.Button(self.scrollable_frame, text=f"Κουμπί {i + 1}")
            btn.pack(pady=10, padx=20, anchor="w")

    # Placeholders
    def create_interface_section(self): pass
    def create_status_section(self): pass
    def create_control_section(self): pass
    def create_mode_section(self): pass
    def create_info_section(self): pass
    def create_advanced_section(self): pass

    def discover_interfaces(self): pass

    def create_interface_section(self):
        """Δημιουργία τμήματος επιλογής interface"""
        interface_frame = tk.LabelFrame(
            self.window,
            text="📡 Interface Selection",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 12, "bold")
        )
        interface_frame.pack(fill="x", padx=20, pady=10)

        # Interface selection
        select_frame = tk.Frame(interface_frame, bg="#34495e")
        select_frame.pack(fill="x", pady=5)

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(
            select_frame,
            textvariable=self.interface_var,
            state="readonly",
            font=("Arial",
11),
        )
        self.interface_combo.pack(
            side="left", padx=(0,
10), fill="x", expand=True)
        self.interface_combo.bind(
            "<<ComboboxSelected>>", self.on_interface_selected)

        refresh_btn = ttk.Button(
            select_frame,
            text="🔄 Refresh",
            style="Custom.TButton",
            command=self.discover_interfaces,
        )
        refresh_btn.pack(side="right")

        # Selected interface display
        self.selected_label = tk.Label(
            interface_frame,
            text="Επιλεγμένη διεπαφή: Καμία",
            font=("Arial",
11,
"bold"),
            bg="#34495e",
            fg="#f39c12",
        )
        self.selected_label.pack(pady=5)
        
import tkinter as tk
from tkinter import ttk

class StatusSection:
    def __init__(self, parent):
        self.window = parent
        self.create_status_section()
        self.create_control_section()

    def create_status_section(self):
        """Δημιουργία τμήματος κατάστασης"""
        status_frame = tk.LabelFrame(
            self.window,
            text="📊 Status Information",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
        )
        status_frame.pack(fill="x", padx=20, pady=10)

        status_grid = tk.Frame(status_frame, bg="#34495e")
        status_grid.pack(fill="x", pady=5)

        self.status_label = tk.Label(
            status_grid, text="Κατάσταση: --", font=("Arial", 11, "bold"),
            bg="#34495e", fg="#bdc3c7"
        )
        self.status_label.grid(row=0, column=0, sticky="w", padx=10)

        self.mode_label = tk.Label(
            status_grid, text="Λειτουργία: --", font=("Arial", 11, "bold"),
            bg="#34495e", fg="#bdc3c7"
        )
        self.mode_label.grid(row=0, column=1, sticky="w", padx=10)

        self.mac_label = tk.Label(
            status_grid, text="MAC: --", font=("Arial", 11),
            bg="#34495e", fg="#bdc3c7"
        )
        self.mac_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)

        self.ip_label = tk.Label(
            status_grid, text="IP: --", font=("Arial", 11),
            bg="#34495e", fg="#bdc3c7"
        )
        self.ip_label.grid(row=1, column=1, sticky="w", padx=10, pady=5)

    def create_control_section(self):
        """Δημιουργία τμήματος ελέγχου"""
        self.control_frame = tk.LabelFrame(
            self.window,
            text="🎛️ Interface Control",
            bg="#34495e",
            fg="#ecf0f1",
            font=("Arial", 12, "bold"),
            padx=10,
            pady=10,
        )
        self.control_frame.pack(fill="x", padx=20, pady=10)

        btn_frame = tk.Frame(self.control_frame, bg="#34495e")
        btn_frame.pack(fill="x", pady=5)

        self.toggle_btn = ttk.Button(
            btn_frame,
            text="🔴 Απενεργοποίηση",
            style="Danger.TButton",
            command=self.toggle_interface
        )
        self.toggle_btn.pack(side="left", padx=5, fill="x", expand=True)

        reset_btn = ttk.Button(
            btn_frame,
            text="🔧 Reset",
            style="Custom.TButton",
            command=self.reset_interface
        )
        reset_btn.pack(side="left", padx=5, fill="x", expand=True)

    def toggle_interface(self):
        print("Τoggle Interface")

    def reset_interface(self):
        print("Reset Interface")

def create_mode_section(self):
    """Δημιουργία τμήματος λειτουργίας"""
    mode_frame = tk.LabelFrame(
        self.window,
        text="⚙️ Mode Management",
        bg="#34495e",
        fg="#ecf0f1",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10,
    )
    mode_frame.pack(fill="x", padx=20, pady=10)

    btn_frame = tk.Frame(mode_frame, bg="#34495e")
    btn_frame.pack(fill="x", pady=5)

    monitor_btn = ttk.Button(
        btn_frame,
        text="👁️ Monitor Mode",
        style="Custom.TButton",
        command=self.set_monitor_mode,
    )
    monitor_btn.pack(side="left", padx=5, fill="x", expand=True)

    managed_btn = ttk.Button(
        btn_frame,
        text="📱 Managed Mode",
        style="Success.TButton",
        command=self.set_managed_mode,
    )
    managed_btn.pack(side="left", padx=5, fill="x", expand=True)


def create_info_section(self):
    """Δημιουργία τμήματος πληροφοριών"""
    info_frame = tk.LabelFrame(
        self.window,
        text="📋 Network Information",
        bg="#34495e",
        fg="#ecf0f1",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10,
    )
    info_frame.pack(fill="x", padx=20, pady=10)

    self.info_text = tk.Text(
        info_frame,
        height=6,
        bg="#2c3e50",
        fg="#ecf0f1",
        font=("Courier", 10),
        wrap=tk.WORD,
    )
    self.info_text.pack(fill="both", expand=True, pady=5)

    scrollbar = ttk.Scrollbar(info_frame, orient="vertical", command=self.info_text.yview)
    scrollbar.pack(side="right", fill="y")
    self.info_text.configure(yscrollcommand=scrollbar.set)


def create_advanced_section(self):
    """Δημιουργία τμήματος προηγμένων επιλογών"""
    advanced_frame = tk.LabelFrame(
        self.window,
        text="🔬 Advanced Options",
        bg="#34495e",
        fg="#ecf0f1",
        font=("Arial", 12, "bold"),
        padx=10,
        pady=10,
    )
    advanced_frame.pack(fill="x", padx=20, pady=10)

    btn_frame = tk.Frame(advanced_frame, bg="#34495e")
    btn_frame.pack(fill="x", pady=5)

    scan_btn = ttk.Button(
        btn_frame,
        text="🔍 Scan Networks",
        style="Custom.TButton",
        command=self.scan_networks,
    )
    scan_btn.pack(side="left", padx=5, fill="x", expand=True)

    info_btn = ttk.Button(
        btn_frame,
        text="ℹ️ Interface Info",
        style="Custom.TButton",
        command=self.show_interface_info,
    )
    info_btn.pack(side="left", padx=5, fill="x", expand=True)

    stats_btn = ttk.Button(
        btn_frame,
        text="📈 Statistics",
        style="Custom.TButton",
        command=self.show_statistics,
    )
    stats_btn.pack(side="left", padx=5, fill="x", expand=True)


    def show_statistics(self): """Εμφάνιση στατιστικών"""
    if not self.selected_interface:
        messagebox.showwarning(
            "Προειδοποίηση",
            "Επίλεξε πρώτα ένα interface"
        )

    try:
        result = subprocess.run(
            [
                "ifconfig", self.selected_interface
            ],
            stdout=subprocess.PIPE,
            text=True,
        )
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(tk.END, result.stdout)
    except Exception as e:
            messagebox.showerror("Σφάλμα", f"Αποτυχία λήψης στατιστικών: {e}")

    def discover_interfaces(self): """Εντοπισμός διαθέσιμων interfaces"""
    try:
            # Βρες wireless interfaces
            result = subprocess.run(
                [
    "iwconfig"
],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            interfaces = []

            for line in result.stdout.split("\n"):
                if "IEEE" in line:
                    interface = line.split()[
    0
]
                    interfaces.append(interface)

            # Προσθήκη κοινών interfaces αν δεν βρέθηκαν
            if not interfaces:
                interfaces = [
    "wlan0",
    "wlan1",
    "wlp2s0",
    "wlp3s0"
]

            self.interface_combo[
    "values"
] = interfaces

            # Auto-select wlan0 if available
            if "wlan0" in interfaces:
                self.interface_combo.set("wlan0")
                self.on_interface_selected(None)

    except Exception as e:
            self.interface_combo[
    "values"
] = [
    "wlan0",
    "wlan1"
]
            messagebox.showwarning(
                "Προειδοποίηση", f"Σφάλμα εντοπισμού interfaces: {e}"
            )

def show_interface_info(self, interface): 
    """Λήψη λειτουργίας interface"""
    try:
        result = subprocess.run(
            [
                "iwconfig", interface
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if "Mode:Monitor" in result.stdout:
            return "Monitor"
        elif "Mode:Managed" in result.stdout:
            return "Managed"
        return "Unknown"
    except:
        return "Unknown"

def launch_network_manager(self): 
    """Εκκίνηση του εργαλείου Network Manager GUI"""
    if os.environ.get("DISPLAY", "") == "":
        messagebox.showerror(
            "Σφάλμα",
            "Δεν ανιχνεύθηκε περιβάλλον GUI (DISPLAY)")
    else:
        try:
            subprocess.Popen(['nm-connection-editor'])
        except FileNotFoundError:
            messagebox.showerror(
                "Σφάλμα",
                "Δεν βρέθηκε το εργαλείο nm-connection-editor")

    def on_interface_selected(self, event): """Όταν επιλέγεται interface"""
    selected = self.interface_var.get()
    if selected:
            self.selected_interface = selected
            self.selected_label.config(text=f"Επιλεγμένη διεπαφή: {selected}")
            self.start_monitoring()

    def start_monitoring(self): """Εκκίνηση παρακολούθησης interface"""
    if not self.is_monitoring:
            self.is_monitoring = True
            self.update_status()

    def update_status(self): """Ενημέρωση κατάστασης interface"""
    status, color = self.get_interface_status(self.selected_interface)
    if not self.selected_interface or not self.is_monitoring:
            return

    try:
            # Status
            status, color = self.get_interface_status(self.selected_interface)
            self.status_label.config(text=f"Κατάσταση: {status}", fg=color)

            # Mode
            mode = self.get_interface_mode(self.selected_interface)
            self.mode_label.config(text=f"Λειτουργία: {mode}")

            # MAC Address
            mac = self.get_mac_address(self.selected_interface)
            self.mac_label.config(text=f"MAC: {mac}")

            # IP Address
            ip = self.get_ip_address(self.selected_interface)
            self.ip_label.config(text=f"IP: {ip}")

            # Update toggle button
            if status == "Ενεργή":
                self.toggle_btn.config(
                    text="🔴 Απενεργοποίηση", style="Danger.TButton")
            else:
                self.toggle_btn.config(
                    text="🟢 Ενεργοποίηση", style="Success.TButton")

    except Exception as e:
            print(f"Σφάλμα ενημέρωσης: {e}")

        # Schedule next update
    if self.is_monitoring:
            self.window.after(2000, self.update_status)

def get_interface_status(self, interface): 
    """Λήψη κατάστασης interface"""
    try:
        result = subprocess.run(
            [
                "ip",
                "link",
                "show", interface
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        if "state UP" in result.stdout:
            return "Ενεργή", "#27ae60"
        else:
            return "Ανενεργή", "#e74c3c"
    except Exception as e:
        # handle exception
        pass

    def get_interface_mode(self, interface): 
        """Λήψη λειτουργίας interface"""
        try:
            result = subprocess.run(
                [
                    "iwconfig", interface
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            output = result.stdout
            if "Mode:Monitor" in output:
                return "Monitor"
            elif "Mode:Managed" in output:
                return "Managed"
            else:
                return "Άγνωστη"
        except subprocess.CalledProcessError:
            return "Άγνωστη"

    def get_ip_address(self, interface): """Λήψη IP address"""
    try:
            result = subprocess.run(
                [
    "ip",
    "addr",
    "show", interface
],
                stdout=subprocess.PIPE,
                text=True,
                check=True,
            )
            for line in result.stdout.split("\n"):
                if "inet " in line and not "127.0.0.1" in line:
                    return line.split()[
    1
].split("/")[
    0
]
            return "Δεν έχει IP"
    except subprocess.CalledProcessError:
            return "Άγνωστη"

    def run_command_safely(self, commands): 
        """Ασφαλής εκτέλεση εντολών"""
    for cmd in commands:
        result = subprocess.run(
        cmd, capture_output=True, text=True, check=True)
    return True,
""
    
def run_command_safely(self, commands): 
    """Ασφαλής εκτέλεση εντολών"""
    for cmd in commands:
        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True)
    return True, ""

    status, _ = self.get_interface_status(self.selected_interface)
    new_state = "down" if status == "Ενεργή" else "up"

    cmd = [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface, new_state
    ]
    success, error = self.run_command_safely([cmd
    ])

    if success:
            action = "απενεργοποιήθηκε" if new_state == "down" else "ενεργοποιήθηκε"
            messagebox.showinfo("Επιτυχία", f"Το interface {action} επιτυχώς")
    else:
            messagebox.showerror(
                "Σφάλμα", f"Αποτυχία αλλαγής κατάστασης: {error}")

    def restart_interface(self): """Επανεκκίνηση interface"""
    if not self.selected_interface:
            messagebox.showwarning(
                "Προειδοποίηση",
"Επίλεξε πρώτα ένα interface")
            return

    commands = [
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
]

    success, error = self.run_command_safely(commands)

    if success:
            messagebox.showinfo(
                "Επιτυχία",
"Το interface επανεκκινήθηκε επιτυχώς")
    else:
            messagebox.showerror("Σφάλμα", f"Σφάλμα επανεκκίνησης: {error}")

    def reset_interface(self): """Reset interface"""
    if not self.selected_interface:
            messagebox.showwarning(
                "Προειδοποίηση",
"Επίλεξε πρώτα ένα interface")
            return

        # Confirm reset
    if not messagebox.askyesno(
            "Επιβεβαίωση",
"Είσαι σίγουρος ότι θέλεις να κάνεις reset το interface;"
        ):
            return

    commands = [
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
    [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "type",
        "managed"
    ],
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
    [
        "sudo",
        "dhclient", self.selected_interface
    ],
]

    success, error = self.run_command_safely(commands)

    if success:
            messagebox.showinfo(
                "Επιτυχία",
"Το interface έγινε reset επιτυχώς")
    else:
            messagebox.showerror("Σφάλμα", f"Σφάλμα reset: {error}")

    def set_monitor_mode(self): """Ρύθμιση σε Monitor mode"""
    if not self.selected_interface:
            messagebox.showwarning(
                "Προειδοποίηση",
"Επίλεξε πρώτα ένα interface")
            return

    commands = [
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
    [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "monitor",
        "none"
    ],
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
]

    success, error = self.run_command_safely(commands)

    if success:
            messagebox.showinfo(
                "Επιτυχία",
"Το interface μπήκε σε Monitor mode")
    else:
            messagebox.showerror(
                "Σφάλμα", f"Αποτυχία αλλαγής σε Monitor mode: {error}")

    def set_managed_mode(self): """Ρύθμιση σε Managed mode"""
    if not self.selected_interface:
            messagebox.showwarning(
                "Προειδοποίηση",
"Επίλεξε πρώτα ένα interface")
            return

    commands = [
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
    [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "type",
        "managed"
    ],
    [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
]

    success, error = self.run_command_safely(commands)

    if success:
            messagebox.showinfo(
                "Επιτυχία",
"Το interface μπήκε σε Managed mode")
    else:
            messagebox.showerror(
                "Σφάλμα", f"Αποτυχία αλλαγής σε Managed mode: {error}")

    def scan_networks(self): """Σάρωση διαθέσιμων δικτύων"""
    if not self.selected_interface:
            messagebox.showwarning(
                "Προειδοποίηση",
    "Επίλεξε πρώτα ένα interface")
            return

    self.info_text.delete(1.0, tk.END)
    self.info_text.insert(tk.END,
    "Σάρωση δικτύων...\n")
    self.window.update()

    try:
            result = subprocess.run(
                [
    "sudo",
    "iwlist", self.selected_interface,
    "scan"
],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )

            # Parse scan results
            networks = []
            current_network = {}

            for line in result.stdout.split("\n"):
                line = line.strip()
                if "Cell" in line and "Address:" in line:
                    if current_network:
                        networks.append(current_network)
                    current_network = {
    "mac": line.split("Address: ")[
        1
    ]
}
                elif "ESSID:" in line:
                    essid = line.split("ESSID:")[
    1
].strip('"')
                    current_network[
    "essid"
] = essid
                elif "Quality=" in line:
                    quality = line.split("Quality=")[
    1
].split()[
    0
]
                    current_network[
    "quality"
] = quality
                elif "Encryption key:" in line:
                    encryption = "Yes" if "on" in line else "No"
                    current_network[
    "encryption"
] = encryption

            if current_network:
                networks.append(current_network)

            # Display results
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(
                tk.END, f"Βρέθηκαν {len(networks)} δίκτυα:\n\n")

            for i, network in enumerate(networks,
1):
                essid = network.get("essid",
"Hidden")
                mac = network.get("mac",
"Unknown")
                quality = network.get("quality",
"Unknown")
                encryption = network.get("encryption",
"Unknown")

                self.info_text.insert(tk.END, f"{i}. {essid}\n")
                self.info_text.insert(tk.END, f"   MAC: {mac}\n")
                self.info_text.insert(tk.END, f"   Ποιότητα: {quality}\n")
                self.info_text.insert(
                    tk.END, f"   Κρυπτογράφηση: {encryption}\n\n")

    except subprocess.CalledProcessError as e:
            self.info_text.delete(1.0, tk.END)
            self.info_text.insert(tk.END, f"Σφάλμα σάρωσης: {e}")

        # Εμφάνιση πληροφοριών interface

    def show_interface_info(self, interface): """Λήψη λειτουργίας interface"""
    try:
                    result = subprocess.run(
                        [
        "iwconfig", interface
    ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if "Mode:Monitor" in result.stdout:
                        return "Monitor"
                    elif "Mode:Managed" in result.stdout:
                        return "Managed"
                    return "Unknown"
    except:
                    return "Unknown"

    def get_mac_address(self, interface): """Λήψη MAC address"""
    try:
                    result = subprocess.run(
                        [
        "ip",
        "link",
        "show", interface
    ], stdout=subprocess.PIPE, text=True
                    )
                    mac = re.search(r"link/ether ([0-9a-f:]{17})", result.stdout)
                    return mac.group(1) if mac else "Unknown"
    except:
                    return "Unknown"

    def get_ip_address(self, interface): """Λήψη IP address"""
    try:
                    result = subprocess.run(
                        [
        "ip",
        "addr",
        "show", interface
    ], stdout=subprocess.PIPE, text=True
                    )
                    ip = re.search(r"inet ([0-9.]+)", result.stdout)
                    return ip.group(1) if ip else "Not assigned"
    except:
                    return "Unknown"

    def toggle_interface(self): """Ενεργοποίηση/απενεργοποίηση interface"""
    if not self.selected_interface:
                    return

    try:
                    status = self.get_interface_status(self.selected_interface)[
        0
    ]
                    if status == "Ενεργή":
                        subprocess.run(
                            [
        "sudo",
        "ip",
        "link",
        "set",
                                self.selected_interface,
        "down"
    ],
                            check=True,
                        )
                    else:
                        subprocess.run(
                            [
        "sudo",
        "ip",
        "link",
        "set",
                                self.selected_interface,
        "up"
    ],
                            check=True,
                        )
                    self.update_status()
    except Exception as e:
                    messagebox.showerror(
                        "Σφάλμα", f"Αποτυχία εναλλαγής interface: {e}")

    def restart_interface(self): """Επανεκκίνηση interface"""
    if not self.selected_interface:
                    return

    try:
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
                        check=True,
                    )
                    time.sleep(1)
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
                        check=True,
                    )
                    messagebox.showinfo("Επιτυχία",
    "Το interface επανεκκινήθηκε")
                    self.update_status()
    except Exception as e:
                    messagebox.showerror("Σφάλμα", f"Αποτυχία επανεκκίνησης: {e}")

    def reset_interface(self): """Reset interface στις προεπιλεγμένες ρυθμίσεις"""
    if not self.selected_interface:
                    return

    try:
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "type",
        "managed"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
                        check=True,
                    )
                    messagebox.showinfo("Επιτυχία",
    "Το interface επαναφέρθηκε")
                    self.update_status()
    except Exception as e:
                    messagebox.showerror("Σφάλμα", f"Αποτυχία επαναφοράς: {e}")

    def set_monitor_mode(self): """Ρύθμιση monitor mode"""
    if not self.selected_interface:
                    return

    try:
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "monitor",
        "none"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
                        check=True,
                    )
                    messagebox.showinfo(
                        "Επιτυχία",
    "Ενεργοποιήθηκε το monitor mode")
                    self.update_status()
    except Exception as e:
                    messagebox.showerror(
                        "Σφάλμα", f"Αποτυχία ρύθμισης monitor mode: {e}")

    def set_managed_mode(self): """Ρύθμιση managed mode"""
    if not self.selected_interface:
                    return

    try:
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "down"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "iw", self.selected_interface,
        "set",
        "type",
        "managed"
    ],
                        check=True,
                    )
                    subprocess.run(
                        [
        "sudo",
        "ip",
        "link",
        "set", self.selected_interface,
        "up"
    ],
                        check=True,
                    )
                    messagebox.showinfo(
                        "Επιτυχία",
    "Ενεργοποιήθηκε το managed mode")
                    self.update_status()
    except Exception as e:
                    messagebox.showerror(
                        "Σφάλμα", f"Αποτυχία ρύθμισης managed mode: {e}")

    def launch_network_manager(self): """Εκκίνηση Network Manager"""
    try:
                    subprocess.Popen([
        "nm-connection-editor"
    ])
    except Exception as e:
                    messagebox.showerror(
                        "Σφάλμα", f"Αποτυχία εκκίνησης Network Manager: {e}"
                    )

    def scan_networks(self): """Σάρωση για ασύρματα δίκτυα"""
    if not self.selected_interface:
                    return

    try:
                    result = subprocess.run(
                        [
        "sudo",
        "iwlist", self.selected_interface,
        "scan"
    ],
                        stdout=subprocess.PIPE,
                        text=True,
                    )
                    self.info_text.delete(1.0, tk.END)
                    self.info_text.insert(tk.END, result.stdout)
    except Exception as e:
                    messagebox.showerror("Σφάλμα", f"Αποτυχία σάρωσης: {e}")

    def show_interface_details(self): """Εμφάνιση πληροφοριών interface"""
    if not self.selected_interface:
                    return

    try:
                    result = subprocess.run(
                        [
        "iwconfig", self.selected_interface
    ],
                        stdout=subprocess.PIPE,
                        text=True,
                    )
                    self.info_text.delete(1.0, tk.END)
                    self.info_text.insert(tk.END, result.stdout)
    except Exception as e:
                    messagebox.showerror(
                        "Σφάλμα", f"Αποτυχία λήψης πληροφοριών: {e}")

# ----------------------------------------------------------------

# Κουμπιά Main Window


# -----------------------------------------
button1 = tk.Button(
    window,
    text="Update",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=full_update,
)
button1.place(x=10, y=10)
button1.bind("<Enter>", on_enter)
button1.bind("<Leave>", on_leave)
ToolTip(button1,
"Full Update of the system")
# ---------------------------------------------
button2 = tk.Button(
    window,
    text="Upgrade",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=full_upgrade,
)
button2.place(x=10, y=50)
button2.bind("<Enter>", on_enter)
button2.bind("<Leave>", on_leave)
ToolTip(button2,
"Full Upgrade of the system")
# -------------------------------------------
button3 = tk.Button(
    window,
    text="Change Mac",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=change_mac,
)
button3.place(x=10, y=90)
button3.bind("<Enter>", on_enter)
button3.bind("<Leave>", on_leave)
ToolTip(button3,
"")
ToolTip(button3,
"Change the MAC address of the network interface")
# ------------------------------------------
button4 = tk.Button(
    window,
    text="Change IP",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=change_ip,
)
button4.place(x=10, y=130)
button4.bind("<Enter>", on_enter)
button4.bind("<Leave>", on_leave)
ToolTip(button4,
"Change the IP address manually or via DHCP")
# -----------------------------------------
button5 = tk.Button(
    window,
    text="Repair System",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=repair_system,
)
button5.place(x=10, y=170)
button5.bind("<Enter>", on_enter)
button5.bind("<Leave>", on_leave)
ToolTip(button5,
"Repair broken packages, dependencies, and system issues")
# -----------------------------------------
button6 = tk.Button(
    window,
    text="Clean System",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=clean_system,
)
button6.place(x=10, y=210)
button6.bind("<Enter>", on_enter)
button6.bind("<Leave>", on_leave)
ToolTip(button6,
"Clean system by removing cache, logs, and unnecessary packages")
# ----------------------------------------
button7 = tk.Button(
    window,
    text="System Info",
    width=15,
    bg="#333333",
    fg="white",
    relief="flat",
    borderwidth=0,
    command=show_system_info,
)
button7.place(x=10, y=250)
button7.bind("<Enter>", on_enter)
button7.bind("<Leave>", on_leave)
ToolTip(button7,
"Display detailed system information")
# ---------------------------------------
button8 = tk.Button(
    window,
    width=15,
    fg="white",
    bg="#333333",
    relief="flat",
    borderwidth=0,
    command=toggle_firewall,
)
# Ενημέρωση κειμένου/χρώματος ανάλογα με το status
update_firewall_button_text(button8)
button8.place(x=10, y=290)
button8.bind("<Enter>", on_enter)
button8.bind("<Leave>", on_leave)
ToolTip(button8,
"Enable or disable the system firewall")
# ---------------------------------------
button9 = tk.Button(
    window,
    text="Network Options",
    width=15,
    fg="white",
    bg="#333333",
    relief="flat",
    borderwidth=0,
    command=open_network_options,
)
button9.place(x=10, y=330)
button9.bind("<Enter>", on_enter)
button9.bind("<Leave>", on_leave)
ToolTip(button9,
"Network and interface management tools")

# -------------------------------------------------------------

window.mainloop()
