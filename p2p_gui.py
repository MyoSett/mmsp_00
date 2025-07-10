import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, ttk
import time
import os
import sqlite3
import uuid

# === CONFIG ===
BROADCAST_PORT = 5001
DISCOVERY_INTERVAL = 5
DB_NAME = "chat.db"

# === GUI APP ===
class ChatApp:
    def __init__(self, root, nickname, port):
        self.root = root
        self.root.title(f"P2P Chat — {nickname} ({port})")
        self.nickname = nickname
        self.my_port = port
        self.peers = set()
        self.seen_messages = set()
        self.message_status = {}  # msg_id: status

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("", self.my_port))
        except OSError:
            self.my_port = self.find_free_port()
            self.sock.bind(("", self.my_port))

        self.discovery_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.discovery_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        try:
            self.discovery_sock.bind(("", BROADCAST_PORT))
        except OSError:
            self.discovery_sock.bind(("", self.find_free_port()))

        self.init_db()
        self.build_gui()
        self.load_chat_history()

        threading.Thread(target=self.listen_for_messages, daemon=True).start()
        threading.Thread(target=self.listen_for_discovery, daemon=True).start()
        threading.Thread(target=self.send_discovery_beacon, daemon=True).start()

    def load_chat_history(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT sender, message FROM messages ORDER BY timestamp ASC")
        rows = cursor.fetchall()
        conn.close()

        self.chat_display.config(state=tk.NORMAL)
        for sender, message in rows:
            tag = "you" if sender == self.nickname else "peer"
            self.chat_display.insert(tk.END, f"[{sender}] {message}\n", tag)
            self.chat_display.config(state=tk.DISABLED)

    def find_free_port(self):
        temp = socket.socket()
        temp.bind(("", 0))
        _, port = temp.getsockname()
        temp.close()
        return port

    def init_db(self):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # Create table if it doesn't exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            message TEXT,
            msg_id TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()

        # Check for missing 'msg_id' column
        cursor.execute("PRAGMA table_info(messages)")
        columns = [col[1] for col in cursor.fetchall()]
        if "msg_id" not in columns:
            cursor.execute("ALTER TABLE messages ADD COLUMN msg_id TEXT")
            conn.commit()

        if "status" not in columns:
            cursor.execute("ALTER TABLE messages ADD COLUMN status TEXT")
            conn.commit()

        conn.close()

    def build_gui(self):
        self.chat_display = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, bg="#f8f8ff", font=("Arial", 12))
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_display.config(state=tk.DISABLED)

        self.chat_display.tag_config("you", foreground="green", font=("Arial", 12, "bold"))
        self.chat_display.tag_config("peer", foreground="blue", font=("Arial", 12))
        self.chat_display.tag_config("status", foreground="gray", font=("Arial", 9, "italic"))

        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(padx=10, pady=5, fill=tk.X)

        tk.Label(bottom_frame, text="Send to:").pack(side=tk.LEFT)
        self.peer_selector = ttk.Combobox(bottom_frame, width=30, state="readonly")
        self.peer_selector.pack(side=tk.LEFT, padx=5)

        self.entry = tk.Entry(bottom_frame, font=("Arial", 12))
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.entry.bind("<Return>", lambda e: self.send_message())

        tk.Button(bottom_frame, text="Send", command=self.send_message, bg="#90ee90", width=8).pack(side=tk.LEFT, padx=5)

        control_frame = tk.Frame(self.root)
        control_frame.pack(pady=5)

        tk.Button(control_frame, text="Send File", command=self.send_file, bg="#d0e0ff", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Clear Chat", command=self.clear_chat, bg="#ffcccb", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Quit", command=self.root.quit, bg="#ffb6c1", width=12).pack(side=tk.LEFT, padx=5)

        # Group Chat Option
        self.peer_selector["values"] = ["Group Chat"]

    def update_peer_list(self):
        formatted_peers = [f"{ip}:{port}" for ip, port in self.peers]
        self.peer_selector["values"] = ["Group Chat"] + formatted_peers
        if not self.peer_selector.get():
            self.peer_selector.set("Group Chat")

    def log_message(self, sender, msg, msg_id, status="Sent"):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO messages (sender, message, msg_id, status) VALUES (?, ?, ?, ?)", (sender, msg, msg_id, status))
        conn.commit()
        conn.close()

    def display_message(self, sender, msg, msg_id=None, status=None):
        self.chat_display.config(state=tk.NORMAL)
        tag = "you" if sender == "You" else "peer"
        self.chat_display.insert(tk.END, f"[{sender}] {msg}\n", tag)
        if status and sender == "You":
            self.chat_display.insert(tk.END, f"   ↪ {status}\n", "status")
        self.chat_display.yview(tk.END)
        self.chat_display.config(state=tk.DISABLED)

    def send_message(self):
        msg = self.entry.get().strip()
        self.entry.delete(0, tk.END)
        peer_str = self.peer_selector.get().strip()
        if not msg or not peer_str:
            return

        msg_id = str(uuid.uuid4())[:8]

        try:
            if peer_str == "Group Chat":
                for peer in self.peers:
                    self.sock.sendto(f"MSG::{msg_id}::{self.nickname}::{msg}".encode(), peer)
                self.display_message("You", msg, msg_id, "Sent to Group")
            else:
                ip, port = peer_str.split(":")
                peer = (ip, int(port))
                self.sock.sendto(f"MSG::{msg_id}::{self.nickname}::{msg}".encode(), peer)
                self.display_message("You", msg, msg_id, "Sent")
                self.message_status[msg_id] = "Sent"
            self.log_message(self.nickname, msg, msg_id)
        except Exception as e:
            messagebox.showerror("Send Failed", str(e))

    def send_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            data = f.read()
        peer_str = self.peer_selector.get().strip()
        if not peer_str:
            return
        try:
            ip, port = peer_str.split(":")
            peer = (ip, int(port))
        except Exception:
            messagebox.showerror("Invalid Format", "Use format IP:PORT")
            return
        try:
            header = f"FILE::{self.nickname}::{filename}::{len(data)}".encode()
            self.sock.sendto(header, peer)
            time.sleep(0.1)
            self.sock.sendto(data, peer)
            self.display_message("You", f"Sent file: {filename}")
        except Exception as e:
            messagebox.showerror("File Send Failed", str(e))

    def clear_chat(self):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.delete(1.0, tk.END)
        self.chat_display.config(state=tk.DISABLED)
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM messages")
        conn.commit()
        conn.close()

    def listen_for_messages(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
                try:
                    decoded = data.decode()
                    parts = decoded.split("::")
                    if parts[0] == "MSG":
                        _, msg_id, sender, msg = parts
                        self.display_message(sender, msg)
                        self.log_message(sender, msg, msg_id, "Delivered")
                        self.sock.sendto(f"DELIVERED::{msg_id}".encode(), addr)
                        time.sleep(0.5)
                        self.sock.sendto(f"SEEN::{msg_id}".encode(), addr)
                    elif parts[0] == "DELIVERED":
                        msg_id = parts[1]
                        self.message_status[msg_id] = "Delivered"
                    elif parts[0] == "SEEN":
                        msg_id = parts[1]
                        self.message_status[msg_id] = "Seen"
                    elif parts[0] == "FILE":
                        _, sender, filename, size = parts
                        size = int(size)
                        file_data, _ = self.sock.recvfrom(size)
                        save_path = os.path.join(os.getcwd(), "received_" + filename)
                        with open(save_path, "wb") as f:
                            f.write(file_data)
                        self.display_message(sender, f"Sent you file: {filename} (saved as {save_path})")
                except UnicodeDecodeError:
                    pass
            except Exception as e:
                print("Error receiving data:", e)

    def listen_for_discovery(self):
        while True:
            try:
                data, addr = self.discovery_sock.recvfrom(1024)
                peer_ip = addr[0]
                try:
                    msg = data.decode()
                    if msg.startswith("DISCOVER::"):
                        port = int(msg.split("::")[1])
                        if (peer_ip, port) != (socket.gethostbyname(socket.gethostname()), self.my_port):
                            self.peers.add((peer_ip, port))
                            self.update_peer_list()
                except Exception:
                    continue
            except Exception as e:
                print("Discovery error:", e)

    def send_discovery_beacon(self):
        while True:
            try:
                msg = f"DISCOVER::{self.my_port}"
                self.discovery_sock.sendto(msg.encode(), ("<broadcast>", BROADCAST_PORT))
                time.sleep(DISCOVERY_INTERVAL)
            except Exception as e:
                print("Beacon error:", e)

# === START APP ===
if __name__ == "__main__":
    nickname = input("Enter your nickname: ")
    try:
        port = int(input("Enter your listening port (0 for auto): "))
    except ValueError:
        port = 0
    if port == 0:
        temp = socket.socket()
        temp.bind(("", 0))
        port = temp.getsockname()[1]
        temp.close()
    root = tk.Tk()
    app = ChatApp(root, nickname, port)
    root.mainloop()
