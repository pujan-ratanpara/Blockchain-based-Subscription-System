
#!/usr/bin/env python3
"""
Blockchain Subscription System - By using Tkinter app

"""

import threading
import time
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta

# ---------------------------
# Blockchain core
# ---------------------------
class Block:
    def __init__(self, index, timestamp, user, sub_date, expiry_date, prev_hash, difficulty=3):
        self.index = index
        self.timestamp = timestamp
        self.user = user
        self.sub_date = sub_date
        self.expiry_date = expiry_date
        self.prev_hash = prev_hash
        self.nonce = 0
        self.difficulty = difficulty
        self.hash = None

    def calculate_hash(self):
        data = f"{self.index}|{self.timestamp}|{self.user}|{self.sub_date}|{self.expiry_date}|{self.prev_hash}|{self.nonce}"
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def mine(self, update_callback=None, stop_event=None):
        target = "0" * self.difficulty
        while not stop_event.is_set():
            h = self.calculate_hash()
            if h.startswith(target):
                self.hash = h
                return h
            self.nonce += 1
            # occasionally call the callback so UI can update
            if update_callback and self.nonce % 5000 == 0:
                try:
                    update_callback(self.nonce)
                except Exception:
                    pass
        raise Exception("Mining interrupted")


class Blockchain:
    def __init__(self, difficulty=3):
        self.difficulty = difficulty
        self.chain = [self.create_genesis()]

    def create_genesis(self):
        g = Block(0, int(time.time()), "GENESIS", "-", "-", "0", self.difficulty)
        g.hash = g.calculate_hash()  # genesis no PoW required
        return g

    def add_block(self, user, sub_date, expiry_date, mining_callback=None, stop_event=None):
        prev = self.chain[-1]
        b = Block(len(self.chain), int(time.time()), user, sub_date, expiry_date, prev.hash, self.difficulty)
        # mine
        b.mine(update_callback=mining_callback, stop_event=stop_event or threading.Event())
        self.chain.append(b)
        return b

    def validate(self):
        for i in range(1, len(self.chain)):
            cur = self.chain[i]
            prev = self.chain[i - 1]

            if cur.hash != cur.calculate_hash():
                return False, f"Hash mismatch at {i}"
            if cur.prev_hash != prev.hash:
                return False, f"Previous hash mismatch at {i}"
            if not cur.hash.startswith("0" * cur.difficulty):
                return False, f"Proof-of-Work failed at {i}"
        return True, "Blockchain is VALID"


# ---------------------------
# System management
# ---------------------------
class System:
    def __init__(self):
        self.blockchain = Blockchain(difficulty=3)
        self.balances = {}
        self.users = set()

    def create_user(self, username):
        if not username:
            return False, "Enter username"
        if username in self.users:
            return False, "User already exists"
        self.users.add(username)
        self.balances[username] = 0
        return True, "User created"

    def topup(self, user, amt):
        if user not in self.users:
            return False, "User not found"
        try:
            amt = int(amt)
        except Exception:
            return False, "Invalid amount"
        if amt <= 0:
            return False, "Amount must be > 0"
        self.balances[user] += amt
        return True, f"Wallet topped by ₹{amt}"

    def get_last_expiry_ts(self, user):
        last = 0
        for b in self.blockchain.chain:
            if b.user == user and b.expiry_date != "-":
                try:
                    ts = int(datetime.strptime(b.expiry_date, "%Y-%m-%d %H:%M:%S").timestamp())
                    last = max(last, ts)
                except Exception:
                    # already timestamp number?
                    try:
                        last = max(last, int(b.expiry_date))
                    except Exception:
                        pass
        return last

    def add_subscription(self, user, amount, days, mining_callback=None, stop_event=None):
        if user not in self.users:
            return False, "User not found"
        if self.balances.get(user, 0) < amount:
            return False, "Not enough balance"
        self.balances[user] -= amount
        now = int(time.time())
        last = self.get_last_expiry_ts(user)
        start = max(now, last or 0)
        expiry_ts = start + days * 24 * 3600
        sub_date = datetime.fromtimestamp(start).strftime("%Y-%m-%d %H:%M:%S")
        expiry_date = datetime.fromtimestamp(expiry_ts).strftime("%Y-%m-%d %H:%M:%S")
        # mining is done inside add_block; pass callbacks
        b = self.blockchain.add_block(user, sub_date, expiry_date, mining_callback=mining_callback, stop_event=stop_event)
        return True, f"Subscription active until {expiry_date}"

    def check_subscription(self, user):
        last = self.get_last_expiry_ts(user)
        if last > int(time.time()):
            return True, f"ACTIVE until {datetime.fromtimestamp(last).strftime('%Y-%m-%d %H:%M:%S')}"
        return False, "Subscription EXPIRED"


# ---------------------------
# Tkinter UI
# ---------------------------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Blockchain Subscription System - Demo")
        self.geometry("1100x700")
        self.configure(bg="#0f1724")
        self.system = System()
        self.mining_thread = None
        self.mining_stop = threading.Event()
        self.create_styles()
        self.create_widgets()

    def create_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        # General widget styles
        style.configure("TLabel", background="#0f1724", foreground="#edf2f7", font=("Inter", 11))
        style.configure("Heading.TLabel", font=("Inter", 16, "bold"), foreground="#edf2f7")
        style.configure("Muted.TLabel", font=("Inter", 10), foreground="#9aa7bf", background="#0f1724")
        style.configure("Card.TFrame", background="#0b1220", relief="flat")
        style.configure("Panel.TFrame", background="#0b1220")
        style.configure("TButton", font=("Inter", 10, "bold"))

    def create_widgets(self):
        # Top header
        header = tk.Frame(self, bg="#0f1724")
        header.pack(fill="x", padx=24, pady=(16, 6))
        brand = tk.Frame(header, bg="#0f1724")
        brand.pack(side="left", anchor="w")

        logo = tk.Label(brand, text="BC", bg="#4f46e5", fg="white", width=4, height=2, font=("Inter", 12, "bold"))
        logo.grid(row=0, column=0, rowspan=2, padx=(0,12))
        tk.Label(brand, text="Blockchain Subscription System", bg="#0f1724", fg="white", font=("Inter", 14, "bold")).grid(row=0, column=1, sticky="w")
        tk.Label(brand, text="Lightweight demo — payments, subscriptions & ledger", bg="#0f1724", fg="#9aa7bf", font=("Inter", 9)).grid(row=1, column=1, sticky="w")

        tk.Label(header, text="Local demo • No external services", bg="#0f1724", fg="#9aa7bf", font=("Inter", 10)).pack(side="right")

        # Main grid
        main = tk.Frame(self, bg="#0f1724")
        main.pack(fill="both", expand=True, padx=24, pady=8)

        left = tk.Frame(main, bg="#0b1220", bd=0)
        left.pack(side="left", fill="y", padx=(0,12), pady=8)
        left.configure(width=320)
        left.pack_propagate(False)

        right = tk.Frame(main, bg="#0f1724")
        right.pack(side="left", fill="both", expand=True, pady=8)

        # Left panel content
        tk.Label(left, text="Manage Users & Subscriptions", bg="#0b1220", fg="white", font=("Inter", 12, "bold")).pack(anchor="w", pady=(8,12), padx=12)

        tk.Label(left, text="Username", bg="#0b1220", fg="#9aa7bf", font=("Inter", 10)).pack(anchor="w", padx=12)
        self.username_var = tk.StringVar()
        self.username_entry = tk.Entry(left, textvariable=self.username_var, font=("Inter", 11), bg="#081022", fg="white", insertbackground="white", bd=0, relief="flat")
        self.username_entry.pack(fill="x", padx=12, pady=(4,10))

        btn_frame = tk.Frame(left, bg="#0b1220")
        btn_frame.pack(fill="x", padx=12)

        self.create_user_btn = tk.Button(btn_frame, text="➕ Create New User", relief="flat", command=self.create_user, bg="#4f46e5", fg="white", padx=8, pady=8)
        self.create_user_btn.pack(fill="x")

        self.topup_btn = tk.Button(btn_frame, text="💰 Top-up Wallet (₹)", relief="flat", command=self.open_topup_dialog, bg="#0b1220", fg="#9aa7bf", padx=8, pady=8)
        self.topup_btn.pack(fill="x", pady=(8,0))

        ttk.Separator(left, orient="horizontal").pack(fill="x", pady=12, padx=12)

        tk.Label(left, text="Top-up Amount", bg="#0b1220", fg="#9aa7bf", font=("Inter", 10)).pack(anchor="w", padx=12)
        self.topup_amount_var = tk.IntVar(value=100)
        self.topup_amount_entry = tk.Entry(left, textvariable=self.topup_amount_var, font=("Inter", 11), bg="#081022", fg="white", insertbackground="white", bd=0, relief="flat")
        self.topup_amount_entry.pack(fill="x", padx=12, pady=(4,8))

        pay_frame = tk.Frame(left, bg="#0b1220")
        pay_frame.pack(fill="x", padx=12, pady=(6,0))
        self.pay100_btn = tk.Button(pay_frame, text="💳 Pay ₹100 (29 days)", relief="flat", bg="#16a34a", fg="black", command=lambda: self.start_subscription(100,29))
        self.pay100_btn.pack(fill="x")

        self.pay200_btn = tk.Button(pay_frame, text="💳 Pay ₹200 (58 days)", relief="flat", bg="#4f46e5", fg="white", command=lambda: self.start_subscription(200,58))
        self.pay200_btn.pack(fill="x", pady=(8,0))

        self.check_sub_btn = tk.Button(pay_frame, text="📅 Check Subscription", relief="flat", bg="#0b1220", fg="#9aa7bf", command=self.check_subscription)
        self.check_sub_btn.pack(fill="x", pady=(8,0))

        tk.Label(left, text="Tips: Subscriptions are chained using a simplified Proof-of-Work for demo purposes. Data stored in memory.", bg="#0b1220", fg="#9aa7bf", font=("Inter", 9), wraplength=280, justify="left").pack(padx=12, pady=(12,4))

        # Right side: cards
        top_card = tk.Frame(right, bg="#071022", bd=0)
        top_card.pack(fill="x", padx=6, pady=(0,10))

        # toolbar inside top_card
        toolbar = tk.Frame(top_card, bg="#071022")
        toolbar.pack(fill="x", padx=12, pady=12)

        bal_frame = tk.Frame(toolbar, bg="#071022")
        bal_frame.pack(side="left", anchor="w")
        tk.Label(bal_frame, text="Wallet Balance", bg="#071022", fg="#9aa7bf").pack(anchor="w")
        self.balance_label = tk.Label(bal_frame, text="—", bg="#071022", fg="white", font=("Inter", 14, "bold"))
        self.balance_label.pack(anchor="w")

        tool_btns = tk.Frame(toolbar, bg="#071022")
        tool_btns.pack(side="right", anchor="e")
        tk.Button(tool_btns, text="Refresh Ledger", relief="flat", command=self.refresh_ledger).pack(side="left", padx=6)
        tk.Button(tool_btns, text="Validate Blockchain", relief="flat", command=self.validate_blockchain).pack(side="left", padx=6)

        # ledger table
        ledger_container = tk.Frame(top_card, bg="#071022")
        ledger_container.pack(fill="both", expand=True, padx=12, pady=(0,12))

        cols = ("#","User","Subscribed","Expiry","Hash")
        self.tree = ttk.Treeview(ledger_container, columns=cols, show="headings", height=16)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor="w", width=150)
        self.tree.pack(fill="both", expand=True)

        # validation card
        validate_card = tk.Frame(right, bg="#0b1220")
        validate_card.pack(fill="x", padx=6, pady=(0,6))
        tk.Label(validate_card, text="Validation Result", bg="#0b1220", fg="white", font=("Inter", 12, "bold")).pack(anchor="w", padx=12, pady=(8,4))
        self.validation_result = tk.Label(validate_card, text="No validation performed yet", bg="#0b1220", fg="#9aa7bf", font=("Inter", 10))
        self.validation_result.pack(anchor="w", padx=12, pady=(0,12))

        # status bar at bottom
        self.status_var = tk.StringVar(value="Ready")
        status = tk.Label(self, textvariable=self.status_var, bg="#071022", fg="#9aa7bf", anchor="w", padx=12)
        status.pack(fill="x", side="bottom")

        # initial refresh
        self.refresh_ledger()

    # ---------------------------
    # UI action handlers
    # ---------------------------
    def create_user(self):
        u = self.username_var.get().strip()
        ok, msg = self.system.create_user(u)
        messagebox.showinfo("Create User", msg)
        self.refresh_ledger()

    def open_topup_dialog(self):
        # simple dialog to top-up current username using topup_amount_var as default
        user = self.username_var.get().strip()
        if not user:
            messagebox.showerror("Top-up", "Enter username first")
            return
        amt = self.topup_amount_var.get()
        ok, msg = self.system.topup(user, amt)
        messagebox.showinfo("Top-up", msg)
        self.refresh_ledger()

    def start_subscription(self, amount, days):
        user = self.username_var.get().strip()
        if not user:
            messagebox.showerror("Subscription", "Enter username first")
            return
        # check balance quickly
        if self.system.balances.get(user, 0) < amount:
            messagebox.showerror("Subscription", "Not enough balance")
            return
        # Disable buttons while mining
        self.set_busy(True, f"Mining block for {user} ...")
        self.mining_stop.clear()
        def mining_task():
            try:
                def mining_callback(nonce):
                    # update status occasionally (called from mining thread)
                    self.set_status(f"Mining... nonce={nonce}")
                ok, msg = self.system.add_subscription(user, amount, days, mining_callback=mining_callback, stop_event=self.mining_stop)
                # update UI on main thread
                self.after(0, lambda: messagebox.showinfo("Subscription", msg))
            except Exception as e:
                self.after(0, lambda: messagebox.showerror("Mining error", str(e)))
            finally:
                self.after(0, lambda: (self.set_busy(False), self.refresh_ledger()))
        self.mining_thread = threading.Thread(target=mining_task, daemon=True)
        self.mining_thread.start()

    def check_subscription(self):
        user = self.username_var.get().strip()
        if not user:
            messagebox.showerror("Subscription", "Enter username first")
            return
        ok, msg = self.system.check_subscription(user)
        messagebox.showinfo("Subscription Status", msg)

    def refresh_ledger(self):
        # update balance display
        u = self.username_var.get().strip()
        if u and u in self.system.users:
            self.balance_label.config(text=f"₹{self.system.balances.get(u,0)}")
        else:
            self.balance_label.config(text="—")

        # refresh table
        for i in self.tree.get_children():
            self.tree.delete(i)
        for b in self.system.blockchain.chain:
            h = b.hash or (b.calculate_hash()[:64])
            self.tree.insert("", "end", values=(b.index, b.user, b.sub_date, b.expiry_date, h[:32]+"..."))

    def validate_blockchain(self):
        ok, msg = self.system.blockchain.validate()
        self.validation_result.config(text=msg, fg="#16a34a" if ok else "#ef4444")
        messagebox.showinfo("Validation", msg)

    def set_status(self, text):
        self.status_var.set(text)

    def set_busy(self, busy, message=None):
        # enable/disable major buttons
        state = "disabled" if busy else "normal"
        for btn in (self.create_user_btn, self.topup_btn, self.pay100_btn, self.pay200_btn, self.check_sub_btn):
            try:
                btn.config(state=state)
            except Exception:
                pass
        if message:
            self.set_status(message)
        else:
            if not busy:
                self.set_status("Ready")

# ---------------------------
# Run app
# ---------------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
