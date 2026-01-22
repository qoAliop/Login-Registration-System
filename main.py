import tkinter as tk
import sqlite3
import hashlib
import os
import re
import time

# =========================================================
# DATABASE SETUP
# Creates a local SQLite database to store users securely
# =========================================================

conn = sqlite3.connect("users.db")
cur = conn.cursor()

# Create users table if it doesn't already exist
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT,
    salt TEXT
)
""")
conn.commit()

# =========================================================
# SECURITY FUNCTIONS
# Handles hashing and password verification
# =========================================================

def hash_password(password, salt=None):
    """
    Hashes a password using PBKDF2 + SHA256.
    A random salt is generated if none is provided.
    """
    if not salt:
        salt = os.urandom(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000
    )
    return hashed.hex(), salt.hex()


def verify_password(password, stored_hash, stored_salt):
    """
    Verifies a password by hashing it again
    with the stored salt and comparing hashes.
    """
    new_hash, _ = hash_password(password, bytes.fromhex(stored_salt))
    return new_hash == stored_hash


def password_valid(p):
    """
    Password rules:
    - At least 6 characters
    - Must contain a special character
    """
    return len(p) >= 6 and re.search(r"[@#$%!&*]", p)


def username_valid(u):
    """
    Username rules:
    - Letters only
    - Underscore (_) and dot (.) allowed
    - No numbers
    """
    return re.fullmatch(r"[A-Za-z_.]+", u)

# =========================================================
# MAIN APPLICATION CLASS
# =========================================================

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ALI USER SYSTEM")
        self.root.attributes("-fullscreen", True)

        # Start in dark mode
        self.dark = True
        self.set_theme()

        # Main centered container
        self.container = tk.Frame(root, bg=self.bg)
        self.container.place(
            relx=0.5,
            rely=0.5,
            anchor="center",
            width=460,
            height=580
        )

        # App title
        self.title = tk.Label(
            self.container,
            text="ALI USER SYSTEM",
            font=("Segoe UI", 30, "bold"),
            fg="black",
            bg=self.bg
        )
        self.title.pack(pady=(20, 10))

        # Inline status message (errors / success)
        self.status = tk.Label(
            self.container,
            text="",
            font=("Segoe UI", 10),
            fg="red",
            bg=self.bg
        )
        self.status.pack(pady=(0, 10))

        # Startup animation
        self.fade_in()

        # Show login screen first
        self.show_login()

        # Keyboard shortcuts
        self.root.bind("<Return>", lambda e: self.login())
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    # =====================================================
    # THEME HANDLING (LIGHT / DARK MODE)
    # =====================================================

    def set_theme(self):
        """
        Sets colors depending on current theme.
        """
        if self.dark:
            self.bg = "#0f172a"
            self.box = "#020617"
            self.outline = "#334155"
            self.fg = "white"
            self.btn = "#2563eb"
            self.btn_hover = "#1d4ed8"
        else:
            self.bg = "#f8fafc"
            self.box = "#ffffff"
            self.outline = "#64748b"
            self.fg = "#020617"
            self.btn = "#1e40af"       # darker blue in light mode
            self.btn_hover = "#1e3a8a"

        self.root.configure(bg=self.bg)

    def toggle_theme(self):
        """
        Switch between light and dark mode.
        """
        self.dark = not self.dark
        self.set_theme()
        self.container.configure(bg=self.bg)
        self.title.configure(bg=self.bg)
        self.status.configure(bg=self.bg)
        self.show_login()

    # =====================================================
    # ANIMATIONS
    # =====================================================

    def fade_in(self):
        """
        Smooth fade-in animation on startup.
        """
        for i in range(11):
            self.root.attributes("-alpha", i / 10)
            self.root.update()
            time.sleep(0.03)

    # =====================================================
    # COMMON UI HELPERS
    # =====================================================

    def clear(self):
        """
        Clears the screen except title and status message.
        """
        for widget in self.container.winfo_children():
            if widget not in (self.title, self.status):
                widget.destroy()

        self.status.config(text="", fg="red")

    def set_status(self, text, success=False):
        """
        Shows inline feedback under inputs.
        """
        self.status.config(
            text=text,
            fg="#22c55e" if success else "#ef4444"
        )

    def entry(self, placeholder):
        """
        Styled text entry with outline and placeholder.
        """
        frame = tk.Frame(self.container, bg=self.outline)
        frame.pack(pady=8, fill="x")

        e = tk.Entry(
            frame,
            font=("Segoe UI", 12),
            bg=self.box,
            fg="grey",
            insertbackground=self.fg,
            relief="flat"
        )
        e.insert(0, placeholder)
        e.pack(fill="x", padx=1, pady=1, ipady=6)

        # Placeholder logic
        e.bind(
            "<FocusIn>",
            lambda _: (e.delete(0, tk.END), e.config(fg=self.fg))
            if e.get() == placeholder else None
        )
        e.bind(
            "<FocusOut>",
            lambda _: (e.insert(0, placeholder), e.config(fg="grey"))
            if not e.get() else None
        )

        return e

    def password_entry(self, placeholder):
        """
        Password field with show/hide eye button.
        """
        frame = tk.Frame(self.container, bg=self.outline)
        frame.pack(pady=8, fill="x")

        e = tk.Entry(
            frame,
            font=("Segoe UI", 12),
            bg=self.box,
            fg="grey",
            insertbackground=self.fg,
            relief="flat"
        )
        e.insert(0, placeholder)
        e.pack(side="left", fill="x", expand=True, padx=1, pady=1, ipady=6)

        visible = {"on": False}

        def toggle():
            visible["on"] = not visible["on"]
            e.config(show="" if visible["on"] else "*")

        # Eye button
        tk.Button(
            frame,
            text="👁",
            command=toggle,
            bg=self.box,
            fg=self.fg,
            relief="flat"
        ).pack(side="right", padx=5)

        # Placeholder behavior
        e.bind(
            "<FocusIn>",
            lambda _: (e.delete(0, tk.END), e.config(fg=self.fg, show="*"))
            if e.get() == placeholder else None
        )
        e.bind(
            "<FocusOut>",
            lambda _: (e.insert(0, placeholder), e.config(fg="grey", show=""))
            if not e.get() else None
        )

        return e

    def button(self, text, cmd, danger=False):
        """
        Styled button with hover effect.
        """
        bg = "#ef4444" if danger else self.btn
        hover = "#dc2626" if danger else self.btn_hover

        b = tk.Button(
            self.container,
            text=text,
            command=cmd,
            bg=bg,
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief="flat",
            activebackground=hover
        )
        b.pack(pady=8, fill="x")

        b.bind("<Enter>", lambda _: b.config(bg=hover))
        b.bind("<Leave>", lambda _: b.config(bg=bg))
        return b

    # =====================================================
    # LOGIN SCREEN
    # =====================================================

    def show_login(self):
        self.clear()

        tk.Label(
            self.container,
            text="Log In",
            font=("Segoe UI", 20, "bold"),
            fg=self.fg,
            bg=self.bg
        ).pack(pady=10)

        self.user = self.entry("Username")
        self.pwd = self.password_entry("Password")

        self.button("Login", self.login)
        self.button("Create Account", self.show_signup)
        self.button("Forgot Password", self.show_forgot)

        # Theme toggle button
        tk.Button(
            self.container,
            text="🌙 / ☀",
            command=self.toggle_theme,
            bg="#475569",
            fg="white",
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        ).pack(pady=6)

        self.button("EXIT", self.root.destroy, danger=True)

    def login(self):
        """
        Handles user login.
        """
        u, p = self.user.get(), self.pwd.get()

        cur.execute(
            "SELECT password_hash, salt FROM users WHERE username=?",
            (u,)
        )
        row = cur.fetchone()

        if not row:
            self.set_status("User not found")
            return

        if verify_password(p, row[0], row[1]):
            self.show_welcome(u)
        else:
            self.set_status("Wrong password")

    # =====================================================
    # WELCOME SCREEN (AFTER LOGIN)
    # =====================================================

    def show_welcome(self, username):
        self.clear()

        tk.Label(
            self.container,
            text="WELCOME",
            font=("Segoe UI", 26, "bold"),
            fg=self.fg,
            bg=self.bg
        ).pack(pady=(30, 10))

        tk.Label(
            self.container,
            text=username.upper(),
            font=("Segoe UI", 22),
            fg="#22c55e",
            bg=self.bg
        ).pack(pady=(0, 30))

        self.button("BACK", self.show_login)

    # =====================================================
    # SIGN UP SCREEN
    # =====================================================

    def show_signup(self):
        self.clear()

        tk.Label(
            self.container,
            text="Create Account",
            font=("Segoe UI", 18, "bold"),
            fg=self.fg,
            bg=self.bg
        ).pack(pady=10)

        self.new_user = self.entry("New Username")
        self.new_pass = self.password_entry("New Password")

        self.button("Create", self.signup)
        self.button("Back", self.show_login)

    def signup(self):
        """
        Creates a new user account.
        """
        u, p = self.new_user.get(), self.new_pass.get()

        if not username_valid(u):
            self.set_status("Letters + _ . only (no numbers)")
            return

        if not password_valid(p):
            self.set_status("6+ chars & special (@#$%!&*)")
            return

        try:
            h, s = hash_password(p)
            cur.execute(
                "INSERT INTO users VALUES (?,?,?)",
                (u, h, s)
            )
            conn.commit()
            self.set_status("Account created ✔", success=True)
            self.show_login()
        except sqlite3.IntegrityError:
            self.set_status("Username already exists")

    # =====================================================
    # FORGOT PASSWORD
    # =====================================================

    def show_forgot(self):
        self.clear()

        tk.Label(
            self.container,
            text="Reset Password",
            font=("Segoe UI", 18, "bold"),
            fg=self.fg,
            bg=self.bg
        ).pack(pady=10)

        self.reset_user = self.entry("Username")

        self.button("Generate Temp Password", self.reset_password)
        self.button("Back", self.show_login)

    def reset_password(self):
        """
        Generates a temporary password for the user.
        """
        u = self.reset_user.get()
        temp = "Temp@" + os.urandom(2).hex()

        h, s = hash_password(temp)
        cur.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE username=?",
            (h, s, u)
        )
        conn.commit()

        if cur.rowcount == 0:
            self.set_status("User not found")
        else:
            self.set_status(f"Temp password: {temp}", success=True)

# =========================================================
# RUN APPLICATION
# =========================================================

root = tk.Tk()
app = LoginApp(root)
root.mainloop()
