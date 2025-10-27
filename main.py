# -*- coding: utf-8 -*-
"""
main.py
中文 UI；三种候选；模板；熵值；复制与自动清空；本地 AES-GCM 保险库
"""
from __future__ import annotations
import os
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

import pyperclip  # pip install pyperclip

from password_generator import generate_password, estimate_entropy
from encryption_util import encrypt_data, decrypt_data

APP_TITLE = "🔐 SafeGen — 强密码随机生成器"
TEMPLATES_FILE = "templates.json"

class SafeGenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x560")
        self.resizable(False, False)
        # ttk 主题
        try:
            self.call("tk", "scaling", 1.2)
        except Exception:
            pass
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")

        # 读取模板
        if not os.path.exists(TEMPLATES_FILE):
            messagebox.showerror("错误", f"未找到模板文件：{TEMPLATES_FILE}")
            self.destroy()
            return
        with open(TEMPLATES_FILE, "r", encoding="utf-8") as f:
            self.templates = json.load(f)

        self.template_names = list(self.templates.keys())
        self.selected_template = tk.StringVar(value=self.template_names[0])

        # 剪贴板超时（秒）
        self.clipboard_timeout = tk.IntVar(value=20)

        # 三个候选
        self.candidates = ["", "", ""]
        self.labels = [tk.StringVar(value=f"密码 {i+1}") for i in range(3)]
        self.selected_idx = tk.IntVar(value=-1)

        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self):
        top = ttk.Frame(self, padding=(12, 10))
        top.pack(fill=tk.X)

        ttk.Label(top, text="模板：").pack(side=tk.LEFT, padx=(0, 4))
        ttk.OptionMenu(top, self.selected_template,
                       self.template_names[0], *self.template_names).pack(side=tk.LEFT)

        ttk.Button(top, text="创建 三个候选密码", command=self.action_create_three)\
            .pack(side=tk.LEFT, padx=10)
        ttk.Button(top, text="生成（复制选中）", command=self.action_generate_final)\
            .pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="保存到本地保险库", command=self.action_save_vault)\
            .pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="从保险库加载", command=self.action_load_vault)\
            .pack(side=tk.LEFT, padx=6)

        sep = ttk.Separator(self)
        sep.pack(fill=tk.X, pady=6)

        center = ttk.Frame(self, padding=(12, 6))
        center.pack(fill=tk.BOTH, expand=True)

        self.cards = []
        for i in range(3):
            lf = ttk.LabelFrame(center, text=f"候选 {i+1}", padding=12)
            lf.grid(row=0, column=i, padx=8, pady=4, sticky="n")

            pwd_label = tk.Label(lf, text="(未生成)", font=("Consolas", 12),
                                 wraplength=240, justify=tk.LEFT, anchor="w")
            pwd_label.pack(fill=tk.X, pady=(4, 8))

            ttk.Entry(lf, textvariable=self.labels[i], width=28).pack(pady=(0, 6))

            btns = ttk.Frame(lf)
            btns.pack(pady=4)
            ttk.Button(btns, text="刷新", command=lambda idx=i: self.action_refresh(idx))\
                .grid(row=0, column=0, padx=4)
            ttk.Button(btns, text="复制", command=lambda idx=i: self.action_copy(idx))\
                .grid(row=0, column=1, padx=4)
            ttk.Button(btns, text="选择", command=lambda idx=i: self.action_select(idx))\
                .grid(row=0, column=2, padx=4)

            entropy_label = ttk.Label(lf, text="熵：-- bits")
            entropy_label.pack(pady=(8, 2))

            self.cards.append({"pwd": pwd_label, "ent": entropy_label})

        bottom = ttk.Frame(self, padding=(12, 8))
        bottom.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Label(bottom, text="剪贴板自动清除(秒)：").pack(side=tk.LEFT)
        ttk.Spinbox(bottom, from_=5, to=120, textvariable=self.clipboard_timeout,
                    width=8).pack(side=tk.LEFT, padx=(6, 12))
        ttk.Label(bottom, text="提示：复制后将在设定时间后尝试清空剪贴板（best-effort）")\
            .pack(side=tk.LEFT)

    # ---------- Helpers ----------
    def _current_settings(self):
        name = self.selected_template.get()
        return self.templates.get(name, list(self.templates.values())[0])

    def _update_card(self, idx: int, pwd: str, settings: dict):
        self.candidates[idx] = pwd
        self.cards[idx]["pwd"].config(text=pwd)
        ent = estimate_entropy(
            pwd,
            use_upper=settings.get("use_upper", True),
            use_lower=settings.get("use_lower", True),
            use_digits=settings.get("use_digits", True),
            use_symbols=settings.get("use_symbols", True),
            exclude_chars=settings.get("exclude", ""),
        )
        self.cards[idx]["ent"].config(text=f"熵：{ent} bits")

    # ---------- Actions ----------
    def action_create_three(self):
        s = self._current_settings()
        lmin = int(s.get("min", 12))
        lmax = int(s.get("max", max(16, lmin)))

        # 策略1：强密码（含符号）
        len1 = max(lmin, min(16, lmax))
        p1 = generate_password(
            length=len1,
            use_upper=s.get("use_upper", True),
            use_lower=s.get("use_lower", True),
            use_digits=s.get("use_digits", True),
            use_symbols=s.get("use_symbols", True),
            exclude_chars=s.get("exclude", ""),
            require_each_type=True
        )
        self._update_card(0, p1, s)

        # 策略2：长字母数字（便于输入）
        len2 = min(max(lmin, 16), lmax)
        p2 = generate_password(
            length=len2,
            use_upper=s.get("use_upper", True),
            use_lower=s.get("use_lower", True),
            use_digits=True,
            use_symbols=False,
            exclude_chars=s.get("exclude", ""),
            require_each_type=False
        )
        self._update_card(1, p2, s)

        # 策略3：分段易记（小写+数字，4位一段）
        len3 = max(lmin, min(12, lmax))
        raw3 = generate_password(
            length=len3,
            use_upper=False,
            use_lower=True,
            use_digits=True,
            use_symbols=False,
            exclude_chars=s.get("exclude", ""),
            require_each_type=False
        )
        p3 = "-".join([raw3[i:i+4] for i in range(0, len(raw3), 4)])
        self._update_card(2, p3, s)

        self.selected_idx.set(-1)

    def action_refresh(self, idx: int):
        s = self._current_settings()
        # 用 max 长度刷新，以获得更强/更随机的观感
        l = int(s.get("max", max(12, int(s.get("min", 12)))))
        p = generate_password(
            length=l,
            use_upper=s.get("use_upper", True),
            use_lower=s.get("use_lower", True),
            use_digits=s.get("use_digits", True),
            use_symbols=s.get("use_symbols", True),
            exclude_chars=s.get("exclude", ""),
            require_each_type=True
        )
        self._update_card(idx, p, s)

    def action_copy(self, idx: int):
        if not self.candidates[idx]:
            messagebox.showwarning("提示", "请先生成该候选密码。")
            return
        pyperclip.copy(self.candidates[idx])
        messagebox.showinfo("已复制", f"候选 {idx+1} 已复制到剪贴板，"
                             f"{self.clipboard_timeout.get()} 秒后尝试清空。")
        self.after(self.clipboard_timeout.get() * 1000, self._clear_clipboard)

    def action_select(self, idx: int):
        if not self.candidates[idx]:
            messagebox.showwarning("提示", "请先生成该候选密码。")
            return
        self.selected_idx.set(idx)
        messagebox.showinfo("已选择", f"已选择候选 {idx+1} 作为最终密码。")

    def action_generate_final(self):
        idx = self.selected_idx.get()
        if idx < 0 or not self.candidates[idx]:
            messagebox.showwarning("提示", "请先选择一个候选密码！")
            return
        pyperclip.copy(self.candidates[idx])
        messagebox.showinfo("已复制", f"已复制选中密码到剪贴板，"
                             f"{self.clipboard_timeout.get()} 秒后尝试清空。")
        self.after(self.clipboard_timeout.get() * 1000, self._clear_clipboard)

    def _clear_clipboard(self):
        try:
            pyperclip.copy("")
            print("剪贴板已尝试清空。")
        except Exception as e:
            print("清空剪贴板失败：", e)

    def action_save_vault(self):
        entries = []
        for i in range(3):
            entries.append({"label": self.labels[i].get(), "password": self.candidates[i]})
        if all(not item["password"] for item in entries):
            messagebox.showwarning("提示", "没有可保存的密码，请先生成。")
            return

        master = simpledialog.askstring("主密码", "请输入用于加密的主密码（切勿遗忘）：",
                                        show="*")
        if not master:
            return

        payload = {"entries": entries, "meta": {"app": "SafeGen", "ver": 1}}
        blob = encrypt_data(payload, master)

        path = filedialog.asksaveasfilename(
            title="保存保险库文件",
            defaultextension=".vault",
            filetypes=[("Vault 文件", "*.vault"), ("所有文件", "*.*")]
        )
        if not path:
            return
        with open(path, "wb") as f:
            f.write(blob)
        messagebox.showinfo("保存成功", f"已保存到：\n{path}")

    def action_load_vault(self):
        path = filedialog.askopenfilename(
            title="选择保险库文件",
            filetypes=[("Vault 文件", "*.vault"), ("所有文件", "*.*")]
        )
        if not path:
            return
        master = simpledialog.askstring("主密码", "请输入主密码解锁保险库：", show="*")
        if not master:
            return
        try:
            with open(path, "rb") as f:
                blob = f.read()
            obj = decrypt_data(blob, master)
            entries = obj.get("entries", [])
            for i in range(3):
                label = entries[i]["label"] if i < len(entries) else f"密码 {i+1}"
                pwd = entries[i]["password"] if i < len(entries) else ""
                self.labels[i].set(label)
                s = self._current_settings()
                self._update_card(i, pwd, s) if pwd else self._update_card(i, "", s)
                if not pwd:
                    self.cards[i]["pwd"].config(text="(未生成)")
                    self.cards[i]["ent"].config(text="熵：-- bits")
            messagebox.showinfo("解锁成功", "已从保险库加载。")
        except Exception as e:
            messagebox.showerror("解密失败", f"无法解密或文件损坏：\n{e}")

if __name__ == "__main__":
    app = SafeGenApp()
    app.mainloop()
