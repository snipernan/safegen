# -*- coding: utf-8 -*-
"""
password_generator.py
基于 Python secrets 的安全随机生成器 + 熵值估计
"""

from __future__ import annotations
import secrets
import string
import math
from typing import Iterable, Set

# 常用字符集合
UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGIT = string.digits
# 常见可接受符号（避免引号/空白等容易搞混或破格式的符号）
SYMBOL = "!@#$%^&*()-_=+[]{};:,.?/"

# 一些容易混淆的字符（可选排除）
AMBIGUOUS = set("O0Il1|`'\" ")

def _build_pool(use_upper: bool, use_lower: bool, use_digits: bool, use_symbols: bool,
                exclude_chars: Iterable[str] = ()) -> str:
    pool = ""
    if use_upper:
        pool += UPPER
    if use_lower:
        pool += LOWER
    if use_digits:
        pool += DIGIT
    if use_symbols:
        pool += SYMBOL
    # 去除排除字符
    if exclude_chars:
        ex: Set[str] = set(exclude_chars)
        pool = "".join(ch for ch in pool if ch not in ex)
    # 确保不为空
    if not pool:
        raise ValueError("字符池为空：请检查模板的开关与排除字符。")
    return pool

def generate_password(length: int,
                      use_upper: bool = True,
                      use_lower: bool = True,
                      use_digits: bool = True,
                      use_symbols: bool = True,
                      exclude_chars: str = "",
                      require_each_type: bool = True) -> str:
    """
    使用 CSPRNG 生成随机密码，可要求每类字符至少出现一次。
    """
    if length <= 0:
        raise ValueError("length 必须为正整数。")

    pool = _build_pool(use_upper, use_lower, use_digits, use_symbols, exclude_chars)

    if not require_each_type:
        return "".join(secrets.choice(pool) for _ in range(length))

    # 需要至少包含的字符集合
    buckets = []
    if use_upper:
        buckets.append(UPPER)
    if use_lower:
        buckets.append(LOWER)
    if use_digits:
        buckets.append(DIGIT)
    if use_symbols:
        buckets.append(SYMBOL)

    if len(buckets) > length:
        # 如果要求的类型数量超过长度，降级为不强制每类必含
        return "".join(secrets.choice(pool) for _ in range(length))

    # 先保证每类至少一个
    result = [secrets.choice(b) for b in buckets]
    # 剩余随机填充
    remaining = length - len(result)
    result += [secrets.choice(pool) for _ in range(remaining)]

    # 打乱
    for i in range(len(result) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        result[i], result[j] = result[j], result[i]
    return "".join(result)

def estimate_entropy(pwd: str,
                     use_upper: bool = True,
                     use_lower: bool = True,
                     use_digits: bool = True,
                     use_symbols: bool = True,
                     exclude_chars: str = "") -> int:
    """
    近似熵估计：H ≈ length * log2(|字符池|)
    注意：这是理论上界，不考虑网站复杂度校验等外部因素。
    """
    pool = _build_pool(use_upper, use_lower, use_digits, use_symbols, exclude_chars)
    charset_size = max(1, len(set(pool)))
    H = len(pwd) * math.log2(charset_size)
    return int(round(H))
