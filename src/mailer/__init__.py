#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         __init__.py
Description:  Mail subsystem module exports for email sending and queue management.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from .send_mail import send_email
from .mail_queue import start_mail_queue, stop_mail_queue, get_mail_queue
from .recipients import get_recipients_for_event, init_mail_recipients

__all__ = [
    "send_email",
    "start_mail_queue",
    "stop_mail_queue",
    "get_mail_queue",
    "get_recipients_for_event",
    "init_mail_recipients",
]
