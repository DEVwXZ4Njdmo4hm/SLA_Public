#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         send_mail.py
Description:  Email sender with OAuth2 (Outlook) and Basic Auth (Gmail) support.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import smtplib
import logging
import os
import base64
import tomllib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from typing import Optional, List

from ..config import config
from .ms_oauth2_helper import MSOAuth2Helper

logger = logging.getLogger(__name__)

def load_provider_config(provider_name: str) -> dict:
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
    config_path = os.path.join(base_dir, "configs", "mail_providers", f"{provider_name}.toml")

    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file for provider '{provider_name}' not found at {config_path}")

    with open(config_path, "rb") as f:
        data = tomllib.load(f)
    provider_data = data.get("mail_provider", {}).get(provider_name)
    if not provider_data:
        raise ValueError(f"Missing [mail_provider.{provider_name}] section in {config_path}")
    return provider_data

def _send_email_raw(subject: str, html_body: str, recipients: Optional[List[str]] = None, attachments: Optional[List[str]] = None) -> bool:
    """Low-level email sender.  Returns True on success, False on failure.

    This function does NOT interact with the mail queue – callers that need
    retry semantics should use :func:`send_email` instead.
    """
    provider = config.MAIL_PROVIDER
    if not provider:
        logger.error("MAIL_PROVIDER is not set.")
        return False
        
    try:
        provider_config = load_provider_config(provider)
    except Exception as e:
        logger.error(f"Failed to load provider config: {e}")
        return False

    smtp = provider_config.get("smtp", {})
    smtp_host = smtp.get("host")
    smtp_port = smtp.get("port")
    
    if not smtp_host or not smtp_port:
        logger.error("Invalid provider config: missing smtp.host or smtp.port")
        return False

    sender = config.MAIL_SENDER
    
    to_list: List[str] = []
    if recipients:
        to_list = [r.strip() for r in recipients if r.strip()]
    
    if not sender or not to_list:
        logger.error("MAIL_SENDER or recipients not configured.")
        return False

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(to_list)
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))
    
    # Attachments logic if needed (not requested but good placeholder)
    if attachments:
        pass 

    server = None
    try:
        logger.info(f"Connecting to SMTP server {smtp_host}:{smtp_port} using provider '{provider}'...")
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.ehlo()
        server.starttls()
        server.ehlo()
        
        # Authentication Logic
        smtp = provider_config.get("smtp", {})
        auth_methods = smtp.get("auth_methods", ["password"])
        auth_method = auth_methods[0].lower() if auth_methods else "password"

        if auth_method == "oauth2":
            logger.info("Using OAuth2 authentication for provider '%s'.", provider)

            oauth2 = provider_config.get("oauth2", {})
            authority = oauth2.get("authority")
            scopes = oauth2.get("scopes")
            
            helper = MSOAuth2Helper(
                client_id=config.MAIL_CLIENT_ID,
                client_secret=config.MAIL_CLIENT_SECRET,
                authority=authority,
                scopes=scopes,
                token_cache_data=config.MAIL_OAUTH2_TOKEN_CACHE,
            )
            
            access_token, auth_user = helper.get_access_token()

            # Persist refreshed cache back to credentials.db
            if helper.cache_changed and config.AUTH_DB_PATH:
                try:
                    from ..auth.database import UserDB
                    from ..auth.models import CredKey
                    _db = UserDB(config.AUTH_DB_PATH)
                    _db.set_credential(
                        CredKey.MAIL_OAUTH2_TOKEN_CACHE,
                        helper.get_updated_cache(),
                    )
                    _db.close()
                    logger.info("OAuth2 token cache updated in credentials.db.")
                except Exception as e:
                    logger.warning("Failed to persist token cache to credentials.db: %s", e)
            
            # Use auth_user (from token) for XOAUTH2 login
            auth_str = MSOAuth2Helper.generate_xoauth2_string(auth_user, access_token)
            
            code, response = server.docmd("AUTH", "XOAUTH2 " + base64.b64encode(auth_str.encode("utf-8")).decode("utf-8"))
            if code != 235:
                raise Exception(f"OAuth2 Authentication failed: {code} {response}")

        else:
            # Basic Auth
            logger.info(f"Using Basic Authentication for provider '{provider}'.")
            password = config.MAIL_CLIENT_SECRET
            if password:
                server.login(sender, password)
            else:
                 logger.warning("No password found for basic auth. Attempting anonymous or relying on IP auth.")

        logger.info(f"Sending email from {sender} to {', '.join(to_list)}...")
        server.sendmail(sender, to_list, msg.as_string())
        server.quit()
        server = None  # quit() already closed the connection
        logger.info("Email sent successfully.")
        return True

    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False
    finally:
        if server is not None:
            try:
                server.close()
            except Exception:
                pass


def send_email(
    subject: str,
    html_body: str,
    recipients: Optional[List[str]] = None,
    attachments: Optional[List[str]] = None,
) -> bool:
    """Send an email; on failure, spool it for automatic retry.

    If a :class:`MailQueue` is running, the message is enqueued for
    exponential-backoff retry when the initial send fails.
    """
    ok = _send_email_raw(subject, html_body, recipients=recipients, attachments=attachments)
    if ok:
        return True

    # Attempt to spool for later retry
    from .mail_queue import get_mail_queue
    queue = get_mail_queue()
    if queue is not None and queue.is_running:
        queue.enqueue(subject, html_body, recipients=recipients, attachments=attachments)
        logger.info("Mail enqueued for retry (%d pending).", queue.pending_count)
    else:
        logger.warning("Mail queue is not running – failed email will NOT be retried.")
    return False
