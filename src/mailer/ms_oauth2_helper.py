#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         ms_oauth2_helper.py
Description:  MSAL-based OAuth2 token cache management for Outlook integration.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

import msal
import logging

logger = logging.getLogger(__name__)

class MSOAuth2Helper:
    def __init__(self, client_id, client_secret, authority, scopes, token_cache_data):
        """
        Parameters
        ----------
        token_cache_data : str
            Serialised MSAL token cache (JSON string) loaded from
            ``credentials.db``.  The caller is responsible for persisting
            any updates back to the database after use (see
            :pymethod:`get_updated_cache`).
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.authority = authority
        self.scopes = scopes
        self._cache = msal.SerializableTokenCache()
        if token_cache_data:
            try:
                self._cache.deserialize(token_cache_data)
                logger.info("Loaded token cache from credentials.db")
            except Exception as e:
                logger.warning("Failed to deserialise token cache: %s", e)
        else:
            raise RuntimeError(
                "No OAuth2 token cache in credentials.db. "
                "Run the deploy script to provision tokens."
            )

        self.app = msal.ConfidentialClientApplication(
            self.client_id,
            authority=self.authority,
            client_credential=self.client_secret,
            token_cache=self._cache,
        )

    @property
    def cache_changed(self) -> bool:
        """Return ``True`` if the in-memory cache has been modified."""
        return self._cache.has_state_changed

    def get_updated_cache(self) -> str:
        """Return the serialised cache string for persistence."""
        return self._cache.serialize()

    def get_access_token(self):
        """
        Get access token silently from cache.
        Returns: (access_token, username)
        """
        accounts = self.app.get_accounts()
        if accounts:
            # logic to pick the right account? defaults to first one.
            username = accounts[0].get('username')
            logger.info(f"Found account in cache: {username}")
            result = self.app.acquire_token_silent(self.scopes, account=accounts[0])
            if result:
                return result['access_token'], username
            else:
                 logger.error(f"Failed to acquire token silently for {username}.")
        else:
            logger.error("No accounts found in token cache.")
        
        raise RuntimeError("Could not obtain access token. Ensure the cache file is populated and valid.")

    @staticmethod
    def generate_xoauth2_string(user_email, access_token):
        return f"user={user_email}\x01auth=Bearer {access_token}\x01\x01"
