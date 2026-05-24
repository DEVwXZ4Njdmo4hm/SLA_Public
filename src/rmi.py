#!/usr/bin/env python3
"""
Suricata LLM Agent (Milestone 1)
A tool to analyze Suricata logs using a large language model (LLM).

File:         rmi.py
Description:  FastAPI-based remote management interface with authentication and control endpoints.
Author:       Capri XXI (qxwzj@hotmail.com)
License:      MIT
"""

from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Literal, Optional, TYPE_CHECKING
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, EmailStr, Field
import uvicorn

from .config import config, PerfConfig
from .logging_utils import setup_logging
from .auth.models import Role, User, MAIL_PERMISSION_MAP, CredKey
from .auth.database import UserDB
from .auth.tokens import create_jwt, generate_api_key
from .auth.dependencies import get_current_user, require_role, init_auth_dependencies
from .auth.log_broadcast import LogBroadcaster

if TYPE_CHECKING:
	from .daily_report import DailyReportService
	from .executor import ExecutorRuntime
	from .finetune_store import FinetuneStore

logger = logging.getLogger(__name__)


# ── Pydantic request / response schemas ──────────────────────────────────────

class LoginRequest(BaseModel):
	username: str
	password: str

class LoginResponse(BaseModel):
	access_token: str
	token_type: str = "bearer"

class CreateUserRequest(BaseModel):
	username: str = Field(min_length=1, max_length=64)
	email: str = Field(min_length=1)
	password: str = Field(min_length=8)
	role: str = Field(description="One of: Owner, Administrator, Agent, Watcher")

class UpdateUserRequest(BaseModel):
	username: Optional[str] = None
	email: Optional[str] = None
	password: Optional[str] = None
	role: Optional[str] = None

class CreateAPIKeyRequest(BaseModel):
	label: str = ""
	expires_at: Optional[str] = None

class CreateAPIKeyResponse(BaseModel):
	api_key: str
	key_id: int
	label: str

class ExecuteRequest(BaseModel):
	capability: str
	params: Dict[str, Any] = {}

class UpdateCredentialRequest(BaseModel):
	value: str = Field(min_length=1, description="Credential value to store.")


# ── Fine-tuning label schemas (Improvement 30.7-E) ─────────────────────────

class FinetuneLabelRequest(BaseModel):
	label: Literal["confirmed", "rejected", "corrected"]
	note: str = ""
	corrected_response: str = ""

class FinetuneExportRequest(BaseModel):
	label_filter: Optional[str] = "confirmed"
	min_date: Optional[str] = None
	max_date: Optional[str] = None

# Well-known credential keys that may be managed via the RMI.
_MANAGED_CRED_KEYS: frozenset = frozenset({
	CredKey.LLM_API_KEY,
	CredKey.GIT_TOKEN,
	CredKey.MAIL_CLIENT_ID,
	CredKey.MAIL_CLIENT_SECRET,
})

# Mapping from managed credential keys to the corresponding Config attribute
# names.  Used by credential endpoints to hot-reload values into the running
# config singleton so that changes take effect without a restart.
_CRED_TO_CONFIG_ATTR: Dict[str, str] = {
	CredKey.LLM_API_KEY: "LLM_BACKEND_AUTH_TOKEN",
	CredKey.GIT_TOKEN: "GIT_TOKEN",
	CredKey.MAIL_CLIENT_ID: "MAIL_CLIENT_ID",
	CredKey.MAIL_CLIENT_SECRET: "MAIL_CLIENT_SECRET",
}

@dataclass
class RemoteCommand:
	name: str
	args: Dict[str, Any]
	enqueued_at: float


class RemoteCommandQueue:
	def __init__(self) -> None:
		self._lock = threading.Lock()
		self._queue: List[RemoteCommand] = []

	def push(self, cmd: RemoteCommand) -> None:
		with self._lock:
			self._queue.append(cmd)

	def drain(self) -> List[RemoteCommand]:
		with self._lock:
			if not self._queue:
				return []
			drained = list(self._queue)
			self._queue.clear()
			return drained

	def size(self) -> int:
		with self._lock:
			return len(self._queue)


def _perf_config_to_dict(item: PerfConfig) -> Dict[str, Any]:
	return {
		"index": item.index,
		"PERF_INDEX_MIN": item.PERF_INDEX_MIN,
		"PERF_INDEX_MAX": item.PERF_INDEX_MAX,
		"OLLAMA_MODEL": item.OLLAMA_MODEL,
		"OLLAMA_NUM_PREDICT": item.OLLAMA_NUM_PREDICT,
		"OLLAMA_TEMPERATURE": item.OLLAMA_TEMPERATURE,
		"OLLAMA_TOP_P": item.OLLAMA_TOP_P,
		"OLLAMA_TOP_K": item.OLLAMA_TOP_K,
		"LLM_CONCURRENCY": item.LLM_CONCURRENCY,
		"BATCH_SIZE": item.BATCH_SIZE,
		"POLL_INTERVAL": item.POLL_INTERVAL,
		"OLLAMA_CONTEXT_LENGTH": item.OLLAMA_CONTEXT_LENGTH,
	}


def apply_remote_command(command: RemoteCommand) -> Dict[str, Any]:
	return {
		"status": "error",
		"command": command.name,
		"reason": "unknown command",
	}


def apply_remote_commands(queue: RemoteCommandQueue) -> List[Dict[str, Any]]:
	results = []
	for command in queue.drain():
		results.append(apply_remote_command(command))
	return results


def _parse_report_date(date_str: str) -> date:
	"""Parse a date string in YYYY-MM-DD format."""
	try:
		return datetime.strptime(date_str.strip(), "%Y-%m-%d").date()
	except (ValueError, AttributeError) as exc:
		raise ValueError(f"Invalid date format: {date_str!r}. Expected YYYY-MM-DD.") from exc


def create_rmi_app(
	command_queue: RemoteCommandQueue,
	stats_getter: Optional[Callable[[], Dict[str, Any]]] = None,
	daily_report_service: Optional[DailyReportService] = None,
	user_db: Optional[UserDB] = None,
	jwt_secret: str = "",
	log_broadcaster: Optional[LogBroadcaster] = None,
	executor: Optional[ExecutorRuntime] = None,
	finetune_store: Optional[FinetuneStore] = None,
) -> FastAPI:
	app = FastAPI(title="Suricata LLM RMI", version=config.SOFTWARE_VERSION)

	# Wire auth dependencies
	if user_db is not None:
		init_auth_dependencies(user_db, jwt_secret)

	# ── Public endpoints ─────────────────────────────────────────────

	@app.get("/health")
	async def health() -> Dict[str, Any]:
		return {"status": "ok"}

	@app.get("/version")
	async def version() -> Dict[str, Any]:
		return {
			"name": config.SOFTWARE_NAME,
			"suffix": config.SOFTWARE_NAME_SUFFIX,
			"version": config.SOFTWARE_VERSION,
			"author": config.SOFTWARE_AUTHOR,
			"license": config.SOFTWARE_LICENSE,
		}

	# ── Login (public, returns JWT) ──────────────────────────────────

	@app.post("/login")
	async def login(body: LoginRequest) -> LoginResponse:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		user = user_db.authenticate(body.username, body.password)
		if user is None:
			raise HTTPException(status_code=401, detail="Invalid username or password.")
		token = create_jwt({"sub": str(user.id), "role": user.role.value}, jwt_secret, expire_seconds=config.AUTH_JWT_EXPIRE_SECONDS)
		return LoginResponse(access_token=token)

	# ── Authenticated endpoints ──────────────────────────────────────

	_any_role = require_role(Role.OWNER, Role.ADMINISTRATOR, Role.AGENT, Role.WATCHER)
	_admin_plus = require_role(Role.OWNER, Role.ADMINISTRATOR)
	_owner_only = require_role(Role.OWNER)

	@app.get("/perfcfg")
	@app.get("/perfcfgs")
	async def list_perfcfg(user: User = Depends(_any_role)) -> Dict[str, Any]:
		current_cfg = config.CURRENT_PERF_CONFIG
		current_payload = _perf_config_to_dict(current_cfg) if current_cfg else None
		return {
			"perf_index": config.PERF_INDEX_CURRENT,
			"current_config": current_payload,
			"adaptive": config.ADAPTIVE_DETAILS,
			"model_profiles": list(config.MODEL_PROFILES.keys()),
		}

	@app.get("/stats")
	async def stats(user: User = Depends(_any_role)) -> Dict[str, Any]:
		payload: Dict[str, Any] = {}
		if stats_getter is not None:
			try:
				payload = stats_getter() or {}
			except Exception:
				payload = {}
		ad = config.ADAPTIVE_DETAILS
		response = {
			"processed_total": int(payload.get("processed", 0) or 0),
			"failed_total": int(payload.get("failed", 0) or 0),
			"perf_index": config.PERF_INDEX_CURRENT,
			"pressure_score": ad.get("pressure_score"),
			"quality_factor": ad.get("quality_factor"),
			"effective_tps": ad.get("effective_tps"),
		}
		for minutes in (5, 15, 60):
			response[f"{minutes}min_processed"] = int(payload.get(f"{minutes}min_processed", 0) or 0)
			response[f"{minutes}min_failed"] = int(payload.get(f"{minutes}min_failed", 0) or 0)
			response[f"{minutes}min_total"] = int(payload.get(f"{minutes}min_total", 0) or 0)
		# Token consumption stats
		response["token_total"] = int(payload.get("token_total", 0) or 0)
		response["token_total_prompt"] = int(payload.get("token_total_prompt", 0) or 0)
		response["token_total_completion"] = int(payload.get("token_total_completion", 0) or 0)
		for label in ("1min", "5min", "30min", "1h", "6h", "24h"):
			for suffix in ("prompt_tokens", "completion_tokens", "total_tokens"):
				key = f"{label}_{suffix}"
				response[key] = int(payload.get(key, 0) or 0)
		if ad:
			avg_eval = ad.get("avg_eval_tokens")
			if avg_eval is not None:
				response["avg_tokens_per_log"] = avg_eval
		return response

	@app.post("/gen_report+{report_date_str}")
	async def gen_report(report_date_str: str, user: User = Depends(_admin_plus)) -> JSONResponse:
		"""Manually trigger daily report generation for a specific date.

		The report is generated asynchronously in a background thread.
		Returns 202 Accepted immediately; the result is delivered by email / PR
		once generation completes.
		"""
		if daily_report_service is None:
			raise HTTPException(status_code=503, detail="Daily report service is not available.")

		try:
			report_date = _parse_report_date(report_date_str)
		except ValueError as exc:
			raise HTTPException(status_code=400, detail=str(exc))

		if config.daily_report_active:
			return JSONResponse(
				status_code=409,
				content={
					"status": "busy",
					"report_date": report_date.isoformat(),
					"detail": "A daily report generation is already in progress.",
				},
			)

		logger.info("Manual daily report requested for %s via RMI (by %s)", report_date.isoformat(), user.username)

		def _generate() -> None:
			try:
				daily_report_service.generate_and_send(report_date, force=True)
			except Exception as exc:
				logger.error("Manual daily report generation failed: %s", exc)

		thread = threading.Thread(target=_generate, name="gen-report-manual", daemon=True)
		thread.start()

		return JSONResponse(
			status_code=202,
			content={
				"status": "accepted",
				"report_date": report_date.isoformat(),
				"detail": "Daily report generation started. Results will be delivered via email/PR.",
			},
		)

	# ── SSE: Streaming log endpoint ──────────────────────────────────

	@app.get("/log")
	async def stream_log(user: User = Depends(_admin_plus)) -> StreamingResponse:
		"""Server-Sent Events stream of application log lines."""
		if log_broadcaster is None:
			raise HTTPException(status_code=503, detail="Log streaming not available.")

		q = log_broadcaster.subscribe()

		async def _event_generator():
			try:
				while True:
					try:
						msg = await asyncio.wait_for(q.get(), timeout=30.0)
						yield f"data: {msg}\n\n"
					except asyncio.TimeoutError:
						yield ": keepalive\n\n"
			except asyncio.CancelledError:
				pass
			finally:
				log_broadcaster.unsubscribe(q)

		return StreamingResponse(_event_generator(), media_type="text/event-stream")

	# ── SSE: Streaming stats endpoint ────────────────────────────────

	@app.get("/stats/stream")
	async def stream_stats(user: User = Depends(_admin_plus)) -> StreamingResponse:
		"""Server-Sent Events stream of live stats snapshots (every 5s)."""

		async def _stats_generator():
			try:
				while True:
					payload: Dict[str, Any] = {}
					if stats_getter is not None:
						try:
							payload = stats_getter() or {}
						except Exception:
							payload = {}
					ad = config.ADAPTIVE_DETAILS
					snap = {
						"processed_total": int(payload.get("processed", 0) or 0),
						"failed_total": int(payload.get("failed", 0) or 0),
						"perf_index": config.PERF_INDEX_CURRENT,
						"pressure_score": ad.get("pressure_score"),
						"quality_factor": ad.get("quality_factor"),
					}
					yield f"data: {json.dumps(snap)}\n\n"
					await asyncio.sleep(5)
			except asyncio.CancelledError:
				pass

		return StreamingResponse(_stats_generator(), media_type="text/event-stream")

	# ── User management (Owner only) ─────────────────────────────────

	@app.get("/users")
	async def list_users(user: User = Depends(_owner_only)) -> List[Dict[str, Any]]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		users = user_db.list_users()
		return [
			{"id": u.id, "username": u.username, "email": u.email,
			 "role": u.role.value, "created_at": u.created_at, "updated_at": u.updated_at}
			for u in users
		]

	@app.post("/users")
	async def create_user(body: CreateUserRequest, user: User = Depends(_owner_only)) -> Dict[str, Any]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		try:
			role = Role.from_str(body.role)
		except ValueError:
			raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")
		try:
			new_user = user_db.create_user(
				username=body.username, email=body.email,
				password=body.password, role=role,
			)
		except Exception as exc:
			raise HTTPException(status_code=409, detail=str(exc))
		return {
			"id": new_user.id, "username": new_user.username,
			"email": new_user.email, "role": new_user.role.value,
		}

	@app.get("/users/{user_id}")
	async def get_user(user_id: int, user: User = Depends(_owner_only)) -> Dict[str, Any]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		target = user_db.get_user_by_id(user_id)
		if target is None:
			raise HTTPException(status_code=404, detail="User not found.")
		return {
			"id": target.id, "username": target.username, "email": target.email,
			"role": target.role.value, "created_at": target.created_at,
			"updated_at": target.updated_at,
		}

	@app.patch("/users/{user_id}")
	async def update_user(user_id: int, body: UpdateUserRequest, user: User = Depends(_owner_only)) -> Dict[str, Any]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		role = None
		if body.role is not None:
			try:
				role = Role.from_str(body.role)
			except ValueError:
				raise HTTPException(status_code=400, detail=f"Invalid role: {body.role}")
		try:
			updated = user_db.update_user(
				user_id, username=body.username, email=body.email,
				password=body.password, role=role,
			)
		except Exception as exc:
			raise HTTPException(status_code=409, detail=str(exc))
		if updated is None:
			raise HTTPException(status_code=404, detail="User not found.")
		return {
			"id": updated.id, "username": updated.username,
			"email": updated.email, "role": updated.role.value,
		}

	@app.delete("/users/{user_id}")
	async def delete_user(user_id: int, user: User = Depends(_owner_only)) -> Dict[str, str]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		if user_id == user.id:
			raise HTTPException(status_code=400, detail="Cannot delete yourself.")
		ok = user_db.delete_user(user_id)
		if not ok:
			raise HTTPException(status_code=404, detail="User not found.")
		return {"status": "deleted"}

	# ── API Key management ───────────────────────────────────────────

	@app.get("/users/{user_id}/apikeys")
	async def list_api_keys(user_id: int, user: User = Depends(_owner_only)) -> List[Dict[str, Any]]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		keys = user_db.list_api_keys(user_id)
		return [
			{"id": k.id, "label": k.label, "created_at": k.created_at,
			 "expires_at": k.expires_at, "revoked": k.revoked}
			for k in keys
		]

	@app.post("/users/{user_id}/apikeys")
	async def create_api_key_endpoint(
		user_id: int, body: CreateAPIKeyRequest, user: User = Depends(_owner_only),
	) -> CreateAPIKeyResponse:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		target = user_db.get_user_by_id(user_id)
		if target is None:
			raise HTTPException(status_code=404, detail="User not found.")
		raw_key = generate_api_key()
		rec = user_db.create_api_key(user_id, raw_key, label=body.label, expires_at=body.expires_at)
		return CreateAPIKeyResponse(api_key=raw_key, key_id=rec.id, label=rec.label)

	@app.delete("/apikeys/{key_id}")
	async def revoke_api_key_endpoint(key_id: int, user: User = Depends(_owner_only)) -> Dict[str, str]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		ok = user_db.revoke_api_key(key_id)
		if not ok:
			raise HTTPException(status_code=404, detail="API key not found.")
		return {"status": "revoked"}

	# ── Self-service endpoints ───────────────────────────────────────

	@app.get("/me")
	async def me(user: User = Depends(get_current_user)) -> Dict[str, Any]:
		return {
			"id": user.id, "username": user.username,
			"email": user.email, "role": user.role.value,
		}

	@app.get("/me/apikeys")
	async def my_api_keys(user: User = Depends(get_current_user)) -> List[Dict[str, Any]]:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		keys = user_db.list_api_keys(user.id)
		return [
			{"id": k.id, "label": k.label, "created_at": k.created_at,
			 "expires_at": k.expires_at, "revoked": k.revoked}
			for k in keys
		]

	@app.post("/me/apikeys")
	async def create_my_api_key(body: CreateAPIKeyRequest, user: User = Depends(get_current_user)) -> CreateAPIKeyResponse:
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		raw_key = generate_api_key()
		rec = user_db.create_api_key(user.id, raw_key, label=body.label, expires_at=body.expires_at)
		return CreateAPIKeyResponse(api_key=raw_key, key_id=rec.id, label=rec.label)

	# ── Credential management (Owner / Admin) ────────────────────────

	@app.get("/credentials")
	async def list_credentials(user: User = Depends(_admin_plus)) -> List[Dict[str, Any]]:
		"""List managed credential keys and their last-update timestamps."""
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		all_creds = user_db.get_all_credentials()
		return [
			{"key": k, "has_value": True}
			for k in sorted(all_creds)
			if k in _MANAGED_CRED_KEYS
		]

	@app.put("/credentials/{key}")
	async def set_credential(
		key: str, body: UpdateCredentialRequest, user: User = Depends(_admin_plus),
	) -> Dict[str, str]:
		"""Create or update a service credential."""
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		if key not in _MANAGED_CRED_KEYS:
			raise HTTPException(
				status_code=400,
				detail=f"Unknown credential key: {key!r}. "
				       f"Allowed keys: {sorted(_MANAGED_CRED_KEYS)}",
			)
		user_db.set_credential(key, body.value)
		# Hot-reload into the running config singleton so the new value
		# takes effect immediately (e.g. next LLM request uses new API key).
		attr = _CRED_TO_CONFIG_ATTR.get(key)
		if attr:
			setattr(config, attr, body.value)
		# Propagate LLM auth token into live backend instances.
		if key == CredKey.LLM_API_KEY and daily_report_service is not None:
			_backend = getattr(daily_report_service, "_backend", None)
			if _backend is not None and hasattr(_backend, "update_auth_token"):
				_backend.update_auth_token(body.value)
		logger.info("Credential %r updated by %s", key, user.username)
		return {"status": "updated", "key": key}

	@app.delete("/credentials/{key}")
	async def delete_credential(key: str, user: User = Depends(_admin_plus)) -> Dict[str, str]:
		"""Delete a service credential."""
		if user_db is None:
			raise HTTPException(status_code=503, detail="Auth subsystem not available.")
		if key not in _MANAGED_CRED_KEYS:
			raise HTTPException(
				status_code=400,
				detail=f"Unknown credential key: {key!r}. "
				       f"Allowed keys: {sorted(_MANAGED_CRED_KEYS)}",
			)
		ok = user_db.delete_credential(key)
		if not ok:
			raise HTTPException(status_code=404, detail=f"Credential {key!r} not found.")
		# Clear the value in the running config singleton.
		attr = _CRED_TO_CONFIG_ATTR.get(key)
		if attr:
			setattr(config, attr, "")
		# Clear LLM auth token on live backend instances.
		if key == CredKey.LLM_API_KEY and daily_report_service is not None:
			_backend = getattr(daily_report_service, "_backend", None)
			if _backend is not None and hasattr(_backend, "update_auth_token"):
				_backend.update_auth_token("")
		logger.info("Credential %r deleted by %s", key, user.username)
		return {"status": "deleted", "key": key}

	# ── Executor endpoints ───────────────────────────────────────────

	@app.get("/executor/capabilities")
	async def list_capabilities(user: User = Depends(_any_role)) -> List[str]:
		if executor is None:
			raise HTTPException(status_code=503, detail="Executor subsystem not available.")
		return executor.registry.list_names()

	@app.post("/executor/execute")
	async def execute_action(
		body: ExecuteRequest, user: User = Depends(_admin_plus),
	) -> Dict[str, Any]:
		if executor is None:
			raise HTTPException(status_code=503, detail="Executor subsystem not available.")
		from .executor.models import ActionRequest
		req = ActionRequest(
			capability=body.capability,
			params=body.params,
			actor_role=user.role.value,
			actor_id=str(user.id),
		)
		result = executor.execute(req)
		return {
			"request_id": result.request_id,
			"capability": result.capability,
			"status": result.status.value,
			"detail": result.detail,
		}

	@app.get("/executor/audit")
	async def list_audit(
		limit: int = 50, user: User = Depends(_admin_plus),
	) -> List[Dict[str, Any]]:
		if executor is None or executor.audit_db is None:
			raise HTTPException(status_code=503, detail="Executor audit not available.")
		entries = executor.audit_db.list_recent(limit)
		return [
			{
				"request_id": e.request_id,
				"capability": e.capability,
				"actor_role": e.actor_role,
				"actor_id": e.actor_id,
				"status": e.status,
				"detail": e.detail,
				"timestamp": e.timestamp,
				"level": e.level,
			}
			for e in entries
		]

	# ── Fine-tuning data endpoints (Improvement 30.7-E) ─────────────

	@app.get("/finetune/samples")
	async def list_finetune_samples(
		status: Optional[str] = None,
		threat_level: Optional[str] = None,
		limit: int = Query(default=50, le=500),
		offset: int = Query(default=0, ge=0),
		user: User = Depends(_admin_plus),
	):
		"""Query fine-tuning training samples."""
		if finetune_store is None:
			raise HTTPException(status_code=503, detail="finetune collection not enabled")
		return finetune_store.query_samples(
			status=status, threat_level=threat_level,
			limit=limit, offset=offset,
		)

	@app.post("/finetune/samples/{sample_id}/label")
	async def label_finetune_sample(
		sample_id: int,
		body: FinetuneLabelRequest,
		user: User = Depends(_admin_plus),
	):
		"""Submit human annotation for a training sample."""
		if finetune_store is None:
			raise HTTPException(status_code=503, detail="finetune collection not enabled")
		ok = finetune_store.set_human_label(
			sample_id=sample_id,
			label=body.label,
			note=body.note,
			corrected_response=body.corrected_response,
		)
		if not ok:
			raise HTTPException(status_code=404, detail="sample not found")
		return {"status": "ok"}

	@app.post("/finetune/export")
	async def export_finetune_data(
		body: FinetuneExportRequest,
		user: User = Depends(_admin_plus),
	):
		"""Export training samples to JSONL file."""
		if finetune_store is None:
			raise HTTPException(status_code=503, detail="finetune collection not enabled")
		export_dir = Path(config.FINETUNE_EXPORT_DIR)
		export_dir.mkdir(parents=True, exist_ok=True)
		output_path = export_dir / f"finetune_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.jsonl"
		count = finetune_store.export_jsonl(
			output_path=output_path,
			human_label_filter=body.label_filter,
			min_date=body.min_date,
			max_date=body.max_date,
		)
		return {"path": str(output_path), "count": count}

	return app


class RmiServer:
	def __init__(
		self,
		host: str,
		port: int,
		command_queue: RemoteCommandQueue,
		stats_getter: Optional[Callable[[], Dict[str, Any]]] = None,
		daily_report_service: Optional[DailyReportService] = None,
		user_db: Optional[UserDB] = None,
		jwt_secret: str = "",
		log_broadcaster: Optional[LogBroadcaster] = None,
		executor: Optional[ExecutorRuntime] = None,
		finetune_store: Optional[FinetuneStore] = None,
	) -> None:
		self._host = host
		self._port = port
		self._queue = command_queue
		self._stats_getter = stats_getter
		self._daily_report_service = daily_report_service
		self._user_db = user_db
		self._jwt_secret = jwt_secret
		self._log_broadcaster = log_broadcaster
		self._executor = executor
		self._finetune_store = finetune_store
		self._thread: Optional[threading.Thread] = None
		self._server: Optional[uvicorn.Server] = None

	def start(self) -> None:
		if self._server is not None:
			return
		setup_logging()
		app = create_rmi_app(
			self._queue,
			stats_getter=self._stats_getter,
			daily_report_service=self._daily_report_service,
			user_db=self._user_db,
			jwt_secret=self._jwt_secret,
			log_broadcaster=self._log_broadcaster,
			executor=self._executor,
			finetune_store=self._finetune_store,
		)
		config_uv = uvicorn.Config(
			app=app,
			host=self._host,
			port=self._port,
			log_level="info",
			log_config=None,
		)
		self._server = uvicorn.Server(config_uv)
		self._thread = threading.Thread(target=self._server.run, name="rmi-server", daemon=True)
		self._thread.start()
		logger.info("RMI server listening on %s:%s", self._host, self._port)

	def stop(self) -> None:
		if self._server is None:
			return
		self._server.should_exit = True
		if self._thread is not None:
			self._thread.join(timeout=5)
		self._server = None


def start_rmi_server(
	command_queue: RemoteCommandQueue,
	host: str,
	port: int,
	stats_getter: Optional[Callable[[], Dict[str, Any]]] = None,
	daily_report_service: Optional[DailyReportService] = None,
	user_db: Optional[UserDB] = None,
	jwt_secret: str = "",
	log_broadcaster: Optional[LogBroadcaster] = None,
	executor: Optional[ExecutorRuntime] = None,
	finetune_store: Optional[FinetuneStore] = None,
) -> RmiServer:
	server = RmiServer(
		host=host,
		port=port,
		command_queue=command_queue,
		stats_getter=stats_getter,
		daily_report_service=daily_report_service,
		user_db=user_db,
		jwt_secret=jwt_secret,
		log_broadcaster=log_broadcaster,
		executor=executor,
		finetune_store=finetune_store,
	)
	server.start()
	return server
