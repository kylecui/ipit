"""
Admin portal routes — dashboard, plugin management, LLM config, user profile.
"""

import ast
import json
import logging
import os
import shutil
from typing import Any

import yaml
from fastapi import APIRouter, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.responses import StreamingResponse

from admin.auth import get_current_user, login_redirect
from admin.database import admin_db
from admin.log_handler import LogStore
from app.config import settings
from app.i18n import i18n

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin")

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "..", "templates")
)

# ── Plugin config helpers ───────────────────────────────────────


def _plugins_yaml_path() -> str:
    return os.path.join(os.path.dirname(__file__), "..", "config", "plugins.yaml")


def _load_plugin_config() -> dict[str, Any]:
    try:
        with open(_plugins_yaml_path(), "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def _save_plugin_config(config: dict[str, Any]) -> None:
    with open(_plugins_yaml_path(), "w", encoding="utf-8") as f:
        yaml.dump(
            config, f, default_flow_style=False, allow_unicode=True, sort_keys=False
        )


def _get_all_plugins_info() -> list[dict[str, Any]]:
    """Get merged info from plugins.yaml + discovered plugin metadata."""
    config = _load_plugin_config()
    plugin_configs = config.get("plugins", {})

    # Detect which plugins are community-uploaded (deletable)
    community_dir = os.path.join(
        os.path.dirname(__file__), "..", "plugins", "community"
    )
    community_names: set[str] = set()
    if os.path.isdir(community_dir):
        for f in os.listdir(community_dir):
            if f.endswith(".py") and not f.startswith("_"):
                community_names.add(f.removesuffix(".py"))

    # Try to get metadata from registry
    plugin_metadata: dict[str, Any] = {}
    try:
        from plugins import PluginRegistry

        full_config = _load_plugin_config()
        # Temporarily enable all to discover metadata
        temp_config = {"plugins": {}}
        for name, cfg in full_config.get("plugins", {}).items():
            temp_cfg = dict(cfg)
            temp_cfg["enabled"] = True
            temp_config["plugins"][name] = temp_cfg
        reg = PluginRegistry(temp_config)
        reg.discover()
        for meta in reg.list_all():
            plugin_metadata[meta.name] = {
                "display_name": meta.display_name,
                "version": meta.version,
                "description": meta.description,
                "supported_types": meta.supported_types,
                "requires_api_key": meta.requires_api_key,
                "api_key_env_var": meta.api_key_env_var,
                "tags": meta.tags,
                "priority": meta.priority,
            }
    except Exception as e:
        logger.warning(f"Could not load plugin metadata: {e}")

    result = []
    for name, cfg in plugin_configs.items():
        info = {
            "name": name,
            "enabled": cfg.get("enabled", True),
            "api_key_env": cfg.get("api_key_env"),
            "priority": cfg.get("priority", 50),
            "config": cfg.get("config", {}),
        }
        if name in plugin_metadata:
            info.update(plugin_metadata[name])
        else:
            info.setdefault("display_name", name.replace("_", " ").title())
            info.setdefault("version", "?")
            info.setdefault("description", "")
            info.setdefault("requires_api_key", bool(cfg.get("api_key_env")))
            info.setdefault("api_key_env_var", cfg.get("api_key_env"))
        # Check if API key is actually set in environment
        env_var = info.get("api_key_env_var") or cfg.get("api_key_env")
        info["api_key_configured"] = bool(os.environ.get(env_var or ""))
        info["is_community"] = name in community_names
        result.append(info)
    return result


def _validate_plugin_source(source_code: str) -> dict[str, Any]:
    """Validate a plugin .py file using AST analysis.

    Checks:
      1. File is valid Python (parses without errors)
      2. Contains a class that inherits from TIPlugin
      3. Class has a 'metadata' property and 'query' method

    Returns:
        {"ok": bool, "plugin_name": str | None, "error": str | None}
    """
    try:
        tree = ast.parse(source_code)
    except SyntaxError as e:
        return {"ok": False, "plugin_name": None, "error": f"Syntax error: {e}"}

    # Find classes that inherit from TIPlugin
    plugin_classes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                base_names.append(base.id)
            elif isinstance(base, ast.Attribute):
                base_names.append(base.attr)
        if "TIPlugin" in base_names:
            plugin_classes.append(node)

    if not plugin_classes:
        return {
            "ok": False,
            "plugin_name": None,
            "error": "No TIPlugin subclass found. Plugin must inherit from TIPlugin.",
        }

    cls = plugin_classes[0]
    method_names = set()
    has_metadata = False
    for item in cls.body:
        if isinstance(item, ast.FunctionDef) or isinstance(item, ast.AsyncFunctionDef):
            method_names.add(item.name)
            if item.name == "metadata":
                has_metadata = True
        # Check decorated properties for metadata
        if isinstance(item, ast.FunctionDef):
            for dec in item.decorator_list:
                dec_name = ""
                if isinstance(dec, ast.Name):
                    dec_name = dec.id
                elif isinstance(dec, ast.Attribute):
                    dec_name = dec.attr
                if dec_name == "property" and item.name == "metadata":
                    has_metadata = True

    if not has_metadata:
        return {
            "ok": False,
            "plugin_name": None,
            "error": "Plugin class missing 'metadata' property.",
        }
    if "query" not in method_names:
        return {
            "ok": False,
            "plugin_name": None,
            "error": "Plugin class missing 'query' method.",
        }

    # Try to infer plugin name from class or file
    plugin_name = cls.name.lower().replace("plugin", "").strip("_") or cls.name.lower()
    return {"ok": True, "plugin_name": plugin_name, "error": None}


def _get_lang(request: Request) -> str:
    """Resolve display language."""
    lang = request.query_params.get("lang")
    if lang in i18n.SUPPORTED_LANGS:
        return lang
    cookie_lang = request.cookies.get("preferred_locale")
    if cookie_lang in i18n.SUPPORTED_LANGS:
        return cookie_lang
    return settings.language


def _admin_context(request: Request, user: dict, **extra: Any) -> dict[str, Any]:
    """Build template context for admin pages."""
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    return {
        "request": request,
        "user": user,
        "t": t,
        "lang": lang,
        "root_path": settings.root_path,
        **extra,
    }


# ── Auth routes ─────────────────────────────────────────────────


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    user = get_current_user(request)
    next_url = request.query_params.get("next", "")
    if user:
        # Already logged in — honour the next param or go to admin dashboard
        redirect_to = next_url or f"{settings.root_path}/admin/"
        return RedirectResponse(redirect_to, status_code=303)
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    return templates.TemplateResponse(
        "admin/login.html.j2",
        {
            "request": request,
            "t": t,
            "lang": lang,
            "root_path": settings.root_path,
            "next_url": next_url,
        },
    )


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_url: str = Form(""),
):
    user = admin_db.verify_password(username, password)
    if not user:
        lang = _get_lang(request)
        t = i18n.get_translator(lang)
        return templates.TemplateResponse(
            "admin/login.html.j2",
            {
                "request": request,
                "t": t,
                "lang": lang,
                "root_path": settings.root_path,
                "error": "Invalid username or password",
                "next_url": next_url,
            },
        )
    request.session["user_id"] = user["id"]
    admin_db.log_action(user["id"], "login", f"User {username} logged in")
    redirect_to = next_url or f"{settings.root_path}/admin/"
    return RedirectResponse(redirect_to, status_code=303)


@router.get("/logout")
async def logout(request: Request):
    user = get_current_user(request)
    if user:
        admin_db.log_action(user["id"], "logout", f"User {user['username']} logged out")
    request.session.clear()
    return RedirectResponse(f"{settings.root_path}/admin/login", status_code=303)


# ── Dashboard ───────────────────────────────────────────────────


@router.get("/", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    plugins = _get_all_plugins_info()
    enabled_count = sum(1 for p in plugins if p["enabled"])
    llm = admin_db.get_llm_settings(user["id"])
    llm_configured = bool(llm.get("api_key"))
    recent_logs = admin_db.get_recent_logs(10) if user.get("is_admin") else []
    return templates.TemplateResponse(
        "admin/dashboard.html.j2",
        _admin_context(
            request,
            user,
            plugin_count=len(plugins),
            enabled_count=enabled_count,
            llm_configured=llm_configured,
            recent_logs=recent_logs,
        ),
    )


# ── Plugin Management ──────────────────────────────────────────


@router.get("/plugins", response_class=HTMLResponse)
async def plugin_list(request: Request):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    plugins = _get_all_plugins_info()
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin/plugins.html.j2",
        _admin_context(request, user, plugins=plugins, msg=msg),
    )


@router.post("/plugins/{name}/toggle")
async def plugin_toggle(request: Request, name: str):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    config = _load_plugin_config()
    plugins = config.get("plugins", {})
    if name not in plugins:
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg=Plugin+not+found", status_code=303
        )
    current = plugins[name].get("enabled", True)
    plugins[name]["enabled"] = not current
    _save_plugin_config(config)
    action = "disabled" if current else "enabled"
    admin_db.log_action(user["id"], f"plugin_{action}", f"Plugin '{name}' {action}")
    return RedirectResponse(
        f"{settings.root_path}/admin/plugins?msg=Plugin+{name}+{action}",
        status_code=303,
    )


@router.post("/plugins/upload")
async def plugin_upload(request: Request, plugin_file: UploadFile = File(...)):
    """Upload a new community plugin (.py file) with AST validation."""
    user = get_current_user(request)
    if not user:
        return login_redirect(request)

    filename = plugin_file.filename or ""
    if not filename.endswith(".py"):
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg=Only+.py+files+are+accepted",
            status_code=303,
        )

    # Read content and validate
    content = await plugin_file.read()
    try:
        source_code = content.decode("utf-8")
    except UnicodeDecodeError:
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg=File+is+not+valid+UTF-8",
            status_code=303,
        )

    # AST validation: must parse, must contain a TIPlugin subclass
    validation = _validate_plugin_source(source_code)
    if not validation["ok"]:
        msg = validation["error"].replace(" ", "+")
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg={msg}",
            status_code=303,
        )

    # Save to plugins/community/
    community_dir = os.path.join(
        os.path.dirname(__file__), "..", "plugins", "community"
    )
    os.makedirs(community_dir, exist_ok=True)
    dest = os.path.join(community_dir, filename)

    if os.path.exists(dest):
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg=Plugin+{filename}+already+exists.+Delete+it+first.",
            status_code=303,
        )

    with open(dest, "w", encoding="utf-8") as f:
        f.write(source_code)

    # Auto-register in plugins.yaml with default config
    plugin_name = validation.get("plugin_name", filename.removesuffix(".py"))
    config = _load_plugin_config()
    plugins_cfg = config.setdefault("plugins", {})
    if plugin_name not in plugins_cfg:
        plugins_cfg[plugin_name] = {"enabled": True, "priority": 50, "config": {}}
        _save_plugin_config(config)

    admin_db.log_action(
        user["id"], "plugin_upload", f"Uploaded community plugin '{filename}'"
    )
    return RedirectResponse(
        f"{settings.root_path}/admin/plugins?msg=Plugin+{filename}+uploaded+successfully",
        status_code=303,
    )


@router.post("/plugins/{name}/delete")
async def plugin_delete(request: Request, name: str):
    """Delete a community plugin (builtin plugins cannot be deleted)."""
    user = get_current_user(request)
    if not user:
        return login_redirect(request)

    # Only allow deleting community plugins
    community_dir = os.path.join(
        os.path.dirname(__file__), "..", "plugins", "community"
    )
    matched_file = None
    if os.path.isdir(community_dir):
        for f in os.listdir(community_dir):
            if f.endswith(".py") and not f.startswith("_"):
                if f.removesuffix(".py") == name or f == name:
                    matched_file = os.path.join(community_dir, f)
                    break

    if not matched_file:
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins?msg=Cannot+delete+builtin+plugins",
            status_code=303,
        )

    os.remove(matched_file)

    # Remove from plugins.yaml
    config = _load_plugin_config()
    plugins_cfg = config.get("plugins", {})
    if name in plugins_cfg:
        del plugins_cfg[name]
        _save_plugin_config(config)

    admin_db.log_action(
        user["id"], "plugin_delete", f"Deleted community plugin '{name}'"
    )
    return RedirectResponse(
        f"{settings.root_path}/admin/plugins?msg=Plugin+{name}+deleted",
        status_code=303,
    )


@router.get("/plugins/{name}/config", response_class=HTMLResponse)
async def plugin_config_page(request: Request, name: str):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    config = _load_plugin_config()
    plugins = config.get("plugins", {})
    if name not in plugins:
        return RedirectResponse(f"{settings.root_path}/admin/plugins", status_code=303)
    plugin_cfg = plugins[name]
    # Get metadata too
    all_info = _get_all_plugins_info()
    plugin_info = next((p for p in all_info if p["name"] == name), {})
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin/plugin_config.html.j2",
        _admin_context(
            request,
            user,
            plugin_name=name,
            plugin_info=plugin_info,
            plugin_cfg=plugin_cfg,
            config_json=json.dumps(plugin_cfg.get("config", {}), indent=2),
            msg=msg,
        ),
    )


@router.post("/plugins/{name}/config")
async def plugin_config_save(
    request: Request,
    name: str,
    priority: int = Form(...),
    config_json: str = Form("{}"),
):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    config = _load_plugin_config()
    plugins = config.get("plugins", {})
    if name not in plugins:
        return RedirectResponse(f"{settings.root_path}/admin/plugins", status_code=303)
    try:
        parsed_config = json.loads(config_json)
    except json.JSONDecodeError:
        return RedirectResponse(
            f"{settings.root_path}/admin/plugins/{name}/config?msg=Invalid+JSON",
            status_code=303,
        )
    plugins[name]["priority"] = priority
    plugins[name]["config"] = parsed_config
    _save_plugin_config(config)
    admin_db.log_action(
        user["id"], "plugin_config", f"Updated config for plugin '{name}'"
    )
    return RedirectResponse(
        f"{settings.root_path}/admin/plugins/{name}/config?msg=Configuration+saved",
        status_code=303,
    )


# ── LLM Settings ───────────────────────────────────────────────


@router.get("/settings/llm", response_class=HTMLResponse)
async def llm_settings_page(request: Request):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    llm = admin_db.get_llm_settings(user["id"])
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin/llm_settings.html.j2",
        _admin_context(request, user, llm=llm, msg=msg),
    )


@router.post("/settings/llm")
async def llm_settings_save(
    request: Request,
    api_key: str = Form(""),
    model: str = Form("gpt-4o"),
    base_url: str = Form("https://api.openai.com/v1"),
):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    admin_db.save_llm_settings(
        user["id"], api_key=api_key, model=model, base_url=base_url
    )
    admin_db.log_action(
        user["id"], "llm_settings", f"Updated LLM settings (model: {model})"
    )
    return RedirectResponse(
        f"{settings.root_path}/admin/settings/llm?msg=LLM+settings+saved",
        status_code=303,
    )


@router.post("/api/llm/validate")
async def llm_validate(request: Request):
    """Validate LLM API key and base URL, return available models."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "Not authenticated"}, status_code=401
        )
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid JSON"}, status_code=400)
    api_key = body.get("api_key", "").strip()
    base_url = body.get("base_url", "").strip()
    if not api_key or not base_url:
        return JSONResponse({"ok": False, "error": "API key and base URL are required"})
    from app.llm_client import llm_client

    result = await llm_client.validate_connection(api_key, base_url)
    return JSONResponse(result)


@router.get("/api/llm/models")
async def llm_models(request: Request):
    """Return available models for the current user's saved LLM settings."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "Not authenticated"}, status_code=401
        )
    llm = admin_db.get_llm_settings(user["id"])
    api_key = llm.get("api_key", "").strip()
    base_url = llm.get("base_url", "").strip()
    if not api_key or not base_url:
        return JSONResponse({"ok": False, "models": [], "error": "LLM not configured"})
    from app.llm_client import llm_client

    result = await llm_client.validate_connection(api_key, base_url)
    return JSONResponse(result)


# ── User Profile ───────────────────────────────────────────────


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin/profile.html.j2",
        _admin_context(request, user, msg=msg),
    )


@router.post("/profile")
async def profile_update(
    request: Request,
    display_name: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    admin_db.update_profile(user["id"], display_name=display_name)
    admin_db.log_action(
        user["id"], "profile_update", f"Updated display name to '{display_name}'"
    )
    return RedirectResponse(
        f"{settings.root_path}/admin/profile?msg=Profile+updated",
        status_code=303,
    )


@router.post("/profile/password")
async def password_change(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    if new_password != confirm_password:
        return RedirectResponse(
            f"{settings.root_path}/admin/profile?msg=Passwords+do+not+match",
            status_code=303,
        )
    if len(new_password) < 4:
        return RedirectResponse(
            f"{settings.root_path}/admin/profile?msg=Password+too+short+(min+4)",
            status_code=303,
        )
    # Verify current password
    verified = admin_db.verify_password(user["username"], current_password)
    if not verified:
        return RedirectResponse(
            f"{settings.root_path}/admin/profile?msg=Current+password+is+incorrect",
            status_code=303,
        )
    admin_db.update_password(user["id"], new_password)
    admin_db.log_action(user["id"], "password_change", "Password changed")
    return RedirectResponse(
        f"{settings.root_path}/admin/profile?msg=Password+changed+successfully",
        status_code=303,
    )


# ── User Management (admin only) ──────────────────────────────


@router.get("/users", response_class=HTMLResponse)
async def user_list(request: Request):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return login_redirect(request)
    users = admin_db.list_users()
    msg = request.query_params.get("msg", "")
    return templates.TemplateResponse(
        "admin/users.html.j2",
        _admin_context(request, user, users=users, msg=msg),
    )


@router.post("/users/create")
async def user_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    display_name: str = Form(""),
    is_admin: bool = Form(False),
):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return login_redirect(request)
    try:
        admin_db.create_user(
            username=username,
            password=password,
            display_name=display_name or username,
            is_admin=is_admin,
        )
        admin_db.log_action(user["id"], "user_create", f"Created user '{username}'")
        return RedirectResponse(
            f"{settings.root_path}/admin/users?msg=User+{username}+created",
            status_code=303,
        )
    except Exception as e:
        return RedirectResponse(
            f"{settings.root_path}/admin/users?msg=Error:+{e}",
            status_code=303,
        )


@router.post("/users/{user_id}/delete")
async def user_delete(request: Request, user_id: int):
    user = get_current_user(request)
    if not user or not user.get("is_admin"):
        return login_redirect(request)
    if user_id == user["id"]:
        return RedirectResponse(
            f"{settings.root_path}/admin/users?msg=Cannot+delete+yourself",
            status_code=303,
        )
    target = admin_db.get_user_by_id(user_id)
    if target:
        admin_db.delete_user(user_id)
        admin_db.log_action(
            user["id"], "user_delete", f"Deleted user '{target['username']}'"
        )
    return RedirectResponse(
        f"{settings.root_path}/admin/users?msg=User+deleted",
        status_code=303,
    )


# ── Log Viewer ─────────────────────────────────────────────────


@router.get("/logs", response_class=HTMLResponse)
async def log_viewer(request: Request):
    user = get_current_user(request)
    if not user:
        return login_redirect(request)
    return templates.TemplateResponse(
        "admin/logs.html.j2",
        _admin_context(request, user),
    )


@router.get("/api/logs")
async def log_entries(request: Request):
    """Return current log entries as JSON (initial batch)."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "Not authenticated"}, status_code=401
        )
    since_id = int(request.query_params.get("since_id", "0"))
    level = request.query_params.get("level", "")
    search = request.query_params.get("search", "")
    store = LogStore()
    entries = store.get_entries(
        since_id=since_id, level=level or None, search=search or None
    )
    return JSONResponse({"ok": True, "entries": entries})


@router.get("/api/logs/stream")
async def log_stream(request: Request):
    """SSE endpoint streaming live log entries."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            {"ok": False, "error": "Not authenticated"}, status_code=401
        )
    level = request.query_params.get("level", "") or None

    async def _generate():
        store = LogStore()
        async for entry in store.stream(level=level):
            if await request.is_disconnected():
                break
            if entry.get("keepalive"):
                yield ": keepalive\n\n"
            else:
                yield f"event: log\ndata: {json.dumps(entry)}\n\n"

    return StreamingResponse(_generate(), media_type="text/event-stream")
