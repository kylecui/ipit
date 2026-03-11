"""
Admin portal routes — dashboard, plugin management, LLM config, user profile.
"""

import json
import logging
import os
from typing import Any

import yaml
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from admin.auth import get_current_user, login_redirect
from admin.database import admin_db
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
        result.append(info)
    return result


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
    if user:
        return RedirectResponse(f"{settings.root_path}/admin/", status_code=303)
    lang = _get_lang(request)
    t = i18n.get_translator(lang)
    return templates.TemplateResponse(
        "admin/login.html.j2",
        {"request": request, "t": t, "lang": lang, "root_path": settings.root_path},
    )


@router.post("/login")
async def login_submit(
    request: Request, username: str = Form(...), password: str = Form(...)
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
            },
        )
    request.session["user_id"] = user["id"]
    admin_db.log_action(user["id"], "login", f"User {username} logged in")
    return RedirectResponse(f"{settings.root_path}/admin/", status_code=303)


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
