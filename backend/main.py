"""
Git仓库接入体检工具 - v0.4（多平台 + AI 接入建议）
当前能力范围：
  ✅ 解析 GitHub / Gitee 仓库链接 → 提取 provider/owner/repo
  ✅ 调用平台 API 获取仓库文件树
  ✅ 文件级检测：README / 依赖文件 / Windows 脚本后缀
  ✅ 异步并发拉取文本文件内容（Contents API，base64 解码）
  ✅ 正则扫描：硬编码路径（C:\\、/Users/、/home/）、sk- 密钥串
  ✅ 大仓库保护：二进制后缀跳过 + 单仓库最多扫描 200 文件 + 并发信号量
  ✅ 评分计算：满分 100，扣分制，扣分项逐条列出
  ✅ 风险分级：CRITICAL / HIGH / MEDIUM / LOW / CLEAN，密钥自动脱敏
  ✅ 异步任务 + 轮询进度（POST /api/scan + GET /api/tasks/{id}）
  ✅ AI 接入建议：DeepSeek 生成，密钥为空自动禁用且不影响基础扫描
  ✅ Pydantic 请求/响应结构 + 基础异常捕获
暂不做：增量更新、私有仓库授权
"""

import asyncio
import base64
import enum
import logging
import os
import re
import time
import traceback
import uuid
from contextlib import asynccontextmanager
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, model_validator

# ========== 0. 日志配置 ==========
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("git_repo_inspector")

# ========== 1. 读取环境变量 ==========
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITEE_TOKEN = os.getenv("GITEE_TOKEN", "")          # 可选：Gitee 公开仓库匿名亦可访问
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")

# AI 建议开关：密钥为空则自动禁用，不抛异常，不影响基础扫描
AI_ENABLED = bool(DEEPSEEK_API_KEY.strip())

GITHUB_API_BASE = "https://api.github.com"

# ---------- 仓库托管平台配置（GitHub / Gitee） ----------
PROVIDER_GITHUB = "github"
PROVIDER_GITEE = "gitee"

PROVIDER_API_BASE = {
    PROVIDER_GITHUB: "https://api.github.com",
    PROVIDER_GITEE: "https://gitee.com/api/v5",
}
PROVIDER_DOMAIN = {
    PROVIDER_GITHUB: "github.com",
    PROVIDER_GITEE: "gitee.com",
}
PROVIDER_LABEL = {
    PROVIDER_GITHUB: "GitHub",
    PROVIDER_GITEE: "Gitee",
}

# ---------- DeepSeek（AI 接入建议）配置 ----------
DEEPSEEK_API_BASE = "https://api.deepseek.com"
DEEPSEEK_MODEL = "deepseek-chat"
DEEPSEEK_TIMEOUT = 45.0
AI_ADVICE_MAX_TOKENS = 900


# ========== 2. Pydantic 定义 ==========
class ScanRequest(BaseModel):
    """请求体：仓库链接（支持 GitHub / Gitee 公开仓库）"""
    repo_url: str = Field(..., description="公开仓库链接，如 https://github.com/owner/repo 或 https://gitee.com/owner/repo")

    @field_validator("repo_url")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        """Pydantic 校验：在进入业务逻辑前先做基础校验"""
        if not v or not v.strip():
            raise ValueError("仓库链接不能为空")
        v = v.strip().rstrip("/")
        lower = v.lower()
        # 仅支持 GitHub / Gitee
        if not ("github.com" in lower or "gitee.com" in lower):
            raise ValueError("目前仅支持 github.com 或 gitee.com 仓库链接")
        # 必须有协议头或 SSH 格式
        if not (lower.startswith("https://") or lower.startswith("http://") or lower.startswith("git@")):
            raise ValueError("链接格式不正确，请以 https://github.com/owner/repo 或 https://gitee.com/owner/repo 开头")
        # 排除只写了域名的坏链接
        if lower.endswith("github.com") or lower.endswith("gitee.com"):
            raise ValueError("链接缺少 owner/repo 路径，请提供完整仓库链接")
        return v


class RepoInfo(BaseModel):
    """仓库基础信息"""
    owner: str
    repo: str
    default_branch: str
    total_files: int
    provider: str = PROVIDER_GITHUB   # "github" / "gitee"（默认值保证旧接口兼容）


class ReadinessCheck(BaseModel):
    """基础完备度检测结果"""
    has_readme: bool
    found_dependency_files: List[str]


class RiskBrief(BaseModel):
    """风险概览（仅基于文件名，暂不扫内容）"""
    windows_script_files: List[str]  # .bat / .cmd / .ps1 / .vbs


class ContentHit(BaseModel):
    """单文件内容扫描命中项"""
    file_path: str
    hit_type: str                     # "hardcoded_path" / "secret_key"
    matched_texts: List[str]          # 命中的具体文本片段（去重）


class ContentScanResult(BaseModel):
    """内容扫描汇总"""
    scanned_files: int                # 实际拉取并扫描的文本文件数
    skipped_files: List[str]          # 跳过的文件（二进制/超长/拉取失败）
    hits: List[ContentHit]            # 命中清单


class RiskItem(BaseModel):
    """合并后的风险清单条目（前端直接展示）"""
    level: str                        # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
    category: str                     # "secret_key" / "hardcoded_path" / "windows_script"
    file_path: str
    detail: str                       # 具体命中内容（密钥做脱敏）


class ScoreDetail(BaseModel):
    """评分详情：扣分项逐条列出，方便前端展示"""
    base_score: int                   # 起始分 100
    deductions: List[dict]            # [{"item": "无 README", "points": -20}, ...]
    final_score: int                  # 最终得分 0~100


class ScanSummary(BaseModel):
    """汇总：评分 + 风险等级 + 合并后的风险清单"""
    score: int
    score_detail: ScoreDetail
    risk_level: str                   # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "CLEAN"
    risk_items: List[RiskItem]


class AiAdvice(BaseModel):
    """AI 接入建议（DeepSeek 生成；未配置密钥时自动禁用）"""
    enabled: bool                       # AI 模块是否启用（密钥非空）
    provider: str = "deepseek"          # AI 服务商
    model: Optional[str] = None         # 模型名
    content: Optional[str] = None       # 建议正文（Markdown 文本）
    message: Optional[str] = None       # 禁用 / 失败时的提示文案
    error: Optional[str] = None         # 调用失败时的错误摘要


class ScanResponse(BaseModel):
    """POST /api/scan 返回结构"""
    repo_info: RepoInfo
    readiness: ReadinessCheck
    risk_brief: RiskBrief
    content_scan: Optional[ContentScanResult] = None  # 内容扫描结果
    summary: Optional[ScanSummary] = None             # 新增：评分 + 风险汇总
    ai_advice: Optional[AiAdvice] = None              # 新增：AI 接入建议（可选，向后兼容）


class ErrorResponse(BaseModel):
    """统一错误响应格式（全局异常处理器使用）"""
    code: int                           # HTTP status code
    message: str                        # 可读错误信息
    detail: Optional[str] = None        # 技术细节（可选）
    data: Optional[Any] = None          # 占位，保持接口对称


# ========== 3. 配置常量 ==========
# 依赖清单文件名（多语言生态，按 basename 匹配，覆盖任意层级）
# Python 生态：requirements.txt（传统）+ pyproject.toml（现代主流 PEP 517/518）+ setup.py / setup.cfg
# JavaScript：package.json（npm/yarn/pnpm 标配）
# Java：pom.xml（Maven）+ build.gradle(.kts)（Gradle）
# Go：go.mod
# Rust：Cargo.toml
DEPENDENCY_FILES = frozenset({
    # Python
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "Pipfile.lock", "poetry.lock",
    # JavaScript / Node.js
    "package.json",
    # Java
    "pom.xml", "build.gradle", "build.gradle.kts",
    # Go
    "go.mod",
    # Rust
    "Cargo.toml", "Cargo.lock",
})

# Windows 危险脚本后缀
WINDOWS_SCRIPT_EXTS = frozenset({".bat", ".cmd", ".ps1", ".vbs"})

# README 文件名变体（大小写无关）
README_PATTERN = re.compile(r"^readme(\.[^.]+)?$", re.IGNORECASE)

# ---------- 内容扫描：正则模式 ----------
# 硬编码 Windows 绝对路径：C:\... D:\...
HARDCODED_WIN_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")
# 硬编码 Unix 用户路径：/Users/xxx /home/xxx
HARDCODED_UNIX_PATH = re.compile(r"/(?:Users|home)/[^\s\"'`)+,;]+")
# sk- 开头的密钥串（OpenAI/DeepSeek 等兼容格式）
SECRET_KEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b")

# ---------- 内容扫描：跳过规则 ----------
# 明显的二进制/媒体文件后缀，不拉取内容
BINARY_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp", ".tiff",
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo", ".pyd", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".mov", ".flv", ".wav", ".ogg",
    ".db", ".sqlite", ".sqlite3",
    ".lock",  # package-lock.json / yarn.lock 体积大且价值低
})

# 内容扫描：单仓库最多扫描多少个文件（大仓库保护）
MAX_SCAN_FILES = 200

# 并发拉取文件内容的信号量（防止 GitHub API 限流）
CONTENT_SEMAPHORE = asyncio.Semaphore(10)

# GitHub API 限流 headers（用于准确判断限流，不依赖 resp.text 字符串匹配）
GH_HEADER_RATELIMIT_REMAINING = "x-ratelimit-remaining"
GH_HEADER_RATELIMIT_RESET = "x-ratelimit-reset"

# 共享 HTTP client（避免每次请求新建 client 的开销 + 连接复用）
# 生命周期：FastAPI lifespan 启动时创建，关闭时释放
_shared_client: Optional[httpx.AsyncClient] = None

# 通配跳过的文件名（无后缀配置文件，避免拉取 .env / .gitignore 等）
SKIP_FILENAMES = frozenset({
    ".env", ".env.local", ".env.example",
    ".gitignore", ".dockerignore", ".gitattributes",
    ".editorconfig", ".prettierrc", ".eslintrc", ".babelrc",
    ".npmrc", ".yarnrc", ".flake8",
    "Dockerfile", "Makefile", "LICENSE", "CHANGELOG",
})

# ---------- 评分权重（满分 100，扣分制）----------
# 完备度扣分：仓库基本接入条件缺失
SCORE_READINESS_PENALTY = {
    "no_readme": -20,           # 无 README
    "no_dependency": -15,       # 无依赖清单
}

# 风险扣分：内容/文件名扫描命中（per-item + 封顶）
SCORE_RISK_PENALTY = {
    "secret_key_per_hit": -20,       # 每个 sk- 密钥命中（内容）
    "hardcoded_path_per_file": -5,   # 每个硬编码路径文件（内容）
    "windows_script_per_file": -5,   # 每个 Windows 脚本文件（文件名）
}

# 风险扣分封顶（单项最高扣分）——防止大量文档示例路径把分扣到 0
SCORE_RISK_CAP = {
    "hardcoded_path_max": -30,      # 硬编码路径最多扣 30 分
    "windows_script_max": -20,       # Windows 脚本最多扣 20 分
}

# ---------- 风险等级定义（最高严重度优先）----------
RISK_CRITICAL = "CRITICAL"   # 发现密钥泄露（sk-）
RISK_HIGH = "HIGH"           # Windows 脚本 ≥3 或 硬编码路径文件 ≥5
RISK_MEDIUM = "MEDIUM"       # Windows 脚本 1~2 或 硬编码路径文件 1~4
RISK_LOW = "LOW"             # 仅有轻微项
RISK_CLEAN = "CLEAN"         # 无风险


# ========== 4. 工具函数 ==========
def parse_repo_url(url: str) -> Tuple[str, str, str]:
    """
    从仓库链接提取 (provider, owner, repo)，支持 GitHub / Gitee。
    支持格式：
      https://github.com/owner/repo
      https://github.com/owner/repo.git
      https://github.com/owner/repo/tree/main/...
      git@github.com:owner/repo.git
      https://gitee.com/owner/repo(.git)
      git@gitee.com:owner/repo.git
    解析失败则抛 ValueError。
    """
    url = url.strip().rstrip("/")

    for provider in (PROVIDER_GITHUB, PROVIDER_GITEE):
        domain = PROVIDER_DOMAIN[provider]
        domain_re = re.escape(domain)

        # SSH 格式：git@github.com:owner/repo.git
        ssh_match = re.match(rf"git@{domain_re}[:/]([^/]+)/([^/]+?)(?:\.git)?$", url)
        if ssh_match:
            return provider, ssh_match.group(1), ssh_match.group(2)

        # HTTPS 格式
        https_match = re.match(
            rf"https?://(?:www\.)?{domain_re}/([^/]+)/([^/]+?)(?:\.git)?(?:/.*)?$",
            url,
        )
        if https_match:
            return provider, https_match.group(1), https_match.group(2)

    raise ValueError(f"无法解析仓库链接（仅支持 GitHub / Gitee）：{url}")


def parse_github_url(url: str) -> Tuple[str, str]:
    """向后兼容封装：仅返回 (owner, repo)"""
    _, owner, repo = parse_repo_url(url)
    return owner, repo


def _is_github_rate_limited(resp: httpx.Response, provider: str = PROVIDER_GITHUB) -> Optional[str]:
    """
    判断平台响应是否属于限流 / 匿名访问被拒。
    返回提示字符串（含平台名与重置时间）；非限流返回 None。
    """
    label = _provider_label(provider)
    token_name = "GITHUB_TOKEN" if provider == PROVIDER_GITHUB else "GITEE_TOKEN"

    remaining = resp.headers.get(GH_HEADER_RATELIMIT_REMAINING, "")
    reset_ts = resp.headers.get(GH_HEADER_RATELIMIT_RESET, "")

    limited = False
    if provider == PROVIDER_GITHUB and remaining == "0":
        limited = True
    elif resp.status_code == 403 and "rate limit" in resp.text.lower():
        limited = True
    elif provider == PROVIDER_GITEE and resp.status_code == 403:
        # Gitee 匿名访问超频或需要令牌时统一返回 403
        limited = True

    if not limited:
        return None

    reset_msg = ""
    if reset_ts and reset_ts.isdigit():
        import datetime
        reset_time = datetime.datetime.fromtimestamp(int(reset_ts)).strftime("%Y-%m-%d %H:%M:%S")
        reset_msg = f"，额度重置时间：{reset_time}"

    if provider == PROVIDER_GITEE:
        return f"{label} API 拒绝访问（403）{reset_msg}，可能触发匿名访问频率限制，建议在 .env 配置 {token_name}"
    return f"{label} API 限流{reset_msg}（建议配置 {token_name}）"


def _provider_headers(provider: str = PROVIDER_GITHUB) -> Dict[str, str]:
    """构造平台 API 请求 headers（GitHub 支持可选 token）"""
    if provider == PROVIDER_GITHUB:
        headers = {"Accept": "application/vnd.github+json"}
        if GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        return headers
    return {"Accept": "application/json"}


def _provider_params(provider: str = PROVIDER_GITHUB, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """构造平台 API 请求 query 参数（Gitee 用 access_token 传参）"""
    params: Dict[str, str] = dict(extra or {})
    if provider == PROVIDER_GITEE and GITEE_TOKEN:
        params["access_token"] = GITEE_TOKEN
    return params


def _provider_label(provider: str) -> str:
    return PROVIDER_LABEL.get(provider, provider)


def _github_auth_headers() -> Dict[str, str]:
    """向后兼容封装"""
    return _provider_headers(PROVIDER_GITHUB)


async def _get_shared_client() -> httpx.AsyncClient:
    """获取共享 httpx client（延迟初始化 + 连接池复用）"""
    global _shared_client
    if _shared_client is None or _shared_client.is_closed:
        _shared_client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    return _shared_client


async def fetch_repo_info(owner: str, repo: str, provider: str = PROVIDER_GITHUB) -> dict:
    """调用 /repos/{owner}/{repo} 获取仓库元信息（含 default_branch），支持 GitHub / Gitee"""
    label = _provider_label(provider)
    client = await _get_shared_client()
    try:
        resp = await client.get(
            f"{PROVIDER_API_BASE[provider]}/repos/{owner}/{repo}",
            headers=_provider_headers(provider),
            params=_provider_params(provider),
        )
    except httpx.TimeoutException:
        logger.error("fetch_repo_info 超时: %s/%s", owner, repo)
        raise HTTPException(status_code=504, detail=f"{label} API 请求超时：{owner}/{repo}")
    except httpx.NetworkError as e:
        logger.error("fetch_repo_info 网络错误: %s/%s - %s", owner, repo, e)
        raise HTTPException(status_code=502, detail=f"无法连接 {label}：{e}")

    if resp.status_code == 404:
        logger.warning("仓库不存在或私有: %s/%s", owner, repo)
        raise HTTPException(status_code=404, detail=f"仓库不存在或为私有仓库：{owner}/{repo}")
    if resp.status_code == 401:
        logger.error("%s Token 无效", label)
        raise HTTPException(status_code=401, detail=f"{label} Token 无效，请检查 .env 中的 {provider.upper()}_TOKEN")
    rate_limit_msg = _is_github_rate_limited(resp, provider)
    if rate_limit_msg:
        logger.warning("%s API 限流: %s", label, rate_limit_msg)
        raise HTTPException(status_code=429, detail=rate_limit_msg)
    if resp.status_code != 200:
        logger.error("fetch_repo_info 失败: %s %s", resp.status_code, resp.text[:200])
        raise HTTPException(status_code=502, detail=f"{label} API 调用失败：{resp.status_code} {resp.text[:200]}")

    logger.info("仓库元信息获取成功: %s/%s branch=%s", owner, repo, resp.json().get("default_branch"))
    return resp.json()


async def fetch_file_tree(owner: str, repo: str, branch: str, provider: str = PROVIDER_GITHUB) -> List[str]:
    """
    调用 /repos/{owner}/{repo}/git/trees/{branch}?recursive=1
    拉取完整文件树，返回所有文件路径列表（不含目录），支持 GitHub / Gitee。
    """
    label = _provider_label(provider)
    client = await _get_shared_client()
    try:
        resp = await client.get(
            f"{PROVIDER_API_BASE[provider]}/repos/{owner}/{repo}/git/trees/{branch}",
            params=_provider_params(provider, {"recursive": "1"}),
            headers=_provider_headers(provider),
        )
    except httpx.TimeoutException:
        logger.error("fetch_file_tree 超时: %s/%s branch=%s", owner, repo, branch)
        raise HTTPException(status_code=504, detail=f"拉取文件树超时：{branch}")
    except httpx.NetworkError as e:
        logger.error("fetch_file_tree 网络错误: %s/%s - %s", owner, repo, e)
        raise HTTPException(status_code=502, detail=f"无法连接 {label}：{e}")

    if resp.status_code == 404:
        logger.warning("分支不存在: %s/%s branch=%s", owner, repo, branch)
        raise HTTPException(status_code=404, detail=f"分支不存在：{branch}")
    rate_limit_msg = _is_github_rate_limited(resp, provider)
    if rate_limit_msg:
        logger.warning("%s API 限流(文件树): %s", label, rate_limit_msg)
        raise HTTPException(status_code=429, detail=rate_limit_msg)
    if resp.status_code != 200:
        logger.error("fetch_file_tree 失败: %s %s", resp.status_code, resp.text[:200])
        raise HTTPException(status_code=502, detail=f"拉取文件树失败：{resp.status_code} {resp.text[:200]}")

    data = resp.json()
    file_paths = [item["path"] for item in data.get("tree", []) if item.get("type") == "blob"]
    logger.info("文件树获取成功: %s/%s branch=%s files=%d", owner, repo, branch, len(file_paths))
    return file_paths


def run_readiness_check(file_paths: List[str]) -> ReadinessCheck:
    """
    三项文件级完备度检测（只看文件名）：
    - README：匹配任意层级 readme* basename
    - 依赖清单：匹配任意层级的 DEPENDENCY_FILES 集合内的 basename（去重）
    - 返回找到的**依赖文件名列表**（不返回完整路径）
    """
    # README 检测（basename 匹配，任意层级）
    has_readme = any(README_PATTERN.match(os.path.basename(p)) for p in file_paths)

    # 依赖文件检测（basename 匹配，覆盖任意层级 + 去重）
    found_deps = sorted({
        os.path.basename(p) for p in file_paths
        if os.path.basename(p) in DEPENDENCY_FILES
    })

    return ReadinessCheck(has_readme=has_readme, found_dependency_files=found_deps)


def run_risk_check(file_paths: List[str]) -> RiskBrief:
    """Windows 危险脚本文件识别（基于后缀）"""
    script_files = [
        p for p in file_paths
        if os.path.splitext(p)[1].lower() in WINDOWS_SCRIPT_EXTS
    ]
    return RiskBrief(windows_script_files=sorted(script_files))


# ---------- 新增：内容扫描相关工具函数 ----------
def should_skip_file(path: str) -> bool:
    """
    判断文件是否应该跳过内容拉取。
    跳过条件：
      1. 二进制/媒体后缀（BINARY_EXTS）
      2. 敏感配置文件名（SKIP_FILENAMES，如 .env、.gitignore）
      3. .env 通配（含任意层级 .env* 开头的文件）
    """
    basename = os.path.basename(path).lower()
    ext = os.path.splitext(path)[1].lower()
    if ext in BINARY_EXTS:
        return True
    if basename in SKIP_FILENAMES:
        return True
    # .env* 通配：任何 .env.xxx 或以 .env 结尾的
    if basename.startswith(".env"):
        return True
    return False


async def fetch_file_content(
    owner: str, repo: str, branch: str, file_path: str, provider: str = PROVIDER_GITHUB
) -> Optional[str]:
    """
    调用 Contents API 拉取单个文件内容（GitHub / Gitee）。
    返回解码后的文本；拉取失败则返回 None（但不吞异常，调用方会记日志）。
    """
    client = await _get_shared_client()
    try:
        async with CONTENT_SEMAPHORE:
            resp = await client.get(
                f"{PROVIDER_API_BASE[provider]}/repos/{owner}/{repo}/contents/{file_path}",
                params=_provider_params(provider, {"ref": branch}),
                headers=_provider_headers(provider),
            )
    except httpx.TimeoutException:
        logger.debug("fetch_file_content 超时: %s", file_path)
        return None
    except httpx.NetworkError as e:
        logger.debug("fetch_file_content 网络错误: %s - %s", file_path, e)
        return None

    if resp.status_code == 404:
        logger.debug("fetch_file_content 404: %s", file_path)
        return None
    if resp.status_code == 403:
        # Contents API 的限流（单独打 debug，避免刷屏 warning）
        logger.debug("fetch_file_content 403(可能限流): %s", file_path)
        return None

    if resp.status_code != 200:
        logger.debug("fetch_file_content %s: %s", resp.status_code, file_path)
        return None

    try:
        data = resp.json()
        # Contents API 对 >1MB 文件不返回 content 字段
        content_b64 = data.get("content")
        if not content_b64:
            return None
        text = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        # 兜底：检查是否真的是文本（含 null 字节多半是二进制）
        if "\x00" in text[:1024]:
            return None
        return text
    except (ValueError, KeyError, UnicodeDecodeError) as e:
        logger.debug("fetch_file_content 解析失败: %s - %s", file_path, e)
        return None


def scan_text_content(text: str) -> List[Tuple[str, List[str]]]:
    """
    对单个文本执行正则扫描。
    返回 [(hit_type, [去重后的命中片段列表])]；无命中则返回空列表。
    """
    results: List[Tuple[str, List[str]]] = []

    win_hits = list(dict.fromkeys(HARDCODED_WIN_PATH.findall(text)))
    if win_hits:
        results.append(("hardcoded_path", win_hits))

    unix_hits = list(dict.fromkeys(HARDCODED_UNIX_PATH.findall(text)))
    if unix_hits:
        results.append(("hardcoded_path", unix_hits))

    secret_hits = list(dict.fromkeys(SECRET_KEY_PATTERN.findall(text)))
    if secret_hits:
        results.append(("secret_key", secret_hits))

    return results


async def run_content_scan(
    owner: str, repo: str, branch: str, file_paths: List[str],
    task_id: Optional[str] = None,
    progress_cb: Optional[Callable[[str, int, str], None]] = None,
    provider: str = PROVIDER_GITHUB,
) -> ContentScanResult:
    """
    并发拉取文件内容 + 正则扫描。
    task_id / progress_cb 可选：传入则回写进度（用于轮询模式），不传则纯函数调用。
    进度区间：进入时 ~40，并发拉取完 ~70，全部完成 ~85。
    """
    # 预过滤：跳过二进制后缀 + 敏感配置
    candidates = [p for p in file_paths if not should_skip_file(p)]
    skipped = [p for p in file_paths if should_skip_file(p)]

    # 大仓库保护：截断到上限
    if len(candidates) > MAX_SCAN_FILES:
        skipped.extend(candidates[MAX_SCAN_FILES:])
        candidates = candidates[:MAX_SCAN_FILES]
        logger.info("run_content_scan 截断到 %d 文件（原 %d 候选）", MAX_SCAN_FILES, len(file_paths))

    logger.info("run_content_scan 开始: %d 候选文件并发拉取", len(candidates))

    # 阶段1：并发拉取（最耗时的环节）
    if progress_cb and task_id:
        progress_cb(task_id, 40, f"开始拉取 {len(candidates)} 个文件内容...")
    tasks = [fetch_file_content(owner, repo, branch, p, provider) for p in candidates]
    contents = await asyncio.gather(*tasks, return_exceptions=True)
    # 拉取完成 → 40→70
    if progress_cb and task_id:
        progress_cb(task_id, 70, f"内容拉取完成，开始正则扫描...")

    # 阶段2：正则扫描
    hits: List[ContentHit] = []
    scanned = 0
    content_fetch_fail = 0

    for path, content in zip(candidates, contents):
        if isinstance(content, Exception):
            logger.warning("run_content_scan asyncio 异常: %s - %s", path, content)
            skipped.append(path)
            content_fetch_fail += 1
            continue
        if content is None:
            skipped.append(path)
            content_fetch_fail += 1
            continue
        scanned += 1
        found = scan_text_content(content)
        for hit_type, matched_texts in found:
            hits.append(ContentHit(
                file_path=path,
                hit_type=hit_type,
                matched_texts=matched_texts,
            ))

    if content_fetch_fail:
        logger.info("run_content_scan 拉取失败 %d / %d", content_fetch_fail, len(candidates))
    logger.info("run_content_scan 完成: scanned=%d hits=%d", scanned, len(hits))
    if progress_cb and task_id:
        progress_cb(task_id, 85, f"扫描完成：{scanned} 个有效文件，命中 {len(hits)} 条风险")

    return ContentScanResult(
        scanned_files=scanned,
        skipped_files=sorted(set(skipped)),
        hits=hits,
    )


# ---------- 新增：评分 + 风险分级 ----------
def _mask_secret(secret: str) -> str:
    """密钥脱敏：保留前4后4，中间用 ***"""
    if len(secret) <= 8:
        return "***"
    return f"{secret[:4]}***{secret[-4:]}"


def compute_score(
    readiness: ReadinessCheck,
    risk_brief: RiskBrief,
    content_scan: ContentScanResult,
) -> ScoreDetail:
    """
    扣分制评分：起始 100，逐项扣。
    扣分项全部记录在 deductions 列表，方便前端逐项展示。
    """
    deductions: List[dict] = []
    current = 100

    # 完备度扣分
    if not readiness.has_readme:
        points = SCORE_READINESS_PENALTY["no_readme"]
        deductions.append({"item": "仓库缺少 README", "points": points})
        current += points  # 负数，所以是减法
    if not readiness.found_dependency_files:
        points = SCORE_READINESS_PENALTY["no_dependency"]
        deductions.append({"item": "未发现依赖清单", "points": points})
        current += points

    # 风险扣分（文件名）—— Windows 脚本，有封顶
    win_count = len(risk_brief.windows_script_files)
    if win_count > 0:
        raw_penalty = SCORE_RISK_PENALTY["windows_script_per_file"] * win_count
        capped = max(SCORE_RISK_CAP["windows_script_max"], raw_penalty)
        deductions.append({
            "item": f"发现 {win_count} 个 Windows 危险脚本(.bat/.cmd/.ps1/.vbs)",
            "points": capped,
            "raw_points": raw_penalty,
        })
        current += capped

    # 风险扣分（内容）
    # 统计每种类型的命中文件数 / 命中次数
    hardcoded_files = set()
    secret_hits = 0
    for hit in content_scan.hits:
        if hit.hit_type == "hardcoded_path":
            hardcoded_files.add(hit.file_path)
        elif hit.hit_type == "secret_key":
            secret_hits += len(hit.matched_texts)

    if hardcoded_files:
        raw_penalty = SCORE_RISK_PENALTY["hardcoded_path_per_file"] * len(hardcoded_files)
        capped = max(SCORE_RISK_CAP["hardcoded_path_max"], raw_penalty)
        deductions.append({
            "item": f"{len(hardcoded_files)} 个文件含硬编码路径",
            "points": capped,
            "raw_points": raw_penalty,
        })
        current += capped

    if secret_hits:
        points = SCORE_RISK_PENALTY["secret_key_per_hit"] * secret_hits
        deductions.append({
            "item": f"发现 {secret_hits} 处疑似密钥泄露(sk-...)",
            "points": points,
        })
        current += points

    final = max(0, min(100, current))
    return ScoreDetail(base_score=100, deductions=deductions, final_score=final)


def build_risk_items(
    risk_brief: RiskBrief,
    content_scan: ContentScanResult,
) -> Tuple[List[RiskItem], str]:
    """
    合并文件名风险 + 内容风险 → 统一 RiskItem 列表，同时判定最高风险等级。
    返回 (风险清单, 风险等级)。
    """
    items: List[RiskItem] = []
    has_secret = False
    hardcoded_file_count = 0
    win_script_count = len(risk_brief.windows_script_files)

    # ---- Windows 脚本：MEDIUM 起步 ----
    for path in risk_brief.windows_script_files:
        items.append(RiskItem(
            level=RISK_MEDIUM,
            category="windows_script",
            file_path=path,
            detail=f"检测到 Windows 脚本文件：{os.path.basename(path)}",
        ))

    # ---- 内容命中：硬编码路径 + 密钥 ----
    for hit in content_scan.hits:
        if hit.hit_type == "hardcoded_path":
            hardcoded_file_count += 1
            for text in hit.matched_texts:
                items.append(RiskItem(
                    level=RISK_MEDIUM,
                    category="hardcoded_path",
                    file_path=hit.file_path,
                    detail=f"硬编码路径：{text}",
                ))
        elif hit.hit_type == "secret_key":
            has_secret = True
            for text in hit.matched_texts:
                items.append(RiskItem(
                    level=RISK_CRITICAL,
                    category="secret_key",
                    file_path=hit.file_path,
                    detail=f"疑似密钥泄露：{_mask_secret(text)}",
                ))

    # ---- 判定总体风险等级（最高严重度优先）----
    if has_secret:
        overall = RISK_CRITICAL
    elif win_script_count >= 3 or hardcoded_file_count >= 5:
        overall = RISK_HIGH
    elif win_script_count > 0 or hardcoded_file_count > 0:
        overall = RISK_MEDIUM
    else:
        overall = RISK_CLEAN

    # ---- 排序：CRITICAL 在前，然后 HIGH/MEDIUM/LOW ----
    level_order = {RISK_CRITICAL: 0, RISK_HIGH: 1, RISK_MEDIUM: 2, RISK_LOW: 3}
    items.sort(key=lambda x: level_order.get(x.level, 99))

    return items, overall


# ---------- AI 接入建议（DeepSeek，可选能力） ----------
def _build_ai_prompt(
    provider: str,
    owner: str,
    repo: str,
    default_branch: str,
    total_files: int,
    readiness: ReadinessCheck,
    risk: RiskBrief,
    content_scan: ContentScanResult,
    summary: ScanSummary,
) -> str:
    """把扫描结果压缩成结构化 prompt，交给 DeepSeek 生成接入建议"""
    # 内容命中按类型聚合，避免 prompt 过长
    hit_groups: Dict[str, List[str]] = {}
    for hit in content_scan.hits:
        hit_groups.setdefault(hit.hit_type, []).append(hit.file_path)

    hit_lines = []
    for hit_type, files in hit_groups.items():
        uniq_files = sorted(set(files))[:10]
        hit_lines.append(f"- {hit_type}: {len(files)} 处命中，涉及文件（最多10个）：{', '.join(uniq_files)}")
    if not hit_lines:
        hit_lines.append("- 无内容级风险命中")

    deduction_lines = [
        f"- {d.get('item')}：{d.get('points')} 分" for d in summary.score_detail.deductions
    ] or ["- 无扣分项"]

    return f"""你是一名代码仓库接入评审专家。请基于以下自动化扫描结果，给出简洁、可执行的接入建议。

## 仓库信息
- 平台：{_provider_label(provider)}
- 仓库：{owner}/{repo}
- 默认分支：{default_branch}
- 文件总数：{total_files}

## 完备度
- README：{"存在" if readiness.has_readme else "缺失"}
- 依赖清单：{", ".join(readiness.found_dependency_files) if readiness.found_dependency_files else "未发现"}

## 风险
- Windows 危险脚本（.bat/.cmd/.ps1/.vbs）：{len(risk.windows_script_files)} 个
- 内容扫描文件数：{content_scan.scanned_files}
- 风险命中：
{chr(10).join(hit_lines)}

## 评分
- 接入就绪度：{summary.score}/100
- 风险等级：{summary.risk_level}
- 扣分明细：
{chr(10).join(deduction_lines)}

## 输出要求
请用中文输出，严格分为三部分，每部分用「### 」标题：
### 接入结论
一句话结论 + 是否建议接入（建议接入 / 有条件接入 / 不建议接入）。
### 主要问题
按严重程度列出 2-5 条，每条一行，说明问题与影响。
### 接入建议
列出 2-5 条可执行动作，每条一行，具体到要做什么。
总字数控制在 400 字以内，不要输出与以上结构无关的内容。"""


async def generate_ai_advice(
    provider: str,
    owner: str,
    repo: str,
    default_branch: str,
    total_files: int,
    readiness: ReadinessCheck,
    risk: RiskBrief,
    content_scan: ContentScanResult,
    summary: ScanSummary,
) -> AiAdvice:
    """
    调用 DeepSeek 生成接入建议。
    密钥为空 → 返回 enabled=False 的禁用态，不抛异常。
    调用失败 → 返回带 error 的降级结果，不抛异常，不影响基础扫描。
    """
    if not AI_ENABLED:
        logger.info("未配置 DEEPSEEK_API_KEY，AI 建议模块自动禁用")
        return AiAdvice(
            enabled=False,
            model=None,
            message="未配置 DEEPSEEK_API_KEY，AI 建议模块已自动禁用；基础扫描功能不受影响。",
        )

    prompt = _build_ai_prompt(
        provider, owner, repo, default_branch, total_files,
        readiness, risk, content_scan, summary,
    )

    payload = {
        "model": DEEPSEEK_MODEL,
        "messages": [
            {"role": "system", "content": "你是严谨的代码仓库接入评审专家，只输出要求的结构化内容。"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.3,
        "max_tokens": AI_ADVICE_MAX_TOKENS,
        "stream": False,
    }

    client = await _get_shared_client()
    try:
        resp = await client.post(
            f"{DEEPSEEK_API_BASE}/chat/completions",
            headers={
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=DEEPSEEK_TIMEOUT,
        )
    except httpx.TimeoutException:
        logger.warning("DeepSeek 请求超时，降级返回")
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="AI 建议生成超时，本次仅返回基础扫描结果。",
                        error="timeout")
    except httpx.NetworkError as e:
        logger.warning("DeepSeek 网络错误: %s", e)
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="AI 服务连接失败，本次仅返回基础扫描结果。",
                        error=f"network: {e}")
    except Exception as e:
        logger.exception("DeepSeek 调用异常: %s", e)
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="AI 建议生成异常，本次仅返回基础扫描结果。",
                        error=f"{type(e).__name__}: {e}")

    if resp.status_code == 401:
        logger.warning("DeepSeek API Key 无效")
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="DEEPSEEK_API_KEY 无效，AI 建议已降级跳过。",
                        error="401 invalid api key")
    if resp.status_code != 200:
        logger.warning("DeepSeek 返回异常状态: %s %s", resp.status_code, resp.text[:200])
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="AI 服务返回异常，本次仅返回基础扫描结果。",
                        error=f"{resp.status_code}: {resp.text[:200]}")

    try:
        data = resp.json()
        content = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, ValueError, AttributeError) as e:
        logger.warning("DeepSeek 响应解析失败: %s", e)
        return AiAdvice(enabled=True, model=DEEPSEEK_MODEL,
                        message="AI 建议解析失败，本次仅返回基础扫描结果。",
                        error=f"parse: {e}")

    logger.info("DeepSeek 接入建议生成成功，长度 %d", len(content))
    return AiAdvice(
        enabled=True,
        model=DEEPSEEK_MODEL,
        content=content,
        message="AI 建议生成成功",
    )


# ========== 4.5 异步任务模块（扫描进度轮询） ==========
class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    EXPIRED = "expired"


class TaskInfo(BaseModel):
    """任务状态 / 进度 / 结果"""
    task_id: str
    repo_url: str
    status: TaskStatus
    progress: int = Field(ge=0, le=100)        # 0-100
    progress_text: str = ""                     # 阶段描述
    created_at: float                           # time.time()
    updated_at: float
    result: Optional[ScanResponse] = None
    error: Optional[str] = None


# 内存中的任务存储（进程级，重启丢失；生产环境可换 Redis）
# key=task_id, value=TaskInfo
_tasks: Dict[str, TaskInfo] = {}

# 任务超时：完成 / 失败后保留 10 分钟供前端轮询，之后标记 EXPIRED
_TASK_TTL_AFTER_DONE = 600


def _new_task_id() -> str:
    """生成短 task_id：uuid4 前 12 字符"""
    return uuid.uuid4().hex[:12]


def _expire_old_tasks():
    """清理已完成但过期的任务（避免内存泄漏）"""
    now = time.time()
    expired_ids = [
        tid for tid, t in _tasks.items()
        if t.status in (TaskStatus.SUCCESS, TaskStatus.FAILED)
        and now - t.updated_at > _TASK_TTL_AFTER_DONE
    ]
    for tid in expired_ids:
        _tasks[tid] = _tasks[tid].model_copy(update={"status": TaskStatus.EXPIRED})


def _update_progress(task_id: str, progress: int, text: str):
    """进度回写（被 _do_scan 各阶段调用）"""
    if task_id not in _tasks:
        return
    t = _tasks[task_id]
    # 单调递增：只允许 progress 变大
    t.progress = min(100, max(t.progress, progress))
    t.progress_text = text
    t.updated_at = time.time()


async def _do_scan(task_id: str, repo_url: str) -> ScanResponse:
    """
    核心扫描逻辑（和原 scan_repo 完全一致），带进度回写。
    不直接抛异常，内部捕获后通过 TaskInfo.error 回写。
    """
    # 步骤1：解析链接（GitHub / Gitee）
    provider, owner, repo = parse_repo_url(repo_url)
    scan_start_log = f"{_provider_label(provider)}:{owner}/{repo}"
    logger.info("[task=%s] 开始扫描: %s", task_id, scan_start_log)
    _update_progress(task_id, 5, f"解析仓库链接（{_provider_label(provider)}）...")

    # 步骤2：拉仓库元信息
    repo_meta = await fetch_repo_info(owner, repo, provider)
    default_branch = repo_meta["default_branch"]
    _update_progress(task_id, 15, f"获取仓库信息完成，分支 {default_branch}")

    # 步骤3：拉文件树
    file_paths = await fetch_file_tree(owner, repo, default_branch, provider)
    _update_progress(task_id, 25, f"获取文件树完成，共 {len(file_paths)} 个文件")

    # 步骤4：文件级检测
    readiness = run_readiness_check(file_paths)
    risk = run_risk_check(file_paths)
    logger.info("[task=%s] 文件级检测完成: README=%s deps=%s win_scripts=%d",
                task_id, readiness.has_readme, readiness.found_dependency_files,
                len(risk.windows_script_files))
    _update_progress(task_id, 35, f"文件级检测完成")

    # 步骤4.5：内容扫描
    content_scan = await run_content_scan(
        owner, repo, default_branch, file_paths,
        task_id=task_id, progress_cb=_update_progress, provider=provider,
    )
    _update_progress(task_id, 85, f"内容扫描完成，命中 {len(content_scan.hits)} 条")

    # 步骤4.6：评分 + 分级
    score_detail = compute_score(readiness, risk, content_scan)
    risk_items, risk_level = build_risk_items(risk, content_scan)
    summary = ScanSummary(
        score=score_detail.final_score,
        score_detail=score_detail,
        risk_level=risk_level,
        risk_items=risk_items,
    )
    _update_progress(task_id, 92, "生成评分与风险报告...")
    logger.info("[task=%s] 扫描完成: %s score=%d risk=%s hits=%d",
                task_id, scan_start_log, summary.score, summary.risk_level, len(content_scan.hits))

    # 步骤4.7：AI 接入建议（可选，密钥为空自动禁用，失败不影响主流程）
    ai_advice: AiAdvice
    if AI_ENABLED:
        _update_progress(task_id, 95, "正在生成 AI 接入建议...")
    ai_advice = await generate_ai_advice(
        provider, owner, repo, default_branch, len(file_paths),
        readiness, risk, content_scan, summary,
    )
    _update_progress(task_id, 99, "AI 建议处理完成")

    return ScanResponse(
        repo_info=RepoInfo(
            owner=owner, repo=repo, default_branch=default_branch,
            total_files=len(file_paths), provider=provider,
        ),
        readiness=readiness,
        risk_brief=risk,
        content_scan=content_scan,
        summary=summary,
        ai_advice=ai_advice,
    )


async def _run_task_worker(task_id: str, repo_url: str):
    """asyncio 后台任务：执行 _do_scan，捕获异常并回写结果"""
    _expire_old_tasks()
    try:
        result = await _do_scan(task_id, repo_url)
        if task_id in _tasks:
            t = _tasks[task_id]
            t.status = TaskStatus.SUCCESS
            t.progress = 100
            t.progress_text = "扫描完成"
            t.result = result
            t.updated_at = time.time()
    except Exception as e:
        tb = traceback.format_exc()
        logger.error("[task=%s] 扫描失败:\n%s", task_id, tb)
        if task_id in _tasks:
            t = _tasks[task_id]
            t.status = TaskStatus.FAILED
            t.progress_text = "扫描失败"
            # 友好错误消息（去掉 traceback）
            if isinstance(e, HTTPException):
                t.error = e.detail
            else:
                t.error = f"{type(e).__name__}: {e}"
            t.updated_at = time.time()


# ========== 5. FastAPI 应用 ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用启动/关闭时管理共享 HTTP client"""
    logger.info("Git 仓库体检工具 v0.1 启动")
    global _shared_client
    _shared_client = httpx.AsyncClient(timeout=15.0, follow_redirects=True)
    try:
        yield
    finally:
        if _shared_client and not _shared_client.is_closed:
            await _shared_client.aclose()
            logger.info("共享 HTTP client 已关闭")
        logger.info("Git 仓库体检工具关闭")


app = FastAPI(
    title="Git仓库接入体检工具",
    description="输入公开 GitHub 仓库链接，自动检测仓库完备度与风险",
    version="0.1.0",
    lifespan=lifespan,
)

# ---------- CORS 跨域（开发/生产双保险）----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server
        "http://127.0.0.1:5173",
        "http://localhost:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- 全局异常处理器：统一错误返回格式 ----------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """捕获所有 HTTPException → 统一 ErrorResponse 格式"""
    logger.warning("HTTPException [%d]: %s", exc.status_code, exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            code=exc.status_code,
            message=str(exc.detail),
        ).model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """捕获 Pydantic 校验失败（422）→ 统一格式"""
    errors = exc.errors()
    msg = "请求参数校验失败"
    if errors:
        loc = ".".join(str(e) for e in errors[0].get("loc", []))
        msg += f"：{loc} - {errors[0].get('msg', '')}"
    logger.warning("RequestValidationError: %s", msg)
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(code=422, message=msg, detail=str(errors)).model_dump(),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """兜底：捕获所有未预期异常 → 统一 500"""
    logger.exception("未预期异常: %s", exc)
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            code=500,
            message="服务器内部错误，请稍后重试",
            detail=f"{type(exc).__name__}: {exc}",
        ).model_dump(),
    )


@app.post("/api/scan", response_model=TaskInfo, summary="启动异步仓库扫描任务")
async def create_scan_task(req: ScanRequest):
    """
    启动一个异步扫描任务，立即返回 task_id。
    前端通过 GET /api/tasks/{task_id} 轮询进度和结果。
    链接解析失败等已知错误会同步返回 400/422，不创建无效任务。
    """
    # 同步校验：在启动任务之前先过 Pydantic validator + 链接解析
    # （Pydantic validator 已经在 ScanRequest 上做了 github.com 域名校验，
    #  这里再做 parse_github_url 验证路径格式）
    try:
        parse_repo_url(req.repo_url)
    except ValueError as e:
        logger.warning("链接解析失败: %s - %s", req.repo_url, e)
        raise HTTPException(status_code=400, detail=str(e))

    # 创建任务记录（初始状态 running）
    task_id = _new_task_id()
    now = time.time()
    _tasks[task_id] = TaskInfo(
        task_id=task_id,
        repo_url=req.repo_url,
        status=TaskStatus.RUNNING,
        progress=0,
        progress_text="准备中...",
        created_at=now,
        updated_at=now,
    )

    # 后台异步执行（fire-and-forget，立即返回）
    asyncio.create_task(_run_task_worker(task_id, req.repo_url))

    logger.info("创建扫描任务: task_id=%s url=%s", task_id, req.repo_url)
    return _tasks[task_id]


@app.get("/api/tasks/{task_id}", response_model=TaskInfo, summary="查询扫描任务状态")
async def get_task_status(task_id: str):
    """
    轮询任务状态：返回 progress / progress_text / status / result / error。
    终态（success / failed）会保留 10 分钟供前端轮询，之后标记 expired。
    """
    _expire_old_tasks()
    task = _tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"任务不存在或已过期：{task_id}")
    return task


@app.get("/health", summary="健康检查")
async def health():
    """健康检查：返回 token 配置状态和服务版本"""
    return {
        "status": "ok",
        "version": "0.2.0",
        "github_token_configured": bool(GITHUB_TOKEN),
        "github_token_masked": (GITHUB_TOKEN[:4] + "****") if GITHUB_TOKEN else None,
        "gitee_token_configured": bool(GITEE_TOKEN),
        "ai_advice_enabled": AI_ENABLED,
        "supported_providers": list(PROVIDER_API_BASE.keys()),
    }
