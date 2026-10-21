"""Lab-control helpers: run artisan inside the app container, reseed, and seed
bulk rows. Used by exploits that need authenticated accounts restored or a large
backing table.

The lab runs as compose project ``cvehunterlab_filament`` with the app container
``cvehunterlab_filament_app`` (see the manifest). We talk to it with
``docker exec`` from the app's working directory (the Laravel project root).
"""

from __future__ import annotations

import subprocess

APP_CONTAINER = "cvehunterlab_filament_app"


def exec_app(args: list[str], check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    """Run a command inside the app container and return the completed process."""
    cmd = ["docker", "exec", APP_CONTAINER] + args
    return subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)


def artisan(args: list[str], check: bool = True, timeout: int = 300) -> str:
    """Run ``php artisan <args>`` in the container; return stdout."""
    cp = exec_app(["php", "artisan"] + args, check=check, timeout=timeout)
    return cp.stdout + cp.stderr


def reseed(timeout: int = 300) -> str:
    """Restore the seeded accounts after a destructive demo route truncated them.

    The unauth demo table pages truncate + raw-insert plaintext users on mount,
    which breaks admin login. A fresh ``migrate:fresh --seed`` restores the
    documented accounts (``ryan@filamentphp.com`` etc.).
    """
    return artisan(["migrate:fresh", "--seed", "--force"], timeout=timeout)


def tinker(php: str, timeout: int = 180) -> str:
    """Execute a snippet of PHP via ``artisan tinker --execute``."""
    cp = exec_app(["php", "artisan", "tinker", "--execute", php], check=False, timeout=timeout)
    return cp.stdout + cp.stderr


def put_public_file(path: str, content: str) -> None:
    """Write a file onto the app's **public** disk (storage/app/public/<path>).

    Used to stand up a 'victim's' object on a shared disk as a precondition.
    """
    import shlex
    full = f"storage/app/public/{path}"
    dir_ = "/".join(full.split("/")[:-1])
    exec_app(["sh", "-c", f"mkdir -p {shlex.quote(dir_)}"])
    # write content via a heredoc-free base64 round-trip to avoid quoting issues
    import base64
    b64 = base64.b64encode(content.encode()).decode()
    exec_app(["sh", "-c", f"echo {shlex.quote(b64)} | base64 -d > {shlex.quote(full)}"])


def remove_public_file(path: str) -> None:
    import shlex
    full = f"storage/app/public/{path}"
    exec_app(["sh", "-c", f"rm -f {shlex.quote(full)}"], check=False)


def post_count() -> int:
    out = tinker('echo \\App\\Models\\Post::count();')
    import re
    m = re.search(r"(\d+)", out)
    return int(m.group(1)) if m else -1


def seed_posts(n: int, suffix: str, author_id: int = 1) -> int:
    """Bulk-insert ``n`` posts via a single Postgres ``generate_series`` INSERT
    (orders of magnitude faster than the model factory). Returns the new count.

    status/rating/author_id use values observed in the seeded data
    (status enum: draft|published|reviewing; author ids 1..6).
    """
    sql = (
        "DB::statement(\"INSERT INTO posts "
        "(author_id, is_featured, slug, status, description, title, rating, created_at, updated_at) "
        f"SELECT {author_id}, false, 'seed-{suffix}-'||gs, 'draft', 'dos filler', 'Post '||gs, 1, now(), now() "
        f"FROM generate_series(1, {int(n)}) gs\");"
    )
    tinker(sql, timeout=300)
    return post_count()


POSTRESOURCE = "/opt/filament-src/docs-assets/app/app/Filament/Resources/PostResource.php"
_PR_ANCHOR = "->relationship('author', 'name')"


def patch_postresource_option_forms() -> bool:
    """Add ->editOptionForm([...])->createOptionForm([...]) to the EXISTING relationship
    Select on PostResource (the documented pattern VULN-001/003 describe). Harness only:
    it enables opt-in library features on a relationship Select; no library code changes.
    Returns True on success. Reverted with revert_postresource()."""
    import base64
    orig = exec_app(["cat", POSTRESOURCE]).stdout
    if _PR_ANCHOR not in orig:
        return False
    inject = (_PR_ANCHOR +
              "->editOptionForm([Forms\\Components\\TextInput::make('name'), "
              "Forms\\Components\\TextInput::make('email')])"
              "->createOptionForm([Forms\\Components\\TextInput::make('name'), "
              "Forms\\Components\\TextInput::make('email'), "
              "Forms\\Components\\TextInput::make('password')])")
    mod = orig.replace(_PR_ANCHOR, inject, 1)
    b64 = base64.b64encode(mod.encode()).decode()
    exec_app(["sh", "-c", f"cp {POSTRESOURCE} {POSTRESOURCE}.bak && "
                          f"echo {b64} | base64 -d > {POSTRESOURCE} && touch {POSTRESOURCE}"])
    return True


def patch_posts_title_url_column() -> bool:
    """Add ->url(fn ($state) => $state) to the posts table 'title' column — the report's
    canonical TextColumn::make(...)->url(fn ($record) => ...) pattern that routes a
    user-controlled value through generate_href_html(). Harness only; reverted with
    revert_postresource(). Returns True on success."""
    import base64, re
    orig = exec_app(["cat", POSTRESOURCE]).stdout
    pat = r"(TextColumn::make\('title'\)\s*->searchable\(\)\s*->sortable\(\))"
    if not re.search(pat, orig):
        return False
    mod = re.sub(pat, r"\1->url(fn (string $state): string => $state)", orig, count=1)
    b64 = base64.b64encode(mod.encode()).decode()
    exec_app(["sh", "-c", f"cp {POSTRESOURCE} {POSTRESOURCE}.bak && "
                          f"echo {b64} | base64 -d > {POSTRESOURCE} && touch {POSTRESOURCE}"])
    return True


def revert_postresource() -> None:
    # touch after restoring so opcache (validate_timestamps) reloads the older-mtime original.
    exec_app(["sh", "-c",
              f"[ -f {POSTRESOURCE}.bak ] && mv {POSTRESOURCE}.bak {POSTRESOURCE} "
              f"&& touch {POSTRESOURCE} || true"], check=False)


def restart(timeout: int = 120) -> None:
    """Restart the stack to a clean state before a destructive test."""
    import subprocess
    subprocess.run(
        ["docker", "compose", "-p", "cvehunterlab_filament", "restart"],
        cwd="/opt/cvehunter/targets/filament/_cvehunter_lab",
        capture_output=True, text=True, timeout=timeout, check=False,
    )
