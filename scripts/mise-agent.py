#!/usr/bin/env python3
"""mise のタスクを Unix domain socket 越しに実行する小さなエージェント。

サーバ:
    ./scripts/mise-agent.py serve
    ./scripts/mise-agent.py serve --allow build --allow 'lab:*' --allow-args

クライアント:
    ./scripts/mise-agent.py run build
    ./scripts/mise-agent.py list
    ./scripts/mise-agent.py cancel <job-id>

プロトコル (JSON Lines, UTF-8):
    要求 : {"op": "run", "task": "build", "args": [], "env": {}}
           {"op": "list"} / {"op": "ping"} / {"op": "cancel", "job": "..."}
    応答 : {"type": "accepted", "job": "..."}
           {"type": "stdout"|"stderr", "data": "..."}
           {"type": "exit", "code": 0, "duration": 1.23}
           {"type": "error", "message": "..."}

権限:
  * ソケットファイルのパーミッション (既定 0600) と所有者 (--owner)
  * SO_PEERCRED による接続元 uid の検証 (既定は起動ユーザ自身のみ)
  * タスク許可リスト (glob)。既定は mise.toml に定義された全タスク
  * 追加引数と環境変数は既定で拒否 (--allow-args / --allow-env で解禁)

root で常駐する場合 (sudo が要る lab タスク向け):
    sudo ./scripts/mise-agent.py serve \\
        --owner saffron --uid saffron --run-as saffron --root-task 'lab:*'

  --root-task に一致したタスクだけが root のまま走り (sudo.sh は id -u が 0 なら
  そのまま exec するので sudo 自体が不要)、それ以外は --run-as のユーザへ降格する。
  降格しないと target/ や ~/.cargo が root 所有になってしまう。
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import pwd
import selectors
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

DEFAULT_SOCKET = os.environ.get(
    "MISE_AGENT_SOCKET",
    os.path.join(
        os.environ.get("XDG_RUNTIME_DIR") or "/tmp", "mise-agent.sock"
    ),
)

# ---------------------------------------------------------------- 共通ユーティリティ


def log(msg: str) -> None:
    print(f"[mise-agent] {msg}", file=sys.stderr, flush=True)


def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode())


def peer_credentials(sock: socket.socket) -> tuple[int, int, int]:
    """SO_PEERCRED から (pid, uid, gid) を取り出す。"""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", raw)


def resolve_mise(explicit: str | None, run_as: pwd.struct_passwd | None) -> str:
    """mise の実体を絶対パスで確定する。

    mise はユーザローカル (~/.local/bin) に入っていることが多く、root で常駐すると
    PATH から消える。--run-as のホームまで含めて探し、見つからなければ即座に失敗する。
    """
    if explicit:
        path = os.path.abspath(explicit)
        if not os.access(path, os.X_OK):
            raise SystemExit(f"mise が実行できません: {path}")
        return path
    found = shutil.which("mise")
    if found:
        return found
    for home in filter(None, [run_as.pw_dir if run_as else None, os.path.expanduser("~")]):
        candidate = os.path.join(home, ".local", "bin", "mise")
        if os.access(candidate, os.X_OK):
            return candidate
    raise SystemExit("mise が見つかりません。--mise でパスを指定してください")


def mise_tasks(mise: str, project_dir: str) -> list[str]:
    """mise.toml に定義されたタスク名を列挙する。"""
    try:
        out = subprocess.run(
            [mise, "tasks", "ls", "--json"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
        return sorted(entry["name"] for entry in json.loads(out))
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError) as exc:
        log(f"タスク一覧の取得に失敗: {exc}")
        return []


# ---------------------------------------------------------------- サーバ


class Agent:
    def __init__(self, args: argparse.Namespace) -> None:
        self.project_dir = os.path.abspath(args.project_dir)
        # root で常駐すると mise.toml の trust 記録 (~/.local/state/mise) が別ユーザの
        # ものになり、非対話では信頼されない。運用者が指定した project-dir なので
        # 明示的に信頼させる。
        trusted = [p for p in os.environ.get("MISE_TRUSTED_CONFIG_PATHS", "").split(":") if p]
        if self.project_dir not in trusted:
            trusted.append(self.project_dir)
        os.environ["MISE_TRUSTED_CONFIG_PATHS"] = ":".join(trusted)
        self.allow = args.allow
        self.deny = args.deny
        self.allow_args = args.allow_args
        self.allow_env = args.allow_env
        self.timeout = args.timeout
        self.askpass = os.path.abspath(args.askpass) if args.askpass else None
        self.max_jobs = args.max_jobs
        self.root_tasks = args.root_task
        self.run_as = pwd.getpwnam(args.run_as) if args.run_as else None
        self.socket_owner = self._resolve_owner(args.owner)
        self.uids = self._resolve_uids(args.uid)
        self.mise = resolve_mise(args.mise, self.run_as)
        self.tasks = mise_tasks(self.mise, self.project_dir)
        self._jobs: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _resolve_uids(specs: list[str]) -> set[int]:
        if not specs:
            return {os.getuid()}
        uids: set[int] = set()
        for spec in specs:
            if spec == "any":
                return set()  # 空集合 = 検証しない
            try:
                uids.add(int(spec))
            except ValueError:
                uids.add(pwd.getpwnam(spec).pw_uid)
        return uids

    @staticmethod
    def _resolve_owner(spec: str | None) -> tuple[int, int] | None:
        if not spec:
            return None
        user, _, group = spec.partition(":")
        entry = pwd.getpwnam(user)
        if not group:
            return entry.pw_uid, entry.pw_gid
        try:
            gid = int(group)
        except ValueError:
            import grp

            gid = grp.getgrnam(group).gr_gid
        return entry.pw_uid, gid

    # -------------------------------------------------------- 認可

    def task_allowed(self, task: str) -> tuple[bool, str]:
        if not task or task.startswith("-") or "\x00" in task:
            return False, f"不正なタスク名です: {task!r}"
        if any(fnmatch.fnmatch(task, pat) for pat in self.deny):
            return False, f"タスク {task!r} は拒否リストに含まれています"
        if self.allow:
            if not any(fnmatch.fnmatch(task, pat) for pat in self.allow):
                return False, f"タスク {task!r} は許可リストにありません"
        elif self.tasks and task not in self.tasks:
            return False, f"タスク {task!r} は mise.toml に定義されていません"
        return True, ""

    def uid_allowed(self, uid: int) -> bool:
        return not self.uids or uid in self.uids

    # -------------------------------------------------------- 特権

    def needs_root(self, task: str) -> bool:
        return any(fnmatch.fnmatch(task, pat) for pat in self.root_tasks)

    @staticmethod
    def _demote(user: pwd.struct_passwd):
        """タスクを起動する子プロセス側で uid/gid を落とす preexec_fn を返す。"""

        def preexec() -> None:
            os.initgroups(user.pw_name, user.pw_gid)
            os.setgid(user.pw_gid)
            os.setuid(user.pw_uid)  # setuid は最後。先に落とすと gid を変えられない

        return preexec

    # -------------------------------------------------------- 実行

    def run_task(self, conn: socket.socket, req: dict, peer: tuple[int, int, int]) -> None:
        task = req.get("task")
        if not isinstance(task, str):
            send_json(conn, {"type": "error", "message": "task が指定されていません"})
            return

        ok, why = self.task_allowed(task)
        if not ok:
            send_json(conn, {"type": "error", "message": why})
            return

        extra = req.get("args") or []
        if extra and not self.allow_args:
            send_json(conn, {"type": "error", "message": "追加引数は許可されていません (--allow-args)"})
            return
        if not all(isinstance(a, str) for a in extra):
            send_json(conn, {"type": "error", "message": "args は文字列の配列である必要があります"})
            return

        req_env = req.get("env") or {}
        if req_env and not self.allow_env:
            send_json(conn, {"type": "error", "message": "環境変数の指定は許可されていません (--allow-env)"})
            return

        with self._lock:
            if len(self._jobs) >= self.max_jobs:
                send_json(conn, {"type": "error", "message": "同時実行数の上限に達しています"})
                return

        env = dict(os.environ)
        for k, v in req_env.items():
            if isinstance(k, str) and isinstance(v, str) and k.isidentifier():
                env[k] = v
        env["MISE_AGENT"] = "1"
        if self.askpass:
            # エージェント配下のタスクは制御端末を持たないので、sudo は
            # scripts/lab/sudo.sh 経由で askpass ヘルパを使う。
            env["SUDO_ASKPASS"] = self.askpass
        else:
            env.pop("SUDO_ASKPASS", None)
        env["MISE_AGENT_PEER_UID"] = str(peer[1])

        # root で常駐している場合、root を要求しないタスクは --run-as のユーザへ
        # 降格する。そうしないと target/ や ~/.cargo が root 所有になってしまう。
        demote = None
        if os.getuid() == 0 and self.run_as and not self.needs_root(task):
            demote = self.run_as
            env.update(
                HOME=demote.pw_dir,
                USER=demote.pw_name,
                LOGNAME=demote.pw_name,
                SHELL=demote.pw_shell,
            )
            env.pop("XDG_RUNTIME_DIR", None)

        job = uuid.uuid4().hex[:12]
        cmd = [self.mise, "run", task, *extra]
        as_who = demote.pw_name if demote else pwd.getpwuid(os.getuid()).pw_name
        log(f"job={job} peer_uid={peer[1]} pid={peer[0]} as={as_who} cmd={cmd}")
        send_json(
            conn,
            {"type": "accepted", "job": job, "task": task, "cmd": cmd, "user": as_who},
        )

        started = time.monotonic()
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=self.project_dir,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,  # cancel でプロセスグループごと止められるように
                preexec_fn=self._demote(demote) if demote else None,
            )
        except OSError as exc:
            send_json(conn, {"type": "error", "message": f"起動に失敗しました: {exc}"})
            return

        with self._lock:
            self._jobs[job] = proc

        try:
            self._pump(conn, proc)
        finally:
            with self._lock:
                self._jobs.pop(job, None)

        send_json(
            conn,
            {
                "type": "exit",
                "job": job,
                "code": proc.returncode,
                "duration": round(time.monotonic() - started, 3),
            },
        )

    def _pump(self, conn: socket.socket, proc: subprocess.Popen) -> None:
        """子プロセスの stdout/stderr をそのままクライアントへ中継する。"""
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ, "stdout")
        sel.register(proc.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + self.timeout if self.timeout else None
        open_streams = 2

        while open_streams:
            wait = None
            if deadline:
                wait = deadline - time.monotonic()
                if wait <= 0:
                    send_json(conn, {"type": "error", "message": f"タイムアウト ({self.timeout}s)"})
                    self._terminate(proc)
                    break
            for key, _ in sel.select(timeout=wait):
                chunk = key.fileobj.read1(65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_streams -= 1
                    continue
                try:
                    send_json(conn, {"type": key.data, "data": chunk.decode(errors="replace")})
                except OSError:
                    # クライアントが切断したらタスクも巻き取る
                    self._terminate(proc)
                    return

        sel.close()
        proc.wait()

    @staticmethod
    def _terminate(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def cancel(self, conn: socket.socket, req: dict) -> None:
        job = req.get("job")
        with self._lock:
            proc = self._jobs.get(job)
        if proc is None:
            send_json(conn, {"type": "error", "message": f"ジョブが見つかりません: {job}"})
            return
        self._terminate(proc)
        send_json(conn, {"type": "cancelled", "job": job})

    # -------------------------------------------------------- 接続処理

    def handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                peer = peer_credentials(conn)
            except OSError as exc:
                log(f"peer credentials の取得に失敗: {exc}")
                return
            if not self.uid_allowed(peer[1]):
                log(f"uid={peer[1]} からの接続を拒否しました")
                try:
                    send_json(conn, {"type": "error", "message": "権限がありません"})
                except OSError:
                    pass
                return

            buf = b""
            while True:
                try:
                    data = conn.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                buf += data
                if len(buf) > 1 << 20:
                    send_json(conn, {"type": "error", "message": "要求が大きすぎます"})
                    return
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    try:
                        req = json.loads(line)
                    except json.JSONDecodeError as exc:
                        send_json(conn, {"type": "error", "message": f"JSON として解釈できません: {exc}"})
                        continue
                    try:
                        self.dispatch(conn, req, peer)
                    except OSError:
                        return

    def dispatch(self, conn: socket.socket, req: dict, peer: tuple[int, int, int]) -> None:
        op = req.get("op", "run")
        if op == "ping":
            send_json(conn, {"type": "pong", "pid": os.getpid()})
        elif op == "list":
            visible = [t for t in self.tasks if self.task_allowed(t)[0]]
            with self._lock:
                running = list(self._jobs)
            send_json(conn, {"type": "tasks", "tasks": visible, "running": running})
        elif op == "run":
            self.run_task(conn, req, peer)
        elif op == "cancel":
            self.cancel(conn, req)
        else:
            send_json(conn, {"type": "error", "message": f"未知の op: {op!r}"})

    # -------------------------------------------------------- メインループ

    def serve(self, path: str, mode: int) -> None:
        if os.path.exists(path):
            # 生きているソケットは上書きしない
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(path)
                probe.close()
                raise SystemExit(f"既にエージェントが {path} で待ち受けています")
            except (ConnectionRefusedError, FileNotFoundError):
                os.unlink(path)
            finally:
                probe.close()

        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old_umask = os.umask(0o777)
        try:
            srv.bind(path)
        finally:
            os.umask(old_umask)
        os.chmod(path, mode)
        if self.socket_owner:
            # root が作ったソケットは root 所有のままなので、繋ぐ相手に渡しておく。
            os.chown(path, *self.socket_owner)
        srv.listen(16)

        log(f"listening on {path} (mode {mode:04o})")
        log(f"project={self.project_dir}")
        log(f"askpass={self.askpass or '(なし)'}")
        log(f"agent uid={os.getuid()} "
            f"run-as={self.run_as.pw_name if self.run_as else '(降格しない)'} "
            f"root-tasks={self.root_tasks or '(なし)'}")
        log(f"uids={sorted(self.uids) or 'any'} tasks={len(self.tasks)} "
            f"allow={self.allow or '(mise.toml 全タスク)'} deny={self.deny or '(なし)'}")

        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: (stop.set(), srv.close()))

        try:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except OSError:
                    break
                threading.Thread(target=self.handle, args=(conn,), daemon=True).start()
        finally:
            srv.close()
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            log("stopped")


# ---------------------------------------------------------------- クライアント


def client(path: str, request: dict, quiet: bool) -> int:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as exc:
        print(f"接続できません ({path}): {exc}", file=sys.stderr)
        return 111

    with sock:
        send_json(sock, request)
        buf = b""
        exit_code = 0
        while True:
            data = sock.recv(65536)
            if not data:
                break
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                msg = json.loads(line)
                kind = msg.get("type")
                if kind == "stdout":
                    sys.stdout.write(msg["data"])
                    sys.stdout.flush()
                elif kind == "stderr":
                    sys.stderr.write(msg["data"])
                    sys.stderr.flush()
                elif kind == "accepted":
                    if not quiet:
                        print(f"[job {msg['job']}] {' '.join(msg['cmd'])}", file=sys.stderr)
                elif kind == "exit":
                    if not quiet:
                        print(f"[job {msg['job']}] exit={msg['code']} {msg['duration']}s", file=sys.stderr)
                    return msg["code"] or 0
                elif kind == "tasks":
                    for t in msg["tasks"]:
                        print(t)
                    if msg["running"]:
                        print(f"実行中: {', '.join(msg['running'])}", file=sys.stderr)
                    return 0
                elif kind == "pong":
                    print(f"pong (pid={msg['pid']})")
                    return 0
                elif kind == "cancelled":
                    print(f"cancelled: {msg['job']}")
                    return 0
                elif kind == "error":
                    print(f"エラー: {msg['message']}", file=sys.stderr)
                    return 1
        return exit_code


# ---------------------------------------------------------------- CLI


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--socket", default=DEFAULT_SOCKET, help=f"ソケットのパス (既定: {DEFAULT_SOCKET})")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="エージェントを起動する")
    s.add_argument("--project-dir", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    s.add_argument("--allow", action="append", default=[], metavar="GLOB",
                   help="許可するタスク名 (glob 可)。未指定なら mise.toml の全タスク")
    s.add_argument("--deny", action="append", default=[], metavar="GLOB", help="拒否するタスク名 (glob 可)")
    s.add_argument("--uid", action="append", default=[], metavar="UID|NAME|any",
                   help="接続を許可する uid (既定: 起動ユーザのみ)")
    s.add_argument("--mode", default="0600", help="ソケットのパーミッション (既定: 0600)")
    s.add_argument("--allow-args", action="store_true", help="タスクへの追加引数を許可する")
    s.add_argument("--allow-env", action="store_true", help="要求側からの環境変数指定を許可する")
    s.add_argument("--mise", metavar="PATH",
                   help="mise の実体。既定は PATH、次に --run-as ユーザの ~/.local/bin")
    s.add_argument("--run-as", metavar="USER",
                   help="root で常駐しているとき、root を要さないタスクをこのユーザで実行する")
    s.add_argument("--root-task", action="append", default=[], metavar="GLOB",
                   help="root のまま実行するタスク (glob 可)。例: 'lab:*'")
    s.add_argument("--owner", metavar="USER[:GROUP]",
                   help="ソケットの所有者。root 起動時に接続元ユーザを指定する")
    s.add_argument("--askpass", metavar="PATH",
                   help="sudo 用 askpass ヘルパ。タスクに SUDO_ASKPASS として渡す "
                        "(制御端末がないので sudo -A の経路が必要)")
    s.add_argument("--timeout", type=float, default=1800.0, help="1 タスクの上限秒数 (0 で無制限)")
    s.add_argument("--max-jobs", type=int, default=4, help="同時実行数の上限")

    r = sub.add_parser("run", help="タスクを実行する")
    r.add_argument("task")
    r.add_argument("args", nargs="*")
    r.add_argument("--env", action="append", default=[], metavar="K=V")
    r.add_argument("-q", "--quiet", action="store_true")

    sub.add_parser("list", help="実行できるタスクを列挙する")
    sub.add_parser("ping", help="疎通確認")
    c = sub.add_parser("cancel", help="実行中のジョブを止める")
    c.add_argument("job")

    a = p.parse_args()

    if a.cmd == "serve":
        Agent(a).serve(a.socket, int(a.mode, 8))
        return 0
    if a.cmd == "run":
        env = dict(kv.split("=", 1) for kv in a.env if "=" in kv)
        return client(a.socket, {"op": "run", "task": a.task, "args": a.args, "env": env}, a.quiet)
    if a.cmd == "cancel":
        return client(a.socket, {"op": "cancel", "job": a.job}, False)
    return client(a.socket, {"op": a.cmd}, False)


if __name__ == "__main__":
    sys.exit(main())
