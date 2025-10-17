#!/usr/bin/env python3
import argparse
import csv
import os
import sys
import time
import socket
import paramiko
import configparser
import logging
from typing import Tuple, Optional

from parso.python.tree import Literal


def load_hosts(csv_path: str):
    hosts = []
    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        rows = list(reader)
        if not rows:
            return hosts
        # wykryj nagłówki
        header_like = [c.strip().lower() for c in rows[0]]
        start_idx = 1 if set(header_like) >= {"ip", "username", "password"} else 0
        for row in rows[start_idx:]:
            if not row or len(row) < 3:
                continue
            ip, user, pwd = row[0].strip(), row[1].strip(), row[2].strip()
            if ip and user:
                hosts.append((ip, user, pwd))
    return hosts


def parse_args():
    ap = argparse.ArgumentParser(
        description="Ogranicz logowanie SSH na zdalnych hostach wyłącznie do konta root."
    )
    # ap.add_argument("-f", "--file", required=True, help="Ścieżka do pliku CSV: ip,username,password")
    ap.add_argument("-d", "--destination", help="Destination IP")
    ap.add_argument("-c", "--command", help="Raw command")
    ap.add_argument("-u", "--user", help="User name")
    ap.add_argument("-p", "--password", help="Password")
    ap.add_argument("-a", "--all", default=True)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--port", type=int, default=22, help="Port SSH (domyślnie 22)")
    ap.add_argument("--timeout", type=int, default=15, help="Timeout połączenia w sekundach")
    ap.add_argument("--dry-run", action="store_true", help="Tylko pokaż co byłoby wykonane, bez zmian")
    ap.add_argument("-i","--interactive", action="store_true", help="Interactive mode")
    return ap.parse_args()


def connect_ssh(ip: str, username: str, password: str, port: int, timeout: int) -> Tuple[
    paramiko.SSHClient, Optional[str]]:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            ip, port=port, username=username, password=password,
            allow_agent=False, look_for_keys=False, timeout=timeout, banner_timeout=timeout, auth_timeout=timeout
        )
        return client, None
    except (paramiko.SSHException, socket.error, socket.timeout) as e:
        return None, f"Połączenie nieudane: {e}"


def run_cmd(client: paramiko.SSHClient, cmd: str, sudo: bool, password: str, timeout: int = 30, interactive_mode: bool = False) -> Tuple[int, str, str]:
    """
    Uruchamia komendę; jeśli sudo=True, podaje hasło przez stdin.
    Zwraca (rc, stdout, stderr).
    """
    out=""
    err=""
    rc=""

    if not interactive_mode:
        full_cmd = f"sudo -S -p '' {cmd}" if sudo else cmd
        # get_pty=True aby sudo akceptowało hasło
        stdin, stdout, stderr = client.exec_command(full_cmd, get_pty=True, timeout=timeout)
        if sudo:
            stdin.write(password + "\n")
            stdin.flush()
        out = stdout.read().decode("utf-8", "ignore")
        err = stderr.read().decode("utf-8", "ignore")
        rc = stdout.channel.recv_exit_status()
    else:
        shell = client.invoke_shell()
        rc = 0
        for c in cmd.split(";"):
            shell.send(c + "\n")
            print(f"Sent: {c}")
            time.sleep(1)
            while shell.recv_ready():
                o = shell.recv(4096).decode("utf-8", errors="ignore")
                out += o
            while shell.recv_stderr_ready():
                e = shell.recv_stderr(4096).decode("utf-8", errors="ignore")
                err += e
            # Give time for command to execute
    return rc, out, err


def current_user(client: paramiko.SSHClient) -> str:
    rc, out, _ = run_cmd(client, "id -un", sudo=False, password="", timeout=10)
    return out.strip() if rc == 0 else ""


def prepare_commands() -> str:
    # Jeden bezpieczny blok bash: backup, edycja, test, reload.
    # Usuwamy istniejące AllowUsers, ustawiamy PermitRootLogin yes i dodajemy AllowUsers root.
    return 'echo "dupa" > /tmp/test.txt'


def get_logger(level: int) -> logging.Logger:
    logger = logging.getLogger('X')
    logger.setLevel(level=level)

    sh = logging.StreamHandler(sys.stdout)
    fh = logging.FileHandler("test.log")

    fh_formatter = logging.Formatter('%(asctime)s %(levelname)s %(lineno)d:%(filename)s(%(process)d) - %(message)s')
    sh_formatter = logging.Formatter('%(asctime)s %(message)s')

    fh.setFormatter(fh_formatter)
    sh.setFormatter(sh_formatter)

    fh.terminator = ''
    # logger.addHandler(sh)
    logger.addHandler(fh)
    return logger


def main():
    config_file = "settings.conf"
    config_parser = configparser.ConfigParser()
    config_parser.read(config_file)

    logger = get_logger(logging.DEBUG)
    logger.info("ESSSA")

    args = parse_args()
    hosts = load_hosts('hosts.csv')  # load_hosts(args.file)
    if not hosts or args.destination is not None:
        hosts = []
        # print("Brak hostów do przetworzenia (sprawdź plik CSV).", file=sys.stderr)
        for ip in args.destination.split(','):
            hosts.append((ip, args.user, args.password))
        # sys.exit(2)
    cmd_block = args.command if args.command else prepare_commands()

    summary = []
    username = args.user
    password = args.password
    ips_list = args.destination.split(',') if args.destination else hosts
    use_sudo = False
    is_verbose = args.verbose
    is_interactive = args.interactive
    path_to_results = os.getcwd()

    for ip, username, password in hosts:
        l = logging.getLogger(f'{ip}.log')
        l.addHandler(logging.FileHandler(f'{ip}.log'))
        l.setLevel(logging.DEBUG if is_verbose else logging.INFO)

        print(f"\n=== {ip} ({username}) ===")
        if args.dry_run:
            print("[DRY-RUN] Nie łączę się; pokazałbym polecenia:")
            print(cmd_block)
            summary.append((ip, username, "DRY-RUN", "OK"))
            continue

        client, err = connect_ssh(ip, username, password, args.port, args.timeout)
        if not client:
            print(f"❌ Błąd połączenia: {err}")
            summary.append((ip, username, "CONNECT", f"ERROR: {err}"))
            continue

        try:
            # user = current_user(client)
            # use_sudo = (user != "root")
            # if use_sudo and not password:
            #   print("❌ Brak hasła do sudo (użytkownik nie-root).")
            #   summary.append((ip, "SUDO", "ERROR: missing password"))
            #   client.close()

            rc, out, serr = run_cmd(client, cmd_block, sudo=use_sudo, password=password, timeout=120, interactive_mode=is_interactive)
            if rc == 0:
                print(f"✅ Zmiany zastosowane.\n{out.strip() if is_verbose else ''}")
                # out=out.strip().replace('\r\n', '\n')
                l.info(f"{ip} ({username}): {out} ")
                summary.append((ip, username, "APPLY", "OK"))
            else:
                print(
                    f"❌ Błąd wykonywania (rc={rc}).\nSTDOUT:\n{out if is_verbose else '-'}\nSTDERR:\n{serr if is_verbose else '-'}")
                l.error(f"{ip} ({username}): {out} ")
                summary.append((ip, username, "APPLY", f"ERROR rc={rc}"))
        except Exception as e:
            print(f"❌ Wyjątek: {e}")
            summary.append((ip, username, "EXCEPTION", f"{e}"))
        finally:
            client.close()
            # mała pauza, żeby nie zalać serwera
            time.sleep(0.3)

    print("\n=== Podsumowanie ===")
    for ip, username, step, status in summary:
        print(f"{ip:>15}  {username:4s} {step:8s}  {status}")


if __name__ == "__main__":
    main()
