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
        start_idx = 1 if set(header_like) >= {"ip", "username", "oldPasswd", "newPasswd"} else 0
        for row in rows[start_idx:]:
            if not row or len(row) < 3:
                continue
            ip, user, pwd, pwd2 = row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip()
            if ip and user:
                hosts.append((ip, user, pwd, pwd2))
    return hosts


def parse_args():
    ap = argparse.ArgumentParser(
        description="Ogranicz logowanie SSH na zdalnych hostach wyłącznie do konta root."
    )
    ap.add_argument("-f", "--file", default="hosts.csv" ,required=True, help="Ścieżka do pliku CSV: ip,username,password")
    ap.add_argument("-r", "--result", default="new_hosts.csv" ,required=True, help="Ścieżka do pliku CSV: ip,username,password")
    ap.add_argument("-v", "--verbose", action="store_true")
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


def run_cmd(client: paramiko.SSHClient, cmd: str, sudo: bool, password: str, timeout: int = 30, interactive_mode: bool = false) -> Tuple[int, str, str]:
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
        channel = client.invoke_shell()
        print(f"Connected to {host}. Sending commands...\n")
        for c in cmd.split(";"):
            channel.send(c + "\n")
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

    hosts=[]
    hosts = load_hosts(args.file)  # load_hosts(args.file)


    summary = []
    new_hosts=[]
    is_verbose = args.verbose
    is_interactive = args.interactive
    path_to_results = os.getcwd()

    for ip, username, oldPasswd, newPasswd in hosts:
        l = logging.getLogger(f'{ip}.log')
        l.addHandler(logging.FileHandler(f'{ip}.log'))
        l.setLevel(logging.DEBUG if is_verbose else logging.INFO)

        print(f"\n=== {ip} ({username}) ===")


        client, err = connect_ssh(ip, username, oldPasswd, 22, 30)
        if not client:
            print(f"❌ Błąd połączenia: {err}")
            summary.append((ip, username, "CONNECT", f"ERROR: {err}"))
            continue
        x=0
        y=0
        try:

            cmd_block=f"passwd {username};{newPasswd};{newPasswd}"
            rc, out, serr = run_cmd(client, cmd_block, sudo=use_sudo, password=password, timeout=120, interactive_mode=is_interactive)
            if rc == 0:
                print(f"✅ Hasło zmienione.\n{out.strip() if is_verbose else ''}")
                client, err = connect_ssh(ip, username, newPasswd, 22, 10)
                x=1
                summary.append((ip, username, "APPLY", "OK"))
            else:
                print(
                    f"❌ Błąd wykonywania (rc={rc}).\nSTDOUT:\n{out if is_verbose else '-'}\nSTDERR:\n{serr if is_verbose else '-'}")
                summary.append((ip, username, "APPLY", f"ERROR rc={rc}"))
        except Exception as e:
            print(f"❌ Wyjątek: {e}")
            summary.append((ip, username, "EXCEPTION", f"{e}"))
        finally:
            client.close()
            # mała pauza, żeby nie zalać serwera
            time.sleep(0.3)
        try:
            client, err = connect_ssh(ip, username, newPasswd, 22, 10)
            if not client:
                print(f"❌ Błąd połączenia: {err}")
            else:
                y=1
        except Exception as e:
            print(f"❌ Wyjątek: {e}")
            summary.append((ip, username, "EXCEPTION", f"{e}"))
        finally:
            client.close()
            # mała pauza, żeby nie zalać serwera
            time.sleep(0.3)
        if x==1 and y==1:
            print(f"✅ Hasło zmienione i test ok!.\n{out.strip() if is_verbose else ''}")
            new_hosts.append(ip,username,newPasswd)

    with open(args.result, mode="w", newline="", encoding="utf-8") as plik:
        writer = csv.writer(plik)

        # zapis nagłówka (opcjonalnie)
        writer.writerow(["ip","username","password"])

        # zapis każdego elementu z listy
        for element in new_hosts:
            writer.writerow([element])

    print("\n=== Podsumowanie ===")
    for ip, username, step, status in summary:
        print(f"{ip:>15}  {username:4s} {step:8s}  {status}")


if __name__ == "__main__":
    main()
