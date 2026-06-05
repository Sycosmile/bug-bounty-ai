from tools.executor import run_cmd

def run_httpx(target):
    return run_cmd(["httpx", "-silent", "-u", target])
