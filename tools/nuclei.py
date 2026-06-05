from tools.executor import run_cmd

def run_nuclei(target):
    return run_cmd(["nuclei", "-u", target, "-silent"])
