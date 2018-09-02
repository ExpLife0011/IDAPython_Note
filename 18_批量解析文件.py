#coding=utf-8

import os
import subprocess
import glob

paths = glob.glob("*")
ida_path = os.path.join(os.environ['PROGRAMFILES'], "IDA", "idaw.exe")
for file_path in paths:
    if file_path.endswith(".py"):
        continue
    subprocess.call([ida_path, "-B", file_path])
    