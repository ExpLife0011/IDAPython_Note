#coding=utf-8

import idc
import idaapi
import idautils

idaapi.autoWait()  #等待IDA的分析完成

# 统计idb文件中所有指令的总数
# "D:\software\IDA 7.0\idat64.exe" -A -Scountrecord.py rundll32.idb

count = 0
for func in idautils.Functions():
    #忽略库函数
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_LIB:
        continue
    for instru in idautils.FuncItems(func):
        count += 1

f = open("instru_count.txt", "w")
print_me = "Instruction Count is %d" % (count)
f.write(print_me)
f.close()

idc.Exit(0)  #停止执行脚本 并关闭idb数据库文件
