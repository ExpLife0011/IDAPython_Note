#coding=utf-8

import idautils
import idc
import idaapi

#获取指定函数中所有指令地址的集合,FuncItems返回的是迭代器,可以强制转换为list
dism_addr = list(idautils.FuncItems(here()))
print type(dism_addr)

print dism_addr

for line in dism_addr:
    print hex(line), idc.GetDisasm(line)
    
#获取下一个指令的地址
idc.NextHead(ea)

#获取上一条指令的地址
idc.PrevHead(ea)

#获取下一个地址
idc.NextAddr(ea)

#获取上一个地址
idc.PrevAddr(ea)
    
#遍历所有的动态调用 
for func in idautils.Functions():
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for line in dism_addr:
        m = idc.GetMnem(line)
        if m == 'call' or m == 'jmp':
            op = idc.GetOpType(line, 0)
            if op == o_reg:
                print "0x%x %s" % (line, idc.GetDisasm(line))
                
ea = here()
print hex(ea), idc.GetDisasm(ea)
next_instr = idc.NextHead(ea)
print hex(next_instr), idc.GetDisasm(next_instr)
prev_instr = idc.PrevAddr(ea)
print hex(prev_instr), idc.GetDisasm(prev_instr)
print hex(idc.NextAddr(ea))
print hex(idc.PrevAddr(ea))





