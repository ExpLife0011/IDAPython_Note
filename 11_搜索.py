#coding=utf-8

import idautils
import idaapi
import idc

#字节/二进制搜索
# 搜索的方向或者条件
# SEARCH_UP = 0                         指明搜索的方向     往上方搜索
# SEARCH_DOWN = 1                  指明搜索的方向     往下方搜索
# SEARCH_NEXT = 2                     获取下一个已经找到的对象
# SEARCH_CASE = 4                     指明是否区分大小写
# SEARCH_REGEX = 8                   
# SEARCH_NOBRK = 16
# SEARCH_NOSHOW = 32            指明是否显示搜索的进度
# SEARCH_UNICODE = 64 **        将所有搜索字符串视为Unicode
# SEARCH_IDENT = 128 **
# SEARCH_BRK = 256 **

# 二进制查找
# push ebp
# mov ebp,esp
pattern = '55 56 57'
addr = MinEA()
for x in range(0,5):
    addr = idc.FindBinary(addr, SEARCH_DOWN | SEARCH_NEXT, pattern)
    if addr != idc.BADADDR:
        print hex(addr), idc.GetDisasm(addr)

# 字符串查找
cur_addr = MinEA()
end = MaxEA()
while cur_addr < end:
    cur_addr = idc.FindText(cur_addr, SEARCH_DOWN, 0, 0, "_fmode")
    if cur_addr == idc.BADADDR:
        break
    else:
        print hex(cur_addr),idc.GetDisasm(cur_addr)
        cur_addr = idc.NextHead(cur_addr)

#F这个参数需要先通过idc.GetFlags(ea)获取地址的内部标志表示形式,然后再传给idc.is*系列函数当参数

#判断IDA是否将其判定为代码
idc.isCode(F)

#判断IDA是否将其判定为数据
idc.isData(F)

#判断IDA是否将其判定为尾部
idc.isTail(F)

#判断IDA是否将其判定为未知(既不是数据,也不是代码)
idc.isUnknown(F)

#判断IDA是否将其判定为头部
idc.isHead(F)

#0x100001f77L mov     rbx, rsi
#True
ea = here()
print hex(ea),idc.GetDisasm(ea)
print idc.isCode(idc.GetFlags(ea))

# idc.FindCode(ea, flag) 该函数用于寻找被标记为代码的下一个地址. 对于想要查找数据块的尾部很有帮助
#0x1000013c0L text "UTF-16LE", '{00000000-0000-0000-0000-000000000000}',0
#0x1000014f8L xor     r11d, r11d
ea = here()
print hex(ea),idc.GetDisasm(ea)
addr = idc.FindCode(ea, SEARCH_DOWN|SEARCH_NEXT)
print hex(addr),idc.GetDisasm(addr)

# idc.FindData(ea, flag) 该函数用于寻找被标记为数据的下一个地址.
# 0x1000020b6L movzx   eax, word ptr [r12+2]
# 0x100001cccL db 8 dup(0CCh)
ea = here()
print hex(ea),idc.GetDisasm(ea)
addr = idc.FindData(ea, SEARCH_UP|SEARCH_NEXT)
print hex(addr),idc.GetDisasm(addr)

# idc.FindUnexplored(ea, flag) 该函数用于查找IDA未识别为代码或者数据的字节地址. 未知类型需要通过观察或者脚本进一步分析
ea = here()
print hex(ea),idc.GetDisasm(ea)
addr = idc.FindUnexplored(ea, SEARCH_DOWN)
print hex(addr),idc.GetDisasm(addr)

# idc.FindExplored(ea, flag) 用于查找IDA标识为代码或者数据的地址
ea = here()
addr = idc.FindExplored(ea, SEARCH_UP)
print hex(addr),idc.GetDisasm(addr)

for xref in idautils.XrefsTo(addr, 1):
    print hex(xref.frm), idc.GetDisasm(xref.frm)

# idc.FindImmediate(ea, flag, value) 用于寻找确定的数值  例如rand()函数使用的随机种子
addr = idc.FindImmediate(MinEA(), SEARCH_DOWN, 0x343FD)
print "0x%x %s %x" % (addr[0], idc.GetDisasm(addr[0]), addr[1])

# 查找所有的指定立即数
addr = MinEA()
while True:
    addr, operand = idc.FindImmediate(addr, SEARCH_DOWN | SEARCH_NEXT, 0x5c)
    if addr != idc.BADADDR:
        print hex(addr), idc.GetDisasm(addr), "Operand", operand
    else:
        break
    

    

