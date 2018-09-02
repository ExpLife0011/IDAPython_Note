#coding=utf-8

import idaapi
import idc
import idautils

# o_void值为0  表示指令没有任何操作数
# 1000029A9                 retn
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 0)

# o_reg值为1 表示指令的操作数是寄存器
# 0x100002779L mov     rax, cs:__security_cookie
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 0)

# o_mem值为2 表示指令的操作数是直接寻址的内存 这种类型对寻找数据的引用非常有帮助
# 0x100002779L mov     rax, cs:__security_cookie
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 1)

# o_phrase值为3 表示指令的操作数采用的是基址寄存器和变址寄存器的寻址方式
# 1000022B4                 lea     rdx, [rsi+rsi]  ; uBytes
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 1)

# o_displ的值为4 表示指令的操作数采用寄存器加偏移的寻址方式  这种类型在获取结构体中的某个数据的时候非常常见
# 100002396                 lea     r9, [rsp+288h+var_268] ; unsigned __int64 *
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 1)

# o_imm的值为5 表示指令的操作数是一个确定的值
# 1000022B8                 mov     ecx, 40h        ; uFlags
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 1)

# o_far的值为6 用来判断直接访问远端地址的操作数 x86 x64逆向用的很少
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 1)

# o_near的值为7 用来判断直接访问近端地址的操作数
# 1000027E2                 jz      short loc_100002835
ea = here()
print hex(ea), idc.GetDisasm(ea)
print idc.GetOpType(ea, 0)

# 例子1 将o_displ类型的指令 偏移 + 指令首地址 构成字典 便于查询
displace = {}
#遍历所有已知的函数
for func in idautils.Functions():
    flags = idc.GetFunctionFlags(func)
    #跳过库函数和简单的跳转函数
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for curr_addr in dism_addr:
        op = None
        index = None
        #另一种访问类型的方式,跟idc.GetOpType类似
        idaapi.decode_insn(curr_addr)
        if idaapi.cmd.Op1.type == idaapi.o_displ:
            op = 1
        if idaapi.cmd.Op2.type == idaapi.o_displ:
            op = 2
        if op == None:
            continue
        if "bp" in idaapi.tag_remove(idaapi.ua_outop2(curr_addr, 0)) or "bp" in idaapi.tag_remove(idaapi.ua_outop2(curr_addr, 1)):
            # bp/ebp/rbp将返回一个负数
            if op == 1:
                index = (~(int(idaapi.cmd.Op1.addr) - 1) & 0xFFFFFFFF)
            else:
                index = (~(int(idaapi.cmd.Op2.addr) - 1) & 0xFFFFFFFF)
        else:
            if op == 1:
                index = int(idaapi.cmd.Op1.addr)
            else:
                index = int(idaapi.cmd.Op2.addr)
        if index:
            if displace.has_key(index) == False:
                displace[index] = []
            displace[index].append(curr_addr)

for x in displace[0x130]: print hex(x), idc.GetDisasm(x)

#遍历所有函数,尝试将带有立即数寻址方式的指令中立即数转化为对数据的偏移

min = MinEA()
max = MaxEA()
#遍历所有已知的函数
for func in idautils.Functions():
    flags = idc.GetFunctionFlags(func)
    #跳过库函数和简单的跳转函数
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    dism_addr = list(idautils.FuncItems(func))
    for curr_addr in dism_addr:
        if idc.GetOpType(curr_addr, 0) == o_imm and (min < idc.GetOperandValue(curr_addr, 0) < max):
            idc.OpOff(curr_addr, 0, 0)     #将操作数转换为一个偏移
        if idc.GetOpType(curr_addr, 1) == o_imm and (min < idc.GetOperandValue(curr_addr, 1) < max):
            idc.OpOff(curr_addr, 1, 0)     #将操作数转换为一个偏移   
            