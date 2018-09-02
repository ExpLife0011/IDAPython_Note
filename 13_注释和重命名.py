#coding=utf-8

import idc
import idaapi
import idautils

# 利用idc.MakeComm通过添加常规注释 
# 利用idc.MakeRptCmt利用添加重复性注释
# 对所有函数中的异或自身的指令添加常规注释
for func in idautils.Functions():
    flags = idc.GetFunctionFlags(func)
    #跳过库函数和简单的跳转函数
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        continue
    for ea in idautils.FuncItems(func):
        if idc.GetMnem(ea) == "xor":
            if idc.GetOpnd(ea, 0) == idc.GetOpnd(ea, 1):
                comment = "%s = 0" % (idc.GetOpnd(ea, 0))
                idc.MakeComm(ea, comment)
                
# 利用idc.GetCommentEx(ea, repeatable)获取注释
# 0x1000014f8L xor     r11d, r11d; r11d = 0
# r11d = 0
ea = here()
print hex(ea),idc.GetDisasm(ea)
print idc.GetCommentEx(ea, False)

# 利用idc.SetFunctionCmt(ea, cmt, repeatable)给函数添加注释  如果将函数的注释标记为可重复性的话,那么它会在任何调用该函数的地方增加注释
# 利用idc.GetFunctionCmt(ea, repeatable)获取函数的注释
ea = here()
print hex(ea),idc.GetDisasm(ea)
print idc.GetFunctionName(ea)
idc.SetFunctionCmt(ea, "Check out later", True)

# 利用idc.MakeName(ea, name)重命名函数或者地址 要重命令函数的话,ea一定要是函数的起始地址
ea = 0x1000039A4
print idc.GetFunctionName(ea)
print hex(ea),idc.GetDisasm(ea)
print idc.MakeName(ea, "wgetmainargs_wrap")
print idc.GetFunctionName(ea)

# 重命名操作数
#0x100003bc2L mov     eax, cs:dword_100006170
#0x100006170L dd 0
#True
#0x100003bc2L mov     eax, cs:BETA
ea = here()
print hex(ea), idc.GetDisasm(ea)
op = idc.GetOperandValue(ea, 1)
print hex(op), idc.GetDisasm(op)
print idc.MakeName(op, 'BETA')
print hex(ea), idc.GetDisasm(ea)

#Function at 0x1000039a4 renamed w___imp___wgetmainargs
#Function at 0x100003db0 renamed w___imp_SetUnhandledExceptionFilter
# 自动化命名封装函数
def rename_wrapper(name, func_addr):
    if idc.MakeNameEx(func_addr, name, SN_NOWARN):
        print "Function at 0x%x renamed %s" % (func_addr, idc.GetFunctionName(func_addr))
    else:
        print "Rename at 0x%x failed. Function %s is being used." % (func_addr, name)
    return

def check_for_wrapper(func):
    flags = idc.GetFunctionFlags(func)
    #跳过库函数和简单的跳转函数
    if flags & FUNC_LIB or flags & FUNC_THUNK:
        return
    dism_addr = list(idautils.FuncItems(func))
    #获取函数的长度
    func_length = len(dism_addr)
    #如果函数的超过32条指令则返回
    if func_length > 0x20:
        return
    
    func_call = 0
    instr_cmp = 0
    op = None
    op_addr = None
    op_type = None
    
    #遍历函数中的每条指令
    for ea in dism_addr:
        m = idc.GetMnem(ea)
        if m == 'call' or m == 'jmp':
            if m == 'jmp':
                temp = idc.GetOperandValue(ea, 0)
                # 忽略函数边界内的跳转
                if temp in dism_addr:
                    continue
            func_call += 1
            #封装函数内不会包含多个函数调用
            if func_call == 2:
                return
            op_addr = idc.GetOperandValue(ea, 0)
            op_type = idc.GetOpType(ea, 0)
        elif m == 'cmp' or m == 'test':
            # 封装函数内不应该包含太多的逻辑运算
            instr_cmp += 1
            if instr_cmp == 3:
                return
        else:
            continue
    
    # 所有函数内的指令都被分析过了
    if op_addr == None:
        return
    
    name = idc.Name(op_addr)
    #跳过名称粉碎的函数名称
    if "[" in name or "$" in name or "?" in name or "@" in name or name == "":
        return
    name = "w_" + name
    if op_type == o_near:
        if idc.GetFunctionFlags(op_addr) & FUNC_THUNK:
            rename_wrapper(name, func)
            return
    if op_type == o_mem or op_type == o_far:
        rename_wrapper(name, func)
        return
    
for func in idautils.Functions():
    check_for_wrapper(func)

        
        
        









