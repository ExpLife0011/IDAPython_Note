#coding=utf-8

import idc
import idaapi
import idautils

#获取对指定API函数的所有交叉引用处
writefile_addr = idc.LocByName("__imp_iswalpha")                  #获取API函数的地址
print hex(writefile_addr), idc.GetDisasm(writefile_addr)            
for addr in idautils.CodeRefsTo(writefile_addr, 0):                    #循环遍历该API函数的所有交叉引用
    print hex(addr), idc.GetDisasm(addr)

#获取所有API函数和被重命名函数的相关信息
for x in Names():
    print hex(x[0]), x[1]

#获取指定地址所引用的代码
#0x100001dcaL call    cs:__imp_iswalpha
#0x100001278L extrn __imp_iswalpha:qword
ea = here()
print hex(ea),idc.GetDisasm(ea)
for addr in idautils.CodeRefsFrom(ea, 0):
    print hex(addr),idc.GetDisasm(addr)

ea = 0x100001CD4
print idc.MakeName(ea, "RtlCompareMemory")     #将指定地址重命名
for addr in idautils.CodeRefsTo(ea, 0):
    print hex(addr), idc.GetDisasm(addr)

#查询所有对指定地址处数据的交叉引用
#0x100001378L text "UTF-16LE", '\UNC\',0
#0x100001723L lea     r11, aUnc; "\\UNC\\"
ea = here()
print hex(ea), idc.GetDisasm(ea)
for addr in idautils.DataRefsTo(ea):print hex(addr), idc.GetDisasm(addr)

#查询该地址所引用的所有数据地址
#0x100001723L lea     r11, aUnc; "\\UNC\\"
#0x100001378L text "UTF-16LE", '\UNC\',0
ea = here()
print hex(ea), idc.GetDisasm(ea)
for addr in idautils.DataRefsFrom(ea):print hex(addr), idc.GetDisasm(addr)

# 交叉引用的类型 
#0 = 'Data_Unknown'
#1 = 'Data_Offset'
#2 = 'Data_Write'
#3 = 'Data_Read'
#4 = 'Data_Text'
#5 = 'Data_Informational'
#16 = 'Code_Far_Call'
#17 = 'Code_Near_Call'
#18 = 'Code_Far_Jump'
#19 = 'Code_Near_Jump'
#20 = 'Code_User'
#21 = 'Ordinary_Flow'

# 通用查找交叉引用的方式
#0x100001410L text "UTF-16LE", '\\?\Volume',0
#1 Data_Offset 0x100002462L 0x100001410L 0 lea     rbx, aVolume; "\\\\?\\Volume"
ea = here()
print hex(ea), idc.GetDisasm(ea)
for xref in idautils.XrefsTo(ea, 1):    # idautils.XrefsTo 第二个参数为1表示略过正常顺序指令流程造成的交叉引用     
    print xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to),xref.iscode,idc.GetDisasm(xref.frm)

#True
#17 Code_Near_Call 0x1000023ffL 0x100001cd4L 1 call    RtlCompareMemory
#1 Data_Offset 0x100007054L 0x100001cd4L 0 RUNTIME_FUNCTION <rva RtlCompareMemory, rva algn_1000021E7, \
ea = 0x100001CD4
print idc.MakeName(ea, "RtlCompareMemory")     #将指定地址重命名
for xref in idautils.XrefsTo(ea, 1):
    print xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to),xref.iscode,idc.GetDisasm(xref.frm)

#交叉引用的结果可能会有重复
#0x100001100L extrn __imp_GetTickCount:qword
#17 Code_Near_Call 0x100003feaL 0x100001100L 1 call    cs:__imp_GetTickCount
#3 Data_Read 0x100003feaL 0x100001100L 0 call    cs:__imp_GetTickCount
ea = here()
print hex(ea), idc.GetDisasm(ea)
for xref in idautils.XrefsTo(ea, 1):    # idautils.XrefsTo 第二个参数为1表示略过正常顺序指令流程造成的交叉引用     
    print xref.type, idautils.XrefTypeName(xref.type), hex(xref.frm), hex(xref.to),xref.iscode,idc.GetDisasm(xref.frm)

#对交叉引用的结果去重

def get_xrefs_to(ea):
    xref_set = set()
    for xref in idautils.XrefsTo(ea, 1):
        xref_set.add(xref.frm)
    return xref_set

def get_xrefs_frm(ea):
    xref_set = set()
    for xref in idautils.XrefsFrom(ea, 1):
        xref_set.add(xref.to)
    return xref_set

ea = 0x100001100L
print hex(ea), idc.GetDisasm(ea)
xref_set = get_xrefs_to(ea)
for xref in xref_set:
    print hex(xref)



  
