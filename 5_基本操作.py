#coding=utf-8

import idc
import idaapi

#获取当前光标的地址
ea = idc.ScreenEA()
print "0x%x %s" % (ea, ea)

#获取当前光标的地址
ea = here()
print "0x%x %s" % (ea, ea)

#获取当前IDB中最小地址
print hex(MinEA())

#获取当前IDB中最大地址
print hex(MaxEA())

ea = here()

#获取指定地址区段名称
print idc.SegName(ea)

#获取指定地址反汇编代码
print idc.GetDisasm(ea)

#获取指定地址助记符
print idc.GetMnem(ea)

#获取指定地址第一个操作数
print idc.GetOpnd(ea, 0)

#获取指定地址第二个操作数
print idc.GetOpnd(ea, 1)

#标识无效地址
print hex(idaapi.BADADDR)

if idaapi.BADADDR != here() : print "valid address"


