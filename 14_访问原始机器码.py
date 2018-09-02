#coding=utf-8

import idc
import idaapi
import idautils

idc.Byte(ea)          #获取单字节
idc.Word(ea)        #获取单字
idc.Dword(ea)      #获取双字
idc.Qword(ea)      #获取四字
idc.GetFloat(ea)    #获取单精度浮点数
idc.GetDouble(ea) #获取双精度浮点数

#0x100003b2fL mov     rcx, cs:__imp__wcmdln
#0x48
#0x8b48L
#0xa0d8b48L
#0x48ffffd70a0d8b48L
#6.81509894557e-33
#4.46006192587e+43
ea = here()
print hex(ea), idc.GetDisasm(ea)
print hex(idc.Byte(ea))
print hex(idc.Word(ea))
print hex(idc.Dword(ea))
print hex(idc.Qword(ea))
print float(idc.GetFloat(ea))
print float(idc.GetDouble(ea))

# 利用idc.GetManyBytes(ea, size) 获取指定地址开始的多个字节码 该函数返回的是字节的字符形式
ea = here()
for byte in idc.GetManyBytes(ea, 20):
    print "0x%X" % ord(byte)

