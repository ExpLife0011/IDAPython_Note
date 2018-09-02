#coding=utf-8

import idc
import idaapi
import idautils

idc.PatchByte(ea, value)     #修改字节
idc.PatchWord(ea, value)   #修改字
idc.PatchDword(ea, value) #修改双字

# 利用异或解密算法 解密选中的加密字符串
start = idc.SelStart()
end = idc.SelEnd()
print hex(start)
print hex(end)

def xor(size, key, buff):
    for index in range(0, size):
        cur_addr = buff + index
        temp = idc.Byte(cur_addr) ^ key
        idc.PatchByte(cur_addr, temp)

xor(end - start, 0x30, start)
print idc.GetString(start)


