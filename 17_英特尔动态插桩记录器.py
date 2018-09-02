#coding=utf-8

import sys
import idc
import idaapi
import idautils

#对pintools执行完毕生成的文件,用IDAPython脚本来遍历其中的地址并添加注释
f = open('itrace.out', 'r')
lines = f.readlines()
for y in lines:
    y = int(y, 16)
    idc.SetColor(y, CIC_ITEM, 0xfffff)
    com = idc.GetCommentEx(y, 0)
    if com == None or 'count' not in com:
        idc.MakeComm(y, 'count:1')
    else:
        try:
            count = int(com.split(':')[1], 16)
        except:
            print hex(y)
        tmp = "count:0x%x" % (count + 1)
        idc.MakeComm(y, tmp)

f.close()
