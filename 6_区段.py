#coding=utf-8

import idautils
import idc

#遍历区段
for seg in idautils.Segments():
    print idc.SegName(seg), hex(idc.SegStart(seg)), hex(idc.SegEnd(seg))
    
#获取当前地址所在段的下一个段的起始地址
ea  = here()
print hex(idc.NextSeg(ea))

#通过名称获取一个区段的起始地址  ??
print hex(idc.SegByName('.data'))



