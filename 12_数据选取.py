#coding=utf-8

import idautils
import idaapi
import idc

#获取选取的数据的边界(起始地址和结束地址) 注意结束地址是这段数据中最后一条指令的下一条指令的起始地址
#0x100001dfdL 0x100001e2dL
start = idc.SelStart()
end = idc.SelEnd()
print hex(start),hex(end)

# 同上 简化版
#0x1 0x100001dfdL 0x100001e2bL
result,start,end = idaapi.read_selection()
print hex(result), hex(start), hex(end)

