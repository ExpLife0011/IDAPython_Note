#coding=utf-8

import idautils
import idaapi
import idc

#遍历所有区段中的函数
for func in idautils.Functions():
    print hex(func), idc.GetFunctionName(func)
       
#查找指定起始地址,结束地址之间的所有函数
funcs = idautils.Functions(0x1000491D0, 0x10004932A)
for func in funcs:
    print hex(func), idc.GetFunctionName(func)
    
#通过某个地址获取函数名称
print idc.GetFunctionName(0x10000646D)

#获取指定地址所在函数的起始地址和结束地址 方式1
func = idaapi.get_func(0x10000646D)

print "FuncName:%s,Start:0x%x,End:0x%x" % (idc.GetFunctionName(func.startEA),func.startEA, func.endEA)

#获取指定地址所在函数的起始地址和结束地址 方式2
print "Start:0x%x,End:0x%x" % (idc.GetFunctionAttr(0x10003F3BD, FUNCATTR_START), idc.GetFunctionAttr(0x10003F3BD, FUNCATTR_END))

#查看类有哪些属性
dir(func)

#获取类型
type(func)

#获取指定地址所在函数的前一个函数的起始地址
func = idc.PrevFunction(0x10000646D)
print idc.GetFunctionName(func), hex(func)

#获取指定地址所在函数的后一个函数的起始地址
func = idc.NextFunction(0x10000646D)
print idc.GetFunctionName(func), hex(func)

#获取下一条指令的地址
idc.NextHead()

#遍历某个地址所在函数的所有指令
ea = here()
start = idc.GetFunctionAttr(ea, FUNCATTR_START)
end = idc.GetFunctionAttr(ea, FUNCATTR_END)

cur_addr = start

while cur_addr < end:
    print hex(cur_addr), idc.GetDisasm(cur_addr)
    cur_addr = idc.NextHead(cur_addr, end)

#检索关于函数的信息

for func in idautils.Functions():
    flags = idc.GetFunctionFlags(func)
    if flags & FUNC_NORET:     #FUNC_NORET:1 判断某个函数是否有返回值 (也就是说函数最后有没有ret或者leave指令)                                        
        print idc.GetFunctionName(func),hex(func),"FUNC_NORET"          
    if flags & FUNC_FAR:          #FUNC_FAR:2 标识程序是否使用分段内存
        print idc.GetFunctionName(func),hex(func),"FUNC_FAR"
    if flags & FUNC_LIB:            #FUNC_LIB:4  判断是否为库函数
        print idc.GetFunctionName(func),hex(func),"FUNC_LIB"       
    if flags & FUNC_STATIC:      #判断某个函数是否为静态函数,静态函数只能为本文件中的函数访问
        print idc.GetFunctionName(func),hex(func),"FUNC_STATIC"    
    if flags & FUNC_FRAME:     #判断某个函数是否使用了ebp寄存器(帧指针),使用ebp寄存器的函数通常会保存栈帧
        print idc.GetFunctionName(func),hex(func),"FUNC_FRAME"
    if flags & FUNC_USERFAR:  #FUNC_USERFAR:32 用的很少
        print idc.GetFunctionName(func),hex(func),"FUNC_USERFAR"
    if flags & FUNC_HIDDEN:    #带有FUNC_HIDDEN标记的函数意味着它们是隐藏的,这个函数需要展开才能查看
        print idc.GetFunctionName(func),hex(func),"FUNC_HIDDEN"        
    if flags & FUNC_THUNK:      #判断该函数是否为一个thunk函数,thunk函数表示的是一个简单的跳转函数
        print idc.GetFunctionName(func),hex(func),"FUNC_THUNK"
    if flags & FUNC_BOTTOMBP: #用于跟踪帧指针(ebp),它的作用是识别函数中帧指针是否等于堆栈指针(esp)
        print idc.GetFunctionName(func),hex(func),"FUNC_BOTTOMBP"    
    