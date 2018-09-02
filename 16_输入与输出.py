#coding=utf-8

import sys
import idc
import idaapi
import idautils

class IO_DATA():
    def __init__(self):
        self.start = idc.SelStart()
        self.end = idc.SelEnd()
        self.buffer = ''
        self.ogLen = None
        self.status = True
        self.run()
    
    def checkBounds(self):
        if self.start is idc.BADADDR or self.end is idc.BADADDR:
            self.status = False
    
    def getData(self):
        #获取起始地址和结束地址之间的数据,并将它们存入object.buffer中
        self.ogLen = self.end - self.start
        self.buffer = ''
        try:
            for byte in idc.GetManyBytes(self.start, self.ogLen):
                self.buffer = self.buffer + byte
        except:
            self.start = False
        return
    
    def run(self):
        #主要功能
        self.checkBounds()
        if self.status == False:
            sys.stdout.write('ERROR:Please select valid data\n')
            return
        self.getData()
        
    def patch(self, temp = None):
        #用object.buffer中的数据给idb打补丁
        if temp != None:
            self.buffer = temp
            for index,byte in enumerate(self.buffer):
                idc.PatchByte(self.start + index, ord(byte))
    
    def importb(self):
        #将文件中的内容导入到buffer中
        fileName = idc.AskFile(0, "*.*", 'Import File')
        try:
            self.buffer = open(fileName, 'rb').read()
        except:
            sys.stdout.write('ERROR:Cannot access file')
        
    def export(self):
        #将所选择的buffer保存到文件
        exportFile = idc.AskFile(1, "*.*", "Export Buffer")
        f = open(exportFile, 'wb')
        f.write(self.buffer)
        f.close()
        
    def stats(self):
        print "start: %s" % hex(self.start)
        print "end: %s" % hex(self.end)
        print "len: %s" % hex(len(self.buffer))
    
    
        
        
    
        