#!/usr/bin/env python
#
# Dump selection IDA plugin by deroko of ARTeam
import	idaapi
import  idc
import	struct
from PyQt5 import QtCore, QtGui, QtWidgets
import	sip

def     write_py(buff):
        if not buff: return "";

        elem_cnt = 12;
        ret = "";
        for x in range(0, len(buff), elem_cnt):
                data = buff[x:];
                if len(data) >= elem_cnt:
                        data = data[:elem_cnt];
                if x == 0:
                        cstr = "raw_data =  \"";
                else:
                        cstr = "raw_data += \"";
                for b in data:
                        cstr += "\\x%.02x" % ord(b);
                cstr += "\";";
                ret += cstr + "\n";
        ret = ret[:-1];
        return ret;

def     write_c(buff):
        if not buff: return "";
        elem_cnt = 10;

        ret =  "unsigned int  raw_data_len = %d;\n" % len(buff);
        ret += "unsigned char raw_data[] = {\n";
        for x in range(0, len(buff), elem_cnt):
                data = buff[x:];
                if len(data) >= elem_cnt:
                        data = data[:elem_cnt];
                cstr = "        ";
                for b in data:
                        cstr += "0x%.02x, " % ord(b);
                ret += cstr + "\n";
        ret += "};"
        return ret;

def     write_gas(buff):
        if not buff: return "";

        elem_cnt = 12;
        ret = "";
        for x in range(0, len(buff), elem_cnt):
                data = buff[x:];
                if len(data) >= elem_cnt:
                        data = data[:elem_cnt];
                cstr = ".byte                   ";
                for idx,b in enumerate(data):
                        if idx == len(data)-1:
                                cstr += "0x%.02x" % ord(b);
                        else:
                                cstr += "0x%.02x, " % ord(b);
                ret += cstr + "\n";
        ret = ret[:-1];
        return ret;                

def     write_masm(buff):
        if not buff: return "";

        elem_cnt = 12;
        ret = "";
        for x in range(0, len(buff), elem_cnt):
                data = buff[x:];
                if len(data) >= elem_cnt:
                        data = data[:elem_cnt];
                cstr = "db                      ";
                for idx,b in enumerate(data):
                        if idx == len(data)-1:
                                cstr += "0%.02xh" % ord(b);
                        else:
                                cstr += "0%.02xh, " % ord(b);
                ret += cstr + "\n";
        ret = ret[:-1];
        return ret;

def     dump_raw_bytes_py():
        selection, startea, endea = idaapi.read_selection();
        buff = idaapi.get_many_bytes(startea, endea-startea);
        print(write_py(buff));
                
def     dump_raw_bytes_c():
        selection, startea, endea = idaapi.read_selection();
        buff = idaapi.get_many_bytes(startea, endea-startea);
        print(write_c(buff));

def     dump_raw_bytes_gas():
        selection, startea, endea = idaapi.read_selection();
        buff = idaapi.get_many_bytes(startea, endea-startea)
        print(write_gas(buff));        

def     dump_raw_bytes_masm():
        selection, startea, endea = idaapi.read_selection();
        buff = idaapi.get_many_bytes(startea, endea-startea)
        print(write_masm(buff));  

#this is WTF mode when dumping for C patcher, to remember
#easier what instructions are being searched for...
def     dump_raw_bytes_c_asm():
        selection, startea, endea = idaapi.read_selection();
	if selection == False:
		print("dump_selection : Nothing selected");
        	return;
	
	print("unsigned char raw_data[] = {");
	while startea < endea:
		output = "";
		mnemonic = idc.GetDisasm(startea); 
		idaapi.decode_insn(startea);
		size = idaapi.cmd.size;
		buff = idaapi.get_many_bytes(startea, size);
		
		data = " "*8+"".join(["0x%.02x, " % ord(b) for b in buff]); 
		startea += size;
		if startea == endea:
			data = data[:-2];	#wipe , at the end...
		output = data + " " * (64-len(data)) + "// "+mnemonic;
		print(output);
	print("};");
	
class dump_selection_plugin_form(idaapi.PluginForm):
	def	OnCreate(self, form):
		self.parent = self.FormToPyQtWidget(form); #self.FormToPySideWidget(form);
		self.PopulateForm();
	def	PopulateForm(self):
		layout = QtWidgets.QVBoxLayout();
		
		dump_raw_py    = QtWidgets.QPushButton("dump py");
                dump_raw_c     = QtWidgets.QPushButton("dump c");
                dump_raw_c_asm = QtWidgets.QPushButton("dump c asm");
                dump_raw_gas   = QtWidgets.QPushButton("dump gas");
                dump_raw_masm  = QtWidgets.QPushButton("dump masm");
                
		dump_raw_py.clicked.connect(dump_raw_bytes_py);
                dump_raw_c.clicked.connect(dump_raw_bytes_c);
                dump_raw_c_asm.clicked.connect(dump_raw_bytes_c_asm);
                dump_raw_gas.clicked.connect(dump_raw_bytes_gas);
                dump_raw_masm.clicked.connect(dump_raw_bytes_masm);
                
                
		layout.addWidget(dump_raw_py);
        	layout.addWidget(dump_raw_c);
        	layout.addWidget(dump_raw_c_asm);
        	layout.addWidget(dump_raw_gas);
        	layout.addWidget(dump_raw_masm);
        	self.parent.setLayout(layout)	
	def OnClose(self, form):
        	"""
        	Called when the plugin form is closed
        	"""
        	pass
class dump_selection_plugin_t(idaapi.plugin_t):
        flags = 0
        comment     = "Dump selection"
        help        = "Press Ctrl+h to run plugin";
        wanted_name = "dump_selection"
        wanted_hotkey = "Ctrl+h"    
        
        def init(self):
		return idaapi.PLUGIN_KEEP; 
        def run(self, arg):                
        	plg = dump_selection_plugin_form();
		plg.Show("dump selection");
	def term(self):
                pass;
                    
def PLUGIN_ENTRY():
    return dump_selection_plugin_t()
    