#TODO write a description for this script
#@author Sai Bharath Vadhyar

#TODO Add User Code Here

from __main__ import currentProgram

program=currentProgram 

from javax.swing import JOptionPane
from ghidra.util import Msg



arrayAddress=JOptionPane.showInputDialog(None,"Enter the address of the array:","array address Input",JOptionPane.QUESTION_MESSAGE)

size=JOptionPane.showInputDialog(None,"Enter the size","length of the string",JOptionPane.QUESTION_MESSAGE)

key=JOptionPane.showInputDialog(None,"Enter the key:","key Input",JOptionPane.QUESTION_MESSAGE)


decrypted_bytes=[]

start_address=toAddr(arrayAddress)

memory=program.getMemory()

for b in range(int(size)):
    byte_value=memory.getByte(start_address.add(b))
    dec_byte=byte_value^ord(key[b%len(key)])
    decrypted_bytes.append(chr(dec_byte))

print(''.join(decrypted_bytes))