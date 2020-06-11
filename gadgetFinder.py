import capstone as cs


INPUT_FILE = "calc"
START_SEC_OFFSET = 0x2d0
END_SEC_OFFSET = 0x76954 + START_SEC_OFFSET #lenght of section + start
VA = 0x8048000
e = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32) 	# Change to 64 when bin of 64 bit


def dis(bin,address):
  l = []
  for d in e.disasm(bin,address):
    op_str = d.op_str
    mnemonic = d.mnemonic
    address = d.address
		
    l.append((op_str,mnemonic,address))

    if(mnemonic == "ret" or mnemonic == "int"):
      return l

  return []

FILE = open(INPUT_FILE, "rb").read()

for i in range(START_SEC_OFFSET, END_SEC_OFFSET):
  d = dis(FILE[i:i+30],VA+i)
  if len(d) != 0:
    print("0x%x:"%(VA+i))
    for j in d:
      print("\t 0x%x:\t%s %s"%(j[2],j[1],j[0]))
