import sys
import os
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
 
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
 
from shared.utils import read_file_bytes
from shared.logger import get_logger
 
logger = get_logger("decryptor_stub_scanner")
 
def disassemble_file(file_path, base_address=0x1000):
    """
    Disassembles the raw bytes of a file as 32-bit x86 code, starting at a chosen base address.
    Returns a list of Capstone instruction objects.
    """
    data = read_file_bytes(file_path)
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    return list(disassembler.disasm(data, base_address))
 
def find_xor_loops(instructions, window=12):
    """
    Slides a small window across the instruction list and checks for the
    classic decryptor stub pattern: an XOR instruction sitting inside a short loop
    that jumps backward to itself. This pattern is common because a simple
    XOR loop is the easiest way to both encrypt and decrypt the same data.
    """
    suspicious_spots = []
 
    for i in range(len(instructions) - window):
        chunk = instructions[i:i + window]
        has_xor = any(instr.mnemonic == "xor" for instr in chunk)
        has_backward_jump = any(
            instr.mnemonic.startswith("j") and instr.op_str
            and instr.op_str.startswith("0x")
            and int(instr.op_str, 16) < instr.address
            for instr in chunk
        )
        if has_xor and has_backward_jump:
            suspicious_spots.append(chunk[0].address)
 
    return suspicious_spots
 
def scan_for_decryptor_stub(file_path):
    """
    Full check for a given file: disassembles it, then searches for XOR loop patterns.
    Returns True and the list of suspicious addresses if any pattern is found.
    """
    instructions = disassemble_file(file_path)
    spots = find_xor_loops(instructions)
    found = len(spots) > 0
    logger.info(f"{file_path}: decryptor stub pattern found={found}, spots={spots}")
    return found, spots