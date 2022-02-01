import json
import os
import random
import struct


class NimSysCalls(object):
    def __init__(self):
        self.seed = random.randint(2 ** 28, 2 ** 32 - 1)
        self.prototypes = json.load(open(os.path.join(os.path.dirname(__file__), "data", "prototypes.json")))
        self.functions = "functions.txt"

    def read_functions_from_file(self):
        try:
            with open(self.functions, 'r', encoding='utf8') as functionsIn:
                functionsList = [ 'Nt' + f[2:] if f[:2] == 'Zw' else f for f in
                                 [l.strip() for l in functionsIn.readlines()]]
                print('[i] {}.'.format(functionsList))
                return functionsList
        except:
            print('[i] Function filter file "{}" not found. So not filtering functions.'.format(functionsList))

    def _get_function_hash(self, function_name):
        hash = self.seed
        name = 'Zw' + function_name[2:] + '\0' if function_name[:2] == 'Nt' else function_name + '\0'
        ror8 = lambda v: ((v >> 8) & (2 ** 32 - 1)) | ((v << 24) & (2 ** 32 - 1))
        for segment in [s for s in [name[i:i + 2] for i in range(len(name))] if len(s) == 2]:
            partial_name_short = struct.unpack('<H', segment.encode())[0]
            hash ^= partial_name_short + ror8(hash)
        return hex(hash)

    def generate(self, function_names, basename='syscalls'):
        if not function_names:
            function_names = list(self.prototypes.keys())
        with open(f'{basename}.nim', 'wb') as output_header:
            with open(os.path.join(os.path.dirname(__file__), "data", "base.nim"), 'rb') as basenim:
                output_header.write(basenim.read().replace(b'HASH_CODE',hex(self.seed).encode() + b'\'u32') + b'\n')
            for function_name in function_names:
                output_header.write((self._get_function_prototype(function_name) + '\n').encode())
            output_header.write( b'''
when isMainModule:
    SaveSysCallsStub()
                    ''')
        print('[i] The nim code is in syscalls.nim')
    def _get_function_prototype(self, function_name):
        if function_name not in self.prototypes:
            raise ValueError('Invalid function name provided.')

        num_params = len(self.prototypes[function_name]['params'])
        signature = f'proc m{function_name}('
        if num_params:
            for i in range(num_params):
                param = self.prototypes[function_name]['params'][i]
                signature += f'{param["name"]}:{param["type"].split(" ")[0]}'
                signature += ',' if i < num_params - 1 else '): NTSTATUS {.asmNoStackFrame.} ='
        else:
            signature += '): NTSTATUS {.asmNoStackFrame.} ='
        hash = self._get_function_hash(function_name)
        signature += f'''
    asm """
    push rcx
    push rdx
    push r8
    push r9
    sub rsp, 0x28
    mov rcx, {hash}
    call `getCode`
    add rsp, 0x28
    pop r9
    pop r8
    pop rdx
    pop rcx
    mov r10,rcx
    movzx rax,al
    syscall
    ret
    """
                    '''
        return signature


if __name__ == '__main__':
    print('''  __ _  _____   _____ _ __(_)
 / _` |/ _ \ \ / / _ \ '__| |
| (_| |  __/\ V /  __/ |  | |
 \__,_|\___| \_/ \___|_| _/ |
                        |__/ 
                NimSysCalls    
                @aeverj 2022
''')
    p = NimSysCalls()
    p.generate(p.read_functions_from_file())
