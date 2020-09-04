# coding=utf8
import sys
import os
import time
import argparse
import logging
import re
from tempfile import NamedTemporaryFile
from struct import pack

import angr
import claripy
import am_graph
import pyvex

logging.disable(logging.WARNING)


class PrettyPrint:
    @staticmethod
    def info(s):
        return f'[\033[1;36m*\033[0m] {s}'

    @staticmethod
    def warn(s):
        return f'[\033[1;33m!\033[0m] {s}'

    @staticmethod
    def success(s):
        return f'[\033[1;32m+\033[0m] {s}'

    @staticmethod
    def fail(s):
        return f'[\033[1;31m×\033[0m] {s}'

    @staticmethod
    def underline(s):
        return f'\033[4m{s}\033[0m'


# 由于angr中不提供汇编器，因此对需要的指令手写了一个类来提供其汇编
class ASM:
    ARCH_X86 = {"X86", "AMD64"}
    ARCH_ARM = {"ARMEL", "ARMHF"}
    ARCH_ARM64 = {'AARCH64'}

    # x86/x64下jxx指令的op，长度为6
    x86_jx_op = {'a': b'\x87', 'ae': b'\x83', 'b': b'\x82', 'be': b'\x86', 'c': b'\x82', 'e': b'\x84', 'z': b'\x84',
                 'g': b'\x8f', 'ge': b'\x8d', 'l': b'\x8c', 'le': b'\x8e', 'na': b'\x86', 'nae': b'\x82', 'nb': b'\x83',
                 'nbe': b'\x87', 'nc': b'\x83', 'ne': b'\x85', 'ng': b'\x8e', 'nge': b'\x8c', 'nl': b'\x8d',
                 'nle': b'\x8f', 'no': 'b\x81', 'np': b'\x8b', 'ns': b'\x89', 'nz': b'\x85', 'o': b'\x80', 'p': b'\x8a',
                 'pe': b'\x8a', 'po': b'\x8b', 's': b'\x88'}

    # x86/x64下jxx指令的op，长度为2，适用于短偏移
    x86_jx_short_op = {'a': b'w', 'ae': b's', 'b': b'r', 'be': b'v', 'c': b'r', 'e': b't', 'z': b't', 'g': b'\x7f',
                       'ge': b'}', 'l': b'|', 'le': b'~', 'na': b'v', 'nae': b'r', 'nb': b's', 'nbe': b'w', 'nc': b's',
                       'ne': b'u', 'ng': b'~', 'nge': b'|', 'nl': b'}', 'nle': b'\x7f', 'no': b'q', 'np': b'{',
                       'ns': b'y', 'nz': b'u', 'o': b'p', 'p': b'z', 'pe': b'z', 'po': b'{', 's': b'x'}

    @staticmethod
    def x86_jmp(vma, dst):
        """
        提供x86/x64下jmp指令的字节码
        :param vma: 当前指令的地址
        :param dst: 目标地址
        :return: jmp指令字节码
        """
        if dst - vma - 5 == 0:
            return ASM.x86_nop(5)
        if -0x80 <= dst - vma - 2 <= 0x7f:
            return b'\xeb' + pack('<b', dst - vma - 2)
        return b'\xe9' + pack('<i', dst - vma - 5)

    @staticmethod
    def x86_jx(type_name: str, vma, dst):
        """
        提供x86/x64下jxx指令的字节码
        :param type_name: jxx中的'xx'，类型为str
        :param vma: 当前指令地址
        :param dst: 目标地址
        :return: jxx指令字节码
        """
        op = ASM.x86_jx_op.get(type_name)
        if not op:
            raise Exception(f'Can\'t find jxx type: {type_name}')
        if -0x80 <= dst - vma - 2 <= 0x7f:
            op = ASM.x86_jx_short_op.get(type_name)
            return op + pack('<b', dst - vma - 2)
        return b'\x0f' + op + pack('<i', dst - vma - 6)

    @staticmethod
    def x86_nop(length):
        """
        提供x86/x64下指定长度的nop字节码
        :param length: nop长度
        :return: nop字节码
        """
        return b'\x90' * length


# angr cfg中对node的包装，可以轻松得到一些分析所需信息
class SuperNode:
    def __init__(self, node):
        self.node = node
        self.in_degree = 0
        self.out_degree = 0
        self.successors = []
        self.predecessors = []

    def __repr__(self):
        return f'node: {hex(self.node.addr)}, in: {self.in_degree}, out: {self.out_degree}'


# 恢复flow时用到的一个信息结构体
class RecoverInfo:
    def __init__(self, node):
        self.node = node  # 当前节点
        self.is_cond = False  # 是否含有分支
        self.successors = []  # 后继（们）
        self.patch_vma = None  # 开始patch的地址
        self.cond_op = None  # 分支跳转所用的op


# Deflat主类
class DeFlat:
    def __init__(self, binary_name: str, function_addr: int):
        """
        尝试去除ollvm中的flat混淆
        :param binary_name: binary文件名
        :param function_addr: 被混淆的目标函数地址
        """
        # 1.加载程序
        self.p = angr.Project(binary_name, load_options={'auto_load_libs': False})

        # 2.获取函数CFG
        self.whole_cfg = self.p.analyses.CFG()
        self.function_addr = function_addr
        self.func = self.whole_cfg.functions[function_addr]
        self.func.normalize()
        self.cfg = am_graph.to_supergraph(self.func.transition_graph)

        # 3.初始化节点变量
        # 入度为0即序言块
        self.prologue_node = None
        # 出度为0即返回块
        self.ret_node = None
        # 序言的后继即主分发器
        self.main_dispatcher_node = None
        # 主分发器的前驱（除序言外）即预处理器
        self.pre_dispatcher_node = None
        # 预处理器的前驱即真实块
        self.relevant_nodes = []
        # 其余为无用块
        self.nop_nodes = []
        # 除了无用块外的所有块都为有用块
        self.useful_nodes = []
        self.useful_nodes_except_ret = []
        # 存放nodes的信息
        self.nodes_info = {}
        # 存放恢复出来的控制流信息
        self.flows = []
        # 用于记录在恢复flow时指定block的初试state
        # 正常来说没有必要，用于O3混淆下
        self.next_state = None
        # 配置选项
        self.use_unicorn = False

    def run(self):
        """
        去混淆主函数
        :return: None
        """
        print(f'\n\n####################### init node #######################')
        # 初始化节点信息
        self.__init_node()
        print(f'\n\n################ recovering control flow ################')
        # 通过符号执行恢复控制流
        self.__recover_flow()
        # 打印恢复出的控制流
        print(f'\n\n################### recovering result ###################')
        self.__pretty_print_flows()
        # 使用恢复出来的控制流patch程序
        print(f'\n\n######################## patching #######################')
        self.__new_do_patch()
        # self.__do_patch()
        print(f'\n\n########################## done #########################')

    def __new_do_patch(self):
        sym_tbl = set()
        rebuild_asm = '.intel_syntax noprefix\n.section .text\n.global _start\n'
        rebuild_asm += '.type _start, @function\n_start:\n\n'
        rebuild_flows = self.flows.copy()
        ret_flow = RecoverInfo(self.ret_node)
        ret_flow.successors = None
        rebuild_flows.append(ret_flow)
        for f in rebuild_flows:
            print(PrettyPrint.info(f'rebuilding block: {hex(f.node.addr)}'))
            block = self.p.factory.block(f.node.addr, size=f.node.size)
            block_asm = f'block_{hex(f.node.addr)}:\n'
            for ins in block.capstone.insns:
                if 'rip' in ins.op_str:
                    rip_arg = re.search(r'(?P<rip_arg>rip [+-] 0x[0-9a-fA-F]+)', ins.op_str).group('rip_arg')
                    offset = int(rip_arg.replace(' ', '')[3:], 16)
                    addr = ins.address + ins.size
                    target_addr = addr + offset
                    sym_tbl.add(target_addr)
                    block_asm += f'{ins.mnemonic} {ins.op_str.replace(rip_arg, f"rip+sym_{hex(target_addr)}")}\n'
                elif 'call' in ins.mnemonic:
                    addr = int(ins.op_str, 16)
                    sym_tbl.add(addr)
                    block_asm += f'{ins.mnemonic} sym_{hex(addr)}\n'
                elif ins.mnemonic.startswith('j') or ins.mnemonic.startswith('cmov'):
                    break
                else:
                    block_asm += f'{ins.mnemonic} {ins.op_str}\n'
            if f.successors:
                if not f.is_cond:
                    block_asm += f'jmp block_{hex(f.successors[0].addr)}\n\n'
                else:
                    block_asm += f'j{f.cond_op} block_{hex(f.successors[0].addr)}\n'
                    block_asm += f'jmp block_{hex(f.successors[1].addr)}\n\n'
            else:
                block_asm += '\n'
            rebuild_asm += block_asm
        rebuild_asm += '.size _start, .-_start\n'
        for sym_addr in sym_tbl:
            rebuild_asm += f'.section .sec_{hex(sym_addr)}\nsym_{hex(sym_addr)}:\n\n'
        rebuildfile_asm = NamedTemporaryFile(mode='w')
        rebuildfile_asm.write(rebuild_asm)
        rebuildfile_asm.flush()
        rebuildfile_obj = NamedTemporaryFile()
        rebuildfile_elf = NamedTemporaryFile()
        as_cmd = f'as -64 -o {rebuildfile_obj.name} {rebuildfile_asm.name}'
        os.system(as_cmd)
        ld_cmd = f'ld {rebuildfile_obj.name} -o {rebuildfile_elf.name} --section-start=.text={hex(self.function_addr)}'
        for sym_addr in sym_tbl:
            ld_cmd += f' --section-start=.sec_{hex(sym_addr)}={hex(sym_addr)}'
        os.system(ld_cmd)
        new_p = angr.Project(rebuildfile_elf.name, load_options={'auto_load_libs': False})
        new_whole_cfg = new_p.analyses.CFG()
        new_func = new_whole_cfg.functions[self.function_addr]
        new_func.normalize()
        offset = new_p.loader.main_object.addr_to_offset(self.function_addr)
        rebuildfile_elf.seek(offset)
        patch_data = rebuildfile_elf.read(new_func.size)
        binary_name = self.p.loader.main_object.binary_basename
        deflat_binary_name = f'newdeflat_{binary_name}'
        raw_binary_data = bytearray(open(self.p.loader.main_object.binary, 'rb').read())
        patch_start = self.p.loader.main_object.addr_to_offset(self.func.addr)
        patch_size = self.func.size
        raw_binary_data[patch_start:patch_start + patch_size] = ASM.x86_nop(patch_size)
        raw_binary_data[patch_start:patch_start + new_func.size] = patch_data
        open(deflat_binary_name, 'wb').write(raw_binary_data)
        print(PrettyPrint.success(f'write deflat binary to {PrettyPrint.underline(deflat_binary_name)}'))
        rebuildfile_asm.close()
        rebuildfile_obj.close()
        rebuildfile_elf.close()

    def __init_node(self):
        # 初始化nodes_info
        for node in self.cfg.nodes:
            tmp_super_node = SuperNode(node)
            tmp_super_node.in_degree = self.cfg.in_degree(node)
            tmp_super_node.out_degree = self.cfg.out_degree(node)
            tmp_super_node.successors = list(self.cfg.successors(node))
            tmp_super_node.predecessors = list(self.cfg.predecessors(node))
            self.nodes_info[node] = tmp_super_node

        in_degree_zero_nodes = list(filter(
            lambda n: self.nodes_info[n].in_degree == 0,
            self.nodes_info
        ))
        if len(in_degree_zero_nodes) == 0:
            print(PrettyPrint.fail('Can\'t find in_degree == 0 node'))
            exit(1)
        if len(in_degree_zero_nodes) > 1:
            print(PrettyPrint.fail('Find more than one in_degree == 0 nodes'))
            exit(1)
        self.prologue_node = in_degree_zero_nodes[0]
        print(PrettyPrint.success(f'prologue_node: {hex(self.prologue_node.addr)}'))
        out_degree_zero_nodes = list(filter(
            lambda n: self.nodes_info[n].out_degree == 0,
            self.nodes_info
        ))
        if len(out_degree_zero_nodes) == 0:
            print(PrettyPrint.fail('Can\'t find out_degree == 0 node'))
            exit(1)
        if len(out_degree_zero_nodes) > 1:
            print(PrettyPrint.fail('Find more than one out_degree == 0 nodes'))
            exit(1)
        self.ret_node = out_degree_zero_nodes[0]
        print(PrettyPrint.success(f'ret_node: {hex(self.ret_node.addr)}'))
        self.main_dispatcher_node = None
        self.pre_dispatcher_node = None
        self.relevant_nodes = []
        if self.p.arch.name in ASM.ARCH_X86:
            self.__get_x86_relevant_nodes()
        else:
            self.__print_arch_not_support_and_exit()
        print(PrettyPrint.success(f'relevant_nodes: {list(map(lambda x: hex(x.addr), self.relevant_nodes))}'))
        self.nop_nodes = list(self.cfg.nodes)
        self.nop_nodes.remove(self.prologue_node)
        self.nop_nodes.remove(self.ret_node)
        for node in self.relevant_nodes:
            self.nop_nodes.remove(node)
        print(PrettyPrint.success(f'nop_nodes: {list(map(lambda x: hex(x.addr), self.nop_nodes))}'))
        self.useful_nodes = [self.prologue_node, self.ret_node] + self.relevant_nodes
        self.useful_nodes_except_ret = [self.prologue_node] + self.relevant_nodes

    def __get_x86_relevant_nodes(self):
        """
        获取x86/x64架构下的相关块
        由于O3下不能简单通过前驱后继来推出相关块，因此需要编写匹配规则
        :return: None
        """
        for n in self.cfg.nodes:
            if n.addr == 0x40117b:
                continue
            # 1. 跳过序言和ret块
            if n == self.prologue_node or n == self.ret_node:
                continue
            block = self.p.factory.block(n.addr, size=n.size)
            insns = block.capstone.insns
            # 2. 遍历block的指令
            # 2.1 如果指令由j指令或nop开头，直接跳过
            if insns[0].mnemonic.startswith('j') or insns[0].mnemonic == 'nop':
                continue
            # 2.2 如果指令长度大于3，是真实块
            if len(insns) > 3:
                self.relevant_nodes.append(n)
            # 2.3 如果指令长度为3，跳过指令序列为mov,cmp,jxx的块，否则为真实块
            elif len(insns) == 3:
                if insns[0].mnemonic == 'mov' and \
                        insns[1].mnemonic == 'cmp' and \
                        insns[2].mnemonic.startswith('j'):
                    continue
                else:
                    self.relevant_nodes.append(n)
            # 2.4 如果指令长度为2，跳过指令序列为cmp,jxx的块，否则为真实块
            elif len(insns) == 2:
                if insns[0].mnemonic == 'cmp' and \
                        insns[1].mnemonic.startswith('j'):
                    continue
                else:
                    self.relevant_nodes.append(n)
            else:
                self.relevant_nodes.append(n)
        # 3. 把序言块的前驱剔除
        self.relevant_nodes = list(filter(
            lambda n: n not in self.nodes_info[self.prologue_node].successors,
            self.relevant_nodes))

    def __recover_flow(self):
        def hook_node_start(state):
            """
            每个真实块node开头指令的hook回调
            :param state: hook回调时传入的state
            :return: None
            """
            # 如果当前ip不是当前符号指令的起始块，说明成功恢复出一条flow
            if state.solver.eval(state.regs.ip) != self.start_block.addr:
                # 设置terminate block为当前block
                self.terminate_block = self.nodes_start_addr[state.solver.eval(state.regs.ip)]
                # 将目前的state保存下来作为下次terminate block执行时的初始state
                self.next_state = state.copy()
            # 如果是当前ip是起始块，是初次执行跑到的
            # TODO：当然好像也有遇到loop的可能性
            else:
                self.terminate_block = None
                self.next_state = None

        self.nodes_start_addr = {}
        self.flows = []
        for _node in self.useful_nodes:
            self.nodes_start_addr[_node.addr] = _node
        for _addr in self.nodes_start_addr:
            self.p.hook(_addr, hook=hook_node_start)
        # 尝试恢复控制流
        # 在没有O3优化的情况下只需要拿useful_nodes_except_ret一个个跑就行，
        # 但在O3下不能用这条思路，因为每个block并不是完全割裂的，
        # 有些block会利用上个block中的寄存器的值，因此跑这种block时的初始state需要
        # 设置为上次跑flow跑到这个block时的state，通过继承寄存器的值使得其能够正常执行。
        # 目前的思路是维护一个in_process_nodes，且以序言块开头，
        # 序言块跑flow得到的下一个block作为下一个计算flow的对象，保存当前的state，
        # 并将其从新排序到in_process_nodes的首位。
        in_process_nodes = self.useful_nodes_except_ret.copy()
        process_nodes_regs = {}
        process_i = 0
        process_num = len(in_process_nodes)
        while len(in_process_nodes):
            self.start_block = in_process_nodes.pop(0)
            self.terminate_block = None
            print(PrettyPrint.info(f'[{process_i + 1}/{process_num}] dse: {hex(self.start_block.addr)}'))
            tmp_recover_info = RecoverInfo(self.start_block)
            this_block = self.p.factory.block(self.start_block.addr, size=self.start_block.size)
            has_branches = False
            cond_op = None
            cond_addr = None
            for ins in this_block.capstone.insns:
                if self.p.arch.name in ASM.ARCH_X86:
                    if ins.insn.mnemonic.startswith('cmov'):
                        has_branches = True
                        cond_addr = ins.insn.address
                        cond_op = ins.insn.mnemonic[4:]
                    elif ins.insn.mnemonic.startswith('call'):
                        self.p.hook(ins.insn.address, hook=lambda state: None, length=ins.insn.size)
                else:
                    self.__print_arch_not_support_and_exit()
            tmp_recover_info.is_cond = has_branches
            tmp_recover_info.cond_op = cond_op
            if has_branches:
                tmp_recover_info.patch_vma = cond_addr
                for mod_val in [claripy.BVV(1, 1), claripy.BVV(0, 1)]:
                    self.__symbolic_execution(
                        self.start_block.addr,
                        process_nodes_regs.get(self.start_block),
                        cond_addr=cond_addr,
                        modify_value=mod_val
                    )
                    if self.terminate_block:
                        tmp_recover_info.successors.append(self.terminate_block)
                        process_nodes_regs[self.terminate_block] = self.next_state
                        if self.terminate_block in in_process_nodes:
                            in_process_nodes.remove(self.terminate_block)
                            in_process_nodes.insert(0, self.terminate_block)
            else:
                if self.p.arch.name in ASM.ARCH_X86:
                    if this_block.capstone.insns[-1].mnemonic.startswith('j'):
                        if this_block.capstone.insns[-1].mnemonic != 'jmp' and \
                                this_block.capstone.insns[-2].mnemonic == 'cmp':
                            tmp_recover_info.patch_vma = this_block.capstone.insns[-2].address
                        else:
                            tmp_recover_info.patch_vma = this_block.capstone.insns[-1].address
                    elif this_block.capstone.insns[-1].mnemonic == 'nop':
                        tmp_recover_info.patch_vma = this_block.capstone.insns[-1].address
                    else:
                        tmp_recover_info.patch_vma = 0
                else:
                    self.__print_arch_not_support_and_exit()
                self.__symbolic_execution(
                    self.start_block.addr,
                    process_nodes_regs.get(self.start_block)
                )
                if self.terminate_block:
                    tmp_recover_info.successors.append(self.terminate_block)
                    process_nodes_regs[self.terminate_block] = self.next_state
                    if self.terminate_block in in_process_nodes:
                        in_process_nodes.remove(self.terminate_block)
                        in_process_nodes.insert(0, self.terminate_block)
            self.flows.append(tmp_recover_info)
            process_i += 1

    def __symbolic_execution(self, start_addr, old_state=None, cond_addr=None, modify_value=None):
        """
        利用符号执行恢复flow
        :param start_addr: 起始地址
        :param old_state: 执行当前地址的初始state
        :param cond_addr: 条件赋值类指令（如cmov）所在地址
        :param modify_value: 强行修改条件赋值的条件
        :return:
        """

        def statement_inspect(state):
            expressions = list(state.scratch.irsb.statements[state.inspect.statement].expressions)
            if expressions and isinstance(expressions[0], pyvex.expr.ITE):
                state.scratch.temps[expressions[0].cond.tmp] = modify_value

        st = self.p.factory.blank_state(
            addr=start_addr,
            remove_options={angr.sim_options.LAZY_SOLVES}
        ) if not old_state else old_state
        if self.use_unicorn:
            for opt in angr.options.unicorn:
                st.options.add(opt)
        if cond_addr:
            st.inspect.remove_breakpoint('statement', filter_func=lambda b: True)
            st.inspect.make_breakpoint(
                'statement',
                when=angr.state_plugins.inspect.BP_BEFORE,
                instruction=cond_addr,
                action=statement_inspect
            )
        sm = self.p.factory.simgr(st)
        sm.run(until=lambda _self: self.terminate_block)

    def __do_patch(self):
        def vma_to_file_offset(vma):
            return self.p.loader.main_object.addr_to_offset(vma)

        def do_x86_patch():
            print(PrettyPrint.info(f'filling nops'))
            for nop_node in self.nop_nodes:
                patch_data = ASM.x86_nop(nop_node.size)
                faddr = vma_to_file_offset(nop_node.addr)
                raw_binary_data[faddr:faddr + len(patch_data)] = patch_data
            for i, rec_info in enumerate(self.flows):
                print(PrettyPrint.info(f'[{i + 1}/{len(self.flows)}] patching: {hex(rec_info.node.addr)}'))
                if not rec_info.is_cond:
                    if not rec_info.patch_vma:
                        # 是不以jmp结束的真实块，我们也不需要patch
                        continue
                    # 先填充nop
                    patch_data = ASM.x86_nop(rec_info.node.addr + rec_info.node.size - rec_info.patch_vma)
                    faddr = vma_to_file_offset(rec_info.patch_vma)
                    raw_binary_data[faddr:faddr + len(patch_data)] = patch_data
                    # 直接patch jmp
                    patch_data = ASM.x86_jmp(rec_info.patch_vma, rec_info.successors[0].addr)
                    faddr = vma_to_file_offset(rec_info.patch_vma)
                    raw_binary_data[faddr:faddr + len(patch_data)] = patch_data
                else:
                    # 先填充nop
                    patch_data = ASM.x86_nop(rec_info.node.addr + rec_info.node.size - rec_info.patch_vma)
                    faddr = vma_to_file_offset(rec_info.patch_vma)
                    raw_binary_data[faddr:faddr + len(patch_data)] = patch_data
                    # 之后patch分支(从cmov指令开始patch)
                    patch_data1 = ASM.x86_jx(rec_info.cond_op, rec_info.patch_vma, rec_info.successors[0].addr)
                    faddr = vma_to_file_offset(rec_info.patch_vma)
                    raw_binary_data[faddr:faddr + len(patch_data1)] = patch_data1
                    patch_data2 = ASM.x86_jmp(rec_info.patch_vma + len(patch_data1), rec_info.successors[1].addr)
                    faddr = vma_to_file_offset(rec_info.patch_vma + len(patch_data1))
                    raw_binary_data[faddr:faddr + len(patch_data2)] = patch_data2

        binary_name = self.p.loader.main_object.binary_basename
        deflat_binary_name = f'deflat_{binary_name}'
        raw_binary_data = bytearray(open(self.p.loader.main_object.binary, 'rb').read())
        if self.p.arch.name in ASM.ARCH_X86:
            do_x86_patch()
        else:
            self.__print_arch_not_support_and_exit()
        print(PrettyPrint.success(f'write deflat binary to {PrettyPrint.underline(deflat_binary_name)}'))
        open(deflat_binary_name, 'wb').write(raw_binary_data)

    def __pretty_print_flows(self):
        for recover_info in self.flows:
            print(f'{hex(recover_info.node.addr)} : {list(map(lambda x: hex(x.addr), recover_info.successors))}')
        indegree = {f.node.addr: 0 for f in self.flows}
        for recover_info in self.flows:
            for s in recover_info.successors:
                if not indegree.get(s.addr):
                    indegree[s.addr] = 0
                indegree[s.addr] += 1
        print(PrettyPrint.info(f'nodes in_degree: {str({hex(addr): indegree[addr] for addr in indegree})}'))
        count_of_zero_indegree = list(indegree.values()).count(0)
        if count_of_zero_indegree > 1:
            print(PrettyPrint.warn(
                f'find {count_of_zero_indegree} nodes\' indegree == 0, result should be wrong, continue? [y/N]'))
            choice = input()
            if 'y' not in choice.lower():
                exit(0)

    def __print_arch_not_support_and_exit(self):
        print(PrettyPrint.fail(f'Arch {self.p.arch.name} is not supported yet'))
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control flow deflat")
    parser.add_argument("-f", "--file", help="binary to analyze")
    parser.add_argument("--addr", help="address of target function in hex format")
    parser.add_argument("--unicorn", action='store_true', default=False,
                        help="use unicorn (faster but may recover wrong flow)")
    args = parser.parse_args()

    if args.file is None or args.addr is None:
        parser.print_help()
        sys.exit(0)

    t1 = time.perf_counter_ns() / 1000 / 1000 / 1000
    deflat = DeFlat(args.file, int(args.addr, 16))
    if args.unicorn:
        deflat.use_unicorn = True
    deflat.run()
    t2 = time.perf_counter_ns() / 1000 / 1000 / 1000
    print(PrettyPrint.info(f'time cost: {t2 - t1}'))
