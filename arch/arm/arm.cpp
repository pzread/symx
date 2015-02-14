#define LOG_PREFIX "ARM"

#include<stdint.h>
#include<string.h>
#include<assert.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<capstone/arm.h>
#include<memory>
#include<vector>

#include"utils.h"
#include"context.h"
#include"state.h"
#include"expr.h"
#include"arm.h"

using namespace symx;
using namespace arm;

namespace arm {

static refBytVec imm40,imm41,imm44,imm48,imm4FFFF,imm4FFFFFFFE;
static refBytVec insmod_arm,insmod_thumb ;
int initialize() {
	imm40 = BytVec::create_imm(4,0x0);
	imm41 = BytVec::create_imm(4,0x1);
	imm44 = BytVec::create_imm(4,0x4);
	imm48 = BytVec::create_imm(4,0x8);
	imm4FFFF = BytVec::create_imm(4,0xFFFF);
	imm4FFFFFFFE = BytVec::create_imm(4,0xFFFFFFFE);

	insmod_arm = BytVec::create_imm(4,CS_MODE_ARM);
	insmod_thumb = BytVec::create_imm(4,CS_MODE_THUMB);

        return 0;
}

ARMProbe::ARMProbe(pid_t _pid,int fd,uint64_t _off) : pid(_pid),off(_off) {
	struct stat st;
	fstat(fd,&st);
	bin = (uint8_t*)mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
}
uint64_t ARMProbe::read_reg(const unsigned int regid,bool *symbol) {
	//for test
	*symbol = false;
	switch(regid) {
	case ARM_REG_R0:
		*symbol = true;
		return 0x0;
	case ARM_REG_R1:
		return 0XBEAFF100;
	case ARM_REG_R2:
		return 0xBEAFF200;
	case ARM_REG_R3:
		return 0x102E1;
	case ARM_REG_R4:
		return 0x0;
	case ARM_REG_R5:
		return 0x0;
	case ARM_REG_R6:
		return 0x0;
	case ARM_REG_R7:
		return 0x0;
	case ARM_REG_R8:
		return 0x0;
	case ARM_REG_R9:
		return 0x0;
	case ARM_REG_R10:
		return 0x0;
	case ARM_REG_R11:
		return 0x0;
	case ARM_REG_R12:
		return 0x0;
	case ARM_REG_PC:
		return 0x102E0;
	case ARM_REG_SP:
		return 0xBEAFF000;
	case ARM_REG_LR:
		return 0xDEADEEF0;
	}
	return 0;
}
bool ARMProbe::read_flag(const unsigned int flagid) {
	//for test
	switch(flagid) {
	case ARM_SR_N:
		return false;
	case ARM_SR_Z:
		return true;
	case ARM_SR_C:
		return true;
	case ARM_SR_V:
		return false;
	}
	return false;
}
ssize_t ARMProbe::read_mem(
	const uint64_t addr,
	const uint8_t *buf,
	const size_t len
) {
	//for test
	if(addr >= 0xBEAFF000) {
		if(len != 1) {
			err("unhandled argv\n");
		}
		uint32_t val = 0xBEAFF000 + \
			((addr & (~3)) - 0xBEAFF000 + 1) * 0x10000;
		memcpy((void*)buf,(char*)(&val) + (addr & 3),1);
	} else {
		memcpy((void*)buf,(void*)(bin + off + addr),len);
	}
	return len;
}
int ARMProbe::get_insmd() {
	//for test
	return CS_MODE_THUMB;
}
std::vector<MemPage> ARMProbe::get_mem_map() {
	std::vector<MemPage> mem_map;
	//for test
	mem_map.push_back(MemPage(0x10000,PAGE_READ | PAGE_EXEC | PAGE_PROBE));
	mem_map.push_back(MemPage(
		0xBEAFF000,
		PAGE_READ | PAGE_EXEC | PAGE_PROBE));

	return mem_map;
}

ARMContext::ARMContext(Solver *_solver) : Context(
	_solver,
	ARM_REG_SIZE,
	ARM_REG_ENDING,
	ARM_FLAG_NUM,
	ARM_REG_PC
) {
	cs_open(CS_ARCH_ARM,CS_MODE_THUMB,&cs);
	cs_option(cs,CS_OPT_DETAIL,CS_OPT_ON);
}
static refExpr get_relative_pc(const ProgCtr &pc) {
	if(pc.insmd == CS_MODE_THUMB) {
		return BytVec::create_imm(4,pc.rawpc + 4);
	} else {
		return BytVec::create_imm(4,pc.rawpc + 8);
	}
}
static refExpr get_op_expr(
	const std::pair<refBlock,ProgCtr> &meta,
	cs_arm_op *op
) {
	refExpr ret;
	
	auto blk = meta.first;
	auto &pc = meta.second;

	if(op->type == ARM_OP_IMM) {
		ret = BytVec::create_imm(4,op->imm);
	} else if(op->type == ARM_OP_REG) {
		if(op->reg == ARM_REG_PC) {
			ret = get_relative_pc(pc);
		} else {
			ret = blk->reg[op->reg];
		}
	} else if(op->type == ARM_OP_MEM) {
		refExpr index;
		if(op->mem.base != ARM_REG_INVALID) {
			if(op->mem.base == ARM_REG_PC) {
				ret = get_relative_pc(pc);
			} else {
				ret = blk->reg[op->mem.base];
			}
		} else {
			ret = BytVec::create_imm(4,0);
		}
		if(op->mem.index != ARM_REG_INVALID) {
			if(op->mem.scale == 1) {
				ret = expr_add(ret,blk->reg[op->mem.index]);
			} else {
				ret = expr_add(ret,expr_mul(
					blk->reg[op->mem.index],
					BytVec::create_imm(4,op->mem.scale)));
			}
		}
		if(op->mem.disp != 0) {
			ret = expr_add(ret,BytVec::create_imm(4,op->mem.disp));
		}
	}

	switch(op->shift.type) {
	case ARM_SFT_INVALID:
		break;
	default:
		err("TODO: shift\n");
		break;
	}

	return ret;
}
static refExpr get_cc_expr(
	const refExpr old_expr,
	const refExpr new_expr,
	const refCond flag[],
	cs_arm *det
) {
	refExpr ret_expr;

	switch(det->cc) {
	case ARM_CC_INVALID:
	case ARM_CC_AL:
		ret_expr = new_expr;
		break;
	case ARM_CC_EQ:
		ret_expr = expr_ite(flag[ARM_SR_Z],new_expr,old_expr);
		break;
	case ARM_CC_NE:
		ret_expr = expr_ite(flag[ARM_SR_Z],old_expr,new_expr);
		break;
	case ARM_CC_HS:
		ret_expr = expr_ite(flag[ARM_SR_C],new_expr,old_expr);
		break;
	case ARM_CC_LO:
		ret_expr = expr_ite(flag[ARM_SR_C],old_expr,new_expr);
		break;
	case ARM_CC_MI:
		ret_expr = expr_ite(flag[ARM_SR_N],new_expr,old_expr);
		break;
	case ARM_CC_PL:
		ret_expr = expr_ite(flag[ARM_SR_N],old_expr,new_expr);
		break;
	case ARM_CC_VS:
		ret_expr = expr_ite(flag[ARM_SR_V],new_expr,old_expr);
		break;
	case ARM_CC_VC:
		ret_expr = expr_ite(flag[ARM_SR_V],old_expr,new_expr);
		break;
	case ARM_CC_HI:
		ret_expr = expr_ite(
			cond_and(flag[ARM_SR_C],cond_not(flag[ARM_SR_Z])),
			new_expr,
			old_expr);
		break;
	case ARM_CC_LS:
		ret_expr = expr_ite(
			cond_and(flag[ARM_SR_C],cond_not(flag[ARM_SR_Z])),
			old_expr,
			new_expr);
		break;
	case ARM_CC_GE:
		ret_expr = expr_ite(
			cond_xor(flag[ARM_SR_N],flag[ARM_SR_V]),
			old_expr,
			new_expr);
		break;
	case ARM_CC_LT:
		ret_expr = expr_ite(
			cond_xor(flag[ARM_SR_N],flag[ARM_SR_V]),
			new_expr,
			old_expr);
		break;
	case ARM_CC_GT:
		ret_expr = expr_ite(
			cond_or(flag[ARM_SR_Z],
				cond_xor(flag[ARM_SR_N],flag[ARM_SR_V])),
			old_expr,
			new_expr);
		break;
	case ARM_CC_LE:
		ret_expr = expr_ite(
			cond_or(flag[ARM_SR_Z],
				cond_xor(flag[ARM_SR_N],flag[ARM_SR_V])),
			new_expr,
			old_expr);
		break;
	}
	return ret_expr;
}
static refCond get_cc_cond(
	const refCond old_cond,
	const refCond new_cond,
	const refCond flag[],
	cs_arm *det
) {
	refCond ret_cond;

	switch(det->cc) {
	case ARM_CC_INVALID:
	case ARM_CC_AL:
		ret_cond = new_cond;
		break;
	case ARM_CC_EQ:
		ret_cond = cond_ite(flag[ARM_SR_Z],new_cond,old_cond);
		break;
	case ARM_CC_NE:
		ret_cond = cond_ite(flag[ARM_SR_Z],old_cond,new_cond);
		break;
	case ARM_CC_HS:
		ret_cond = cond_ite(flag[ARM_SR_C],new_cond,old_cond);
		break;
	case ARM_CC_LO:
		ret_cond = cond_ite(flag[ARM_SR_C],old_cond,new_cond);
		break;
	case ARM_CC_MI:
		ret_cond = cond_ite(flag[ARM_SR_N],new_cond,old_cond);
		break;
	case ARM_CC_PL:
		ret_cond = cond_ite(flag[ARM_SR_N],old_cond,new_cond);
		break;
	case ARM_CC_VS:
		ret_cond = cond_ite(flag[ARM_SR_V],new_cond,old_cond);
		break;
	case ARM_CC_VC:
		ret_cond = cond_ite(flag[ARM_SR_V],old_cond,new_cond);
		break;
	case ARM_CC_HI:
		ret_cond = cond_ite(
			cond_and(flag[ARM_SR_C],cond_not(flag[ARM_SR_Z])),
			new_cond,
			old_cond);
		break;
	case ARM_CC_LS:
		ret_cond = cond_ite(
			cond_and(flag[ARM_SR_C],cond_not(flag[ARM_SR_Z])),
			old_cond,
			new_cond);
		break;
	case ARM_CC_GE:
		ret_cond = cond_ite(
			cond_xor(flag[ARM_SR_N],flag[ARM_SR_V]),
			old_cond,
			new_cond);
		break;
	case ARM_CC_LT:
		ret_cond = cond_ite(
			cond_xor(flag[ARM_SR_N],flag[ARM_SR_V]),
			new_cond,
			old_cond);
		break;
	case ARM_CC_GT:
		ret_cond = cond_ite(
			cond_or(flag[ARM_SR_Z],
				cond_xor(flag[ARM_SR_N],flag[ARM_SR_V])),
			old_cond,
			new_cond);
		break;
	case ARM_CC_LE:
		ret_cond = cond_ite(
			cond_or(flag[ARM_SR_Z],
				cond_xor(flag[ARM_SR_N],flag[ARM_SR_V])),
			new_cond,
			old_cond);
		break;
	}
	return ret_cond;
}
refBlock ARMContext::interpret(refProbe _probe,const ProgCtr &entry_pc) {
	int i;
	refARMProbe probe = std::dynamic_pointer_cast<ARMProbe>(_probe);
        refBlock blk = state_create_block(this,entry_pc);
	cs_insn *insn,*ins;
        size_t count;
        size_t idx;
        cs_arm *det;
        cs_arm_op *ops;
	bool end_flag;

	bool branch_flag;
	refExpr nr[ARM_REG_ENDING];
	refExpr nm,xrd,xrs,xrt;
	refCond nf[4];
	refCond cdt;
	
	nm = blk->mem;
	for(i = 0;i < ARM_REG_ENDING;i++){
		nr[i] = blk->reg[i];
	}
	for(i = 0;i < ARM_FLAG_NUM;i++) {
		nf[i] = blk->flag[i];
	}
	blk->next_insmd = BytVec::create_imm(4,entry_pc.insmd);
        
	cs_option(cs,CS_OPT_MODE,entry_pc.insmd);
        count = cs_disasm(
		cs,
		probe->bin + probe->off + entry_pc.rawpc,
		64,
		entry_pc.rawpc,
		0,
		&insn);

        ins = insn;
	end_flag = false;
	for(idx = 0; idx < count && !end_flag; idx++) {
		info("0x%08lx %s %s\n",ins->address,ins->mnemonic,ins->op_str);

		auto pc = ProgCtr(ins->address,entry_pc.insmd);
		auto meta = std::make_pair(blk,pc);
                det = &ins->detail->arm;
                ops = det->operands;
		blk->reg[ARM_REG_PC] = BytVec::create_imm(4,pc.rawpc);
		nr[ARM_REG_PC] = blk->reg[ARM_REG_PC];
		branch_flag = false;

                switch(ins->id) {
                case ARM_INS_PUSH:
			xrt = blk->reg[ARM_REG_SP];
			nm = blk->mem;
			for(i = det->op_count - 1; i >= 0; i--) {
				xrt = expr_sub(xrt,imm44);
				xrs = get_op_expr(meta,&ops[i]);
				nm = expr_store(nm,xrt,xrs);
			}
			nr[ARM_REG_SP] = xrt;
                        break;
		case ARM_INS_POP:
			xrt = blk->reg[ARM_REG_SP];
			for(i = 0; i < det->op_count; i++) {
				nr[ops[i].reg] = expr_select(blk->mem,xrt,4);
				xrt = expr_add(xrt,imm44);
			}
			nr[ARM_REG_SP] = xrt;
		case ARM_INS_ADD:
			if(det->op_count == 2) {
				xrd = get_op_expr(meta,&ops[0]);
				xrs = get_op_expr(meta,&ops[1]);
			} else {
				xrd = get_op_expr(meta,&ops[1]);
				xrs = get_op_expr(meta,&ops[2]);
			}
			nr[ops[0].reg] = expr_add(xrd,xrs);
			/*
			cond_sl(xrt,imm40);
			cond_eq(xrt,imm40);
			cond_uge(xrd,expr_neg(xrs));

			cdt = cond_sl(xrt,imm40);
			cond_and(
				cond_xor(cond_sl(xrd,imm40),cdt),
				cond_xor(cond_sl(xrs,imm40),cdt));
			*/
			break;
		case ARM_INS_SUB:
			xrd = get_op_expr(meta,&ops[0]);
			xrs = get_op_expr(meta,&ops[1]);
			nr[ops[0].reg] = expr_sub(xrd,xrs);
			/*
			if(ins->id == ARM_INS_SUBS){
				cdt = cond_sl(xrt,imm40);
				cond_sl(xrt,imm40);
				cond_eq(xrt,imm40);
				cond_uge(xrd,xrs);
				cond_and(
					cond_xor(cond_sl(xrd,imm40),cdt),
					cond_xor(
						cond_sl(expr_neg(xrs),imm40),
						cdt));
			}
			*/
			break;
		case ARM_INS_MOV:
			nr[ops[0].reg] = get_op_expr(meta,&ops[1]);
			break;
		case ARM_INS_MOVW:
			assert(ops[1].type == ARM_OP_IMM);
			nr[ops[0].reg] = BytVec::create_imm(
				4,
				(ops[1].imm & 0xFFFF));
			break;
		case ARM_INS_MOVT:
			assert(ops[1].type == ARM_OP_IMM);
			xrd = get_op_expr(meta,&ops[0]);
			xrs = BytVec::create_imm(2,ops[1].imm);
			nr[ops[0].reg] = expr_concat(expr_extract(xrd,0,2),xrs);
			break;
		case ARM_INS_STR:
		case ARM_INS_STRB:
			xrs = get_op_expr(meta,&ops[0]);
			xrd = get_op_expr(meta,&ops[1]);
			if(ins->id == ARM_INS_STR) {
				nm = expr_store(blk->mem,xrd,xrs);
			} else {
				nm = expr_store(
					blk->mem,
					xrd,
					expr_extract(xrs,0,1));
			}
			break;
		case ARM_INS_LDR:
		case ARM_INS_LDRB:
			xrs = get_op_expr(meta,&ops[1]);
			if(ins->id == ARM_INS_LDR) {
				nr[ops[0].reg] = expr_select(blk->mem,xrs,4);
			} else {
				nr[ops[0].reg] = expr_zext(
					expr_select(blk->mem,xrs,1),
					4);
			}
			break;
		case ARM_INS_CMP:
			xrd = get_op_expr(meta,&ops[0]);
			xrs = get_op_expr(meta,&ops[1]);
			xrt = expr_sub(xrd,xrs);
			cdt = cond_sl(xrt,imm40);
			nf[ARM_SR_N] = cdt;
			nf[ARM_SR_Z] = cond_eq(xrt,imm40);
			nf[ARM_SR_C] = cond_uge(xrd,xrs);
			nf[ARM_SR_V] = cond_and(
				cond_xor(cond_sl(xrd,imm40),cdt),
				cond_xor(cond_sl(expr_neg(xrs),imm40),cdt));
			break;
		case ARM_INS_TBB:
			xrs = get_op_expr(meta,&ops[0]);
			xrt = expr_zext(expr_select(blk->mem,xrs,1),4);
			nr[ARM_REG_PC] = expr_add(
				get_relative_pc(pc),
				expr_shl(xrt,imm41));
			branch_flag = true;
			break;
		case ARM_INS_CBZ:
		case ARM_INS_CBNZ:
			xrs = get_op_expr(meta,&ops[0]);
			xrd = get_op_expr(meta,&ops[1]);
			cdt = cond_eq(xrs,imm40);
			if(ins->id == ARM_INS_CBZ) {
				nr[ARM_REG_PC] = expr_ite(
					cdt,
					xrd,
					BytVec::create_imm(
						4,
						pc.rawpc + ins->size));
			} else {
				nr[ARM_REG_PC] = expr_ite(
					cdt,
					BytVec::create_imm(
						4,
						pc.rawpc + ins->size),
					xrd);
			}
			branch_flag = true;
			break;
		case ARM_INS_BL:
		case ARM_INS_BLX:
			if(pc.insmd == CS_MODE_THUMB) {
				xrt = BytVec::create_imm(
					4,
					((pc.rawpc + ins->size) | 1));
			} else {
				xrt = BytVec::create_imm(
					4,
					(pc.rawpc + ins->size));
			}
			nr[ARM_REG_LR] = xrt;
		case ARM_INS_B:
		case ARM_INS_BX:
			xrd = get_op_expr(meta,&ops[0]);
			if(ins->id == ARM_INS_B || ins->id == ARM_INS_BL) {
				branch_flag = true;
			}
			nr[ARM_REG_PC] = xrd;
			break;
		default:
			err("TODO: inst\n");
			break;
                }

		if(nm != blk->mem) {
			blk->mem = get_cc_expr(blk->mem,nm,blk->flag,det);
			nm = blk->mem;
		}
		for(i = 0;i < ARM_REG_ENDING;i++){
			if(nr[i] != blk->reg[i] && i != ARM_REG_PC) {
				blk->reg[i] = get_cc_expr(
					blk->reg[i],
					nr[i],
					blk->flag,
					det);
				nr[i] = blk->reg[i];
			}
		}
		if(nr[ARM_REG_PC] != blk->reg[ARM_REG_PC]) {
			xrd = nr[ARM_REG_PC];
			if(branch_flag == false) {
				//handle mode change
				xrt = expr_ite(
					cond_eq(expr_and(xrd,imm41),imm41),
					insmod_thumb,
					insmod_arm);
				blk->next_insmd = get_cc_expr(
					blk->next_insmd,
					xrt,
					blk->flag,
					det);
				xrd = expr_and(xrd,imm4FFFFFFFE);
			}
			blk->reg[ARM_REG_PC] = get_cc_expr(
				BytVec::create_imm(4,pc.rawpc + ins->size),
				xrd,
				blk->flag,
				det);
			nr[ARM_REG_PC] = blk->reg[ARM_REG_PC];
			end_flag = true;
		}
		for(i = 0;i < ARM_FLAG_NUM;i++){
			if(nf[i] != blk->flag[i]) {
				nf[i] = get_cc_cond(
					blk->flag[i],
					nf[i],
					blk->flag,
					det);
			}
		}
		//flag are always update at last
		for(i = 0;i < ARM_FLAG_NUM;i++){
			blk->flag[i] = nf[i];
		}

                ins += 1;
	}
	cs_free(insn,count);

        return blk;
}

};
