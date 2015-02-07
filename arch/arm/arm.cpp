#define LOG_PREFIX "ARM"

#include<stdint.h>
#include<string.h>
#include<assert.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/mman.h>
#include<capstone/arm.h>
#include<memory>

#include"utils.h"
#include"context.h"
#include"state.h"
#include"expr.h"
#include"arm.h"

using namespace symx;
using namespace arm;

namespace arm {

static refExpr imm40,imm41,imm44,imm48;
int initialize() {
	imm40 = BytVec::create_imm(4,0);
	imm41 = BytVec::create_imm(4,1);
	imm44 = BytVec::create_imm(4,4);
	imm48 = BytVec::create_imm(4,8);
        return 0;
}

ARMProbe::ARMProbe(const int fd,const uint64_t _off) : off(_off) {
	struct stat st;
	fstat(fd,&st);
	bin = (uint8_t*)mmap(NULL,st.st_size,PROT_READ,MAP_PRIVATE,fd,0);
}
uint64_t ARMProbe::read_reg(const unsigned int regid) {
	//Temp fixed data
	switch(regid) {
	case ARM_REG_PC:
		return 0x8558;
	case ARM_REG_SP:
		return 0x7FFFFFF0;
	}
	return 0;
}
bool ARMProbe::read_flag(const unsigned int flagid) {
	return false;
}
ssize_t ARMProbe::read_mem(
	const uint64_t addr,
	const uint8_t *buf,
	const size_t len
) {
	memcpy((void*)buf,(void*)(bin + off + addr),len);
	return len;
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
static refExpr get_op_expr(refBlock blk,cs_arm_op *op,uint64_t pc) {
	refExpr ret;
	if(op->type == ARM_OP_IMM) {
		ret = BytVec::create_imm(4,op->imm);
	} else if(op->type == ARM_OP_REG) {
		ret = blk->reg[op->reg];
	} else if(op->type == ARM_OP_MEM) {
		refExpr index;
		if(op->mem.base != ARM_REG_INVALID) {
			ret = blk->reg[op->mem.base];
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
			ret = expr_add(ret,blk->reg[op->mem.disp]);
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
refBlock ARMContext::interpret(
	refProbe _probe,
	uint64_t pc
) {
	int i;
	refARMProbe probe = std::dynamic_pointer_cast<ARMProbe>(_probe);
        refBlock blk = state_create_block(this);
	cs_insn *insn,*ins;
        size_t count;
        size_t idx;
        cs_arm *det;
        cs_arm_op *ops;
	bool end_flag;

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
        
        count = cs_disasm(cs,probe->bin + probe->off + pc,64,pc,0,&insn);
        ins = insn;
	end_flag = false;
	for(idx = 0; idx < count && !end_flag; idx++) {
		info("%s %s\n",ins->mnemonic,ins->op_str);

		pc = ins->address;
                det = &ins->detail->arm;
                ops = det->operands;
		blk->reg[ARM_REG_PC] = BytVec::create_imm(4,pc);
		nr[ARM_REG_PC] = blk->reg[ARM_REG_PC];

                switch(ins->id) {
                case ARM_INS_PUSH:
			xrt = blk->reg[ARM_REG_SP];
			nm = blk->mem;
			for(i = det->op_count - 1; i >= 0; i--) {
				xrt = expr_sub(xrt,imm44);
				xrs = get_op_expr(blk,&ops[i],pc);
				nm = expr_store(nm,xrt,xrs);
			}
			nr[ARM_REG_SP] = xrt;
                        break;
		case ARM_INS_ADD:
			if(det->op_count == 2) {
				xrd = get_op_expr(blk,&ops[0],pc);
				xrs = get_op_expr(blk,&ops[1],pc);
			} else {
				xrd = get_op_expr(blk,&ops[1],pc);
				xrs = get_op_expr(blk,&ops[2],pc);
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
			xrd = get_op_expr(blk,&ops[0],pc);
			xrs = get_op_expr(blk,&ops[1],pc);
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
		case ARM_INS_MOVW:
			nr[ops[0].reg] = get_op_expr(blk,&ops[1],pc);
			break;
		case ARM_INS_MOVT:
			xrd = get_op_expr(blk,&ops[0],pc);
			xrs = BytVec::create_imm(2,ops[1].imm);
			nr[ops[0].reg] = expr_concat(expr_extract(xrd,0,2),xrs);
			break;
		case ARM_INS_STR:
			xrs = get_op_expr(blk,&ops[0],pc);
			xrd = get_op_expr(blk,&ops[1],pc);
			nm = expr_store(blk->mem,xrd,xrs);
			break;
		case ARM_INS_LDR:
			xrs = get_op_expr(blk,&ops[1],pc);
			nr[ops[0].reg] = expr_select(blk->mem,xrs,4);
			break;
		case ARM_INS_CMP:
			xrd = get_op_expr(blk,&ops[0],pc);
			xrs = get_op_expr(blk,&ops[1],pc);
			xrt = expr_sub(xrd,xrs);
			cdt = cond_sl(xrt,imm40);
			nf[ARM_SR_N] = cdt;
			nf[ARM_SR_Z] = cond_eq(xrt,imm40);
			nf[ARM_SR_C] = cond_uge(xrd,xrs);
			nf[ARM_SR_V] = cond_and(
				cond_xor(cond_sl(xrd,imm40),cdt),
				cond_xor(cond_sl(expr_neg(xrs),imm40),cdt));
			break;
		case ARM_INS_BL:
		case ARM_INS_BLX:
			nr[ARM_REG_LR] = BytVec::create_imm(4,pc + ins->size);
		case ARM_INS_B:
			nr[ARM_REG_PC] = get_op_expr(blk,&ops[0],pc);
			end_flag = true;
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
			if(nr[i] != blk->reg[i]) {
				blk->reg[i] = get_cc_expr(
					blk->reg[i],
					nr[i],
					blk->flag,
					det);
				nr[i] = blk->reg[i];
			}
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
		for(i = 0;i < ARM_FLAG_NUM;i++){
			blk->flag[i] = nf[i];
		}
                ins += 1;
	}
	cs_free(insn,count);

        return blk;
}

};
