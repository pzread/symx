#include<stdint.h>
#include<assert.h>
#include<unistd.h>
#include<capstone/arm.h>

#include"utils.h"
#include"context.h"
#include"state.h"
#include"expr.h"
#include"arm.h"

#define LOG_PREFIX "ARM"

#define err(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);while(1);}
#define info(x,...) {fprintf(stderr,"[%d][" LOG_PREFIX "] " x,getpid(),##__VA_ARGS__);}

static refExpr imm40,imm41,imm44,imm48;

int arm_init(Context *ctx) {
	ctx->reg_size = ARM_REG_SIZE;
	ctx->num_reg = ARM_REG_ENDING;
	ctx->num_flag = ARM_FLAG_NUM;
	imm40 = BytVec::create_imm(4,0);
	imm41 = BytVec::create_imm(4,1);
	imm44 = BytVec::create_imm(4,4);
	imm48 = BytVec::create_imm(4,8);
        return 0;
}

static refExpr get_op_expr(refBlock blk,cs_arm_op *op,uint64_t pc) {
	refExpr ret;
	if(op->type == ARM_OP_IMM) {
		ret = BytVec::create_imm(4,op->imm);
	}else if(op->type == ARM_OP_REG) {
		ret = blk->reg[op->reg];
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
static refExpr get_cc_expr(refExpr expr,cs_arm *det) {
	if(det->cc == ARM_CC_INVALID || det->cc == ARM_CC_AL) {
		return expr;
	}
	err("TODO: get_cc_expr\n");
	return expr;
}
static refMem get_cc_mem(refMem mem,cs_arm *det) {
	if(det->cc == ARM_CC_INVALID || det->cc == ARM_CC_AL) {
		return mem;
	}
	err("TODO: get_cc_mem\n");
	return mem;
}
refBlock arm_emit(Context *ctx,uint8_t *bin,uint64_t pc,off_t off) {
	int i;
        refBlock blk = state_create_block(ctx);
	cs_insn *insn,*ins;
        size_t count;
        size_t idx;
        cs_arm *det;
        cs_arm_op *ops;

	refExpr nr[ARM_REG_ENDING];
	refMem nm;
	refExpr xrd,xrs,xrt;
	refCond cdt;

	nm = blk->mem;
	for(i = 0;i < ARM_REG_ENDING;i++){
		nr[i] = blk->reg[i];
	}
        
        count = cs_disasm(ctx->cs,bin + off,64,pc,0,&insn);
        ins = insn;
	for(idx = 0; idx < 10; idx++) {
		info("%s %s\n",ins->mnemonic,ins->op_str);

		pc = ins->address;
                det = &ins->detail->arm;
                ops = det->operands;

                switch(ins->id) {
                case ARM_INS_PUSH:
			xrt = blk->reg[ARM_REG_SP];
			for(i = det->op_count - 1; i >= 0; i--) {
				xrt = expr_sub(xrt,imm44);
				xrs = get_op_expr(blk,&ops[i],pc);
				nm = expr_store(blk->mem,xrt,xrs);
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
			xrs = BytVec::create_imm(2,ops[1].imm << 16);
			nr[ops[0].reg] = expr_concat(expr_extract(xrd,0,4),xrs);
			break;
		default:
			err("TODO: inst\n");
			break;
                }

		if(nm != blk->mem) {
			blk->mem = get_cc_mem(nm,det);
			nm = blk->mem;
		}
		for(i = 0;i < ARM_REG_ENDING;i++){
			if(nr[i] != blk->reg[i]) {
				blk->reg[i] = get_cc_expr(nr[i],det);
				nr[i] = blk->reg[i];
			}
		}

                ins += 1;
	}
	cs_free(insn,count);

        return blk;
}
