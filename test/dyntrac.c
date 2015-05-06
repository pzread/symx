#ifndef LINUX
#define LINUX
#endif
#ifndef X86_32
#define X86_32
#endif

#include<stdint.h>
#include<dr_api.h>

static void basic_block_call() {
    
}
static dr_emit_flags_t event_basic_block(
	void *drctx,
	void *tag,
	instrlist_t *bb,
	bool for_trace,
	bool translating
) {
    /*
    dr_mutex_lock(ins_count_lock);
    ins_count += num_ins;
    dr_mutex_unlock(ins_count_lock);

    dr_save_arith_flags(drcontext,bb,where,SPILL_SLOT_1);
    instrlist_meta_preinsert(bb,where,LOCK(
		INSTR_CREATE_add(drcontext,
		    OPND_CREATE_ABSMEM((uint8_t*)&ins_count,OPSZ_8),
		    OPND_CREATE_INT_32OR8(num_ins))));
    dr_restore_arith_flags(drcontext,bb,where,SPILL_SLOT_1);
    */

    instr_t *where = instrlist_first(bb);
    dr_mem_info_t meminfo;

    dr_printf("0x%08x\n",instr_get_app_pc(where));
    if(dr_query_memory_ex(instr_get_app_pc(where),&meminfo) &&
	    !dr_memory_is_dr_internal(meminfo.base_pc)) {
	dr_printf("0x%08x 0x%08x\n",meminfo.base_pc,meminfo.size);
    }

    dr_insert_clean_call(drctx,bb,where,basic_block_call,false,0);

    return DR_EMIT_DEFAULT;
}
static void event_exit() {}

DR_EXPORT void dr_init(client_id_t id) {
    dr_register_exit_event(event_exit);
    dr_register_bb_event(event_basic_block);
}
