#include <asm/kvm.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include "utils.h"
#include "verify_state.h"

#if !defined(__x86_64__) || !defined(__linux__)
#error "This virtual machine requires Linux/x86_64."
#endif

#include <asm/bootparam.h>
#include <asm/e820.h>

#include <fcntl.h>
#include <linux/kvm.h>
#include <linux/kvm_para.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "err.h"
#include "pci.h"
#include "serial.h"
#include "virtio-pci.h"
#include "vm.h"




// this file contain fucntions for verifying that two KVM structures are 
// identical.  This is used to verify that the state of the KVM structures
// is identical between the parent and the child.


void print_kvm_segment(struct kvm_segment *seg) {
    printf("base     = 0x%llx,\t", seg->base);
    printf("limit    = 0x%x,\t", seg->limit);
    printf("selector = 0x%x,\t", seg->selector);
    printf("type     = 0x%x,\t", seg->type);
    printf("present  = %d,\t", seg->present);
    printf("dpl      = %d,\t", seg->dpl);
    printf("db       = %d,\t", seg->db);
    printf("s        = %d,\t", seg->s);
    printf("l        = %d,\t", seg->l);
    printf("g        = %d,\t", seg->g);
    printf("avl      = %d,\t", seg->avl);
    printf("unusable = %d,\t", seg->unusable);
    printf("padding  = %d\n", seg->padding);
}
void print_kvm_dtable(struct kvm_dtable *dtable) {
    printf("base   = 0x%llx,\t", dtable->base);
    printf("limit  = 0x%x,\t", dtable->limit);
    printf("padding = [%d, %d, %d]\n", dtable->padding[0], dtable->padding[1], dtable->padding[2]);
}

static void print_sregs(struct kvm_sregs *sregs) {
    printf("CS=>\n");
    print_kvm_segment(&sregs->cs);
    printf("DS=>\n");
    print_kvm_segment(&sregs->ds);
    printf("ES=>\n");
    print_kvm_segment(&sregs->es);
    printf("FS=>\n");
    print_kvm_segment(&sregs->fs);
    printf("GS=>\n");
    print_kvm_segment(&sregs->gs);
    printf("SS=>\n");
    print_kvm_segment(&sregs->ss);
    printf("TR=>\n");
    print_kvm_segment(&sregs->tr);
    printf("LDT=>\n");
    print_kvm_segment(&sregs->ldt);
    printf("GDT=>\n");
    print_kvm_dtable(&sregs->gdt);
    printf("IDT=>\n");
    print_kvm_dtable(&sregs->idt);

    printf("cr0      = 0x%llx\n", sregs->cr0);
    printf("cr2      = 0x%llx\n", sregs->cr2);
    printf("cr3      = 0x%llx\n", sregs->cr3);
    printf("cr4      = 0x%llx\n", sregs->cr4);
    printf("cr8      = 0x%llx\n", sregs->cr8);
    printf("efer     = 0x%llx\n", sregs->efer);
    printf("apic_base = 0x%llx\n", sregs->apic_base);
    printf("interrupt_bitmap = { ");
    for (int i = 0; i < KVM_NR_INTERRUPTS / 64; i++) {
        printf("%016llx ", sregs->interrupt_bitmap[i]);
    }
    printf("}\n");

}

void print_clock_data(struct kvm_clock_data *clk) {
    
}


int compare_state(int vmfd, int vcpufd, pre_fork_state_t *prefork_state){
    int ret = 0;
    
    ret = ret | compare_regs(vcpufd, prefork_state->regs);
    ret = ret | compare_sregs(vcpufd, prefork_state->sregs);
    ret = ret | compare_fpu(vcpufd, prefork_state->fpu);
    ret = ret | compare_msrs(vcpufd, prefork_state->msrs);
    ret = ret | compare_xcrs(vcpufd, prefork_state->xcrs);
    ret = ret | compare_lapic(vcpufd, prefork_state->lapic);
    ret = ret | compare_xsave(vcpufd, prefork_state->xsave);
    ret = ret | compare_debugregs(vcpufd, prefork_state->debugregs);
    ret = ret | compare_events(vcpufd, prefork_state->events);
    ret = ret | compare_clock_data(vcpufd, prefork_state->clock_data);
    ret = ret | compare_mp_state(vcpufd, prefork_state->mp_state);
    // ret = ret | compare_tsc_khz(vcpufd, prefork_state->tsc_khz);
    ret = ret | compare_pit2(vmfd, prefork_state->pit2);
    ret = ret | compare_irqchip(vmfd, prefork_state->irqchip);

    return ret;
}

int compare_regs(int vcpufd, struct kvm_regs *regs) {
    struct kvm_regs *regs2 = malloc(sizeof(struct kvm_regs));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_REGS, regs2);
    if (ret < 0) {
        perror("KVM_GET_REGS");
    }
    ret2 = memcmp(regs, regs2, sizeof(struct kvm_regs));
    if (ret2 != 0) {
        printf("KVM_REGS Comparison failed\n");
    }
    free(regs2);
    return ret2;
}


int compare_sregs(int vcpufd, struct kvm_sregs *sregs) {
    struct kvm_sregs *sregs2 = malloc(sizeof(struct kvm_sregs));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_SREGS, sregs2);
    if (ret < 0) {
        perror("KVM_GET_SREGS");
    }
    ret2 = memcmp(sregs, sregs2, sizeof(struct kvm_sregs));
    if (ret2 != 0) {
        printf("KVM_SREGS Comparison failed\n");
        printf("=========================Prefork SREGS====================\n");
        print_sregs(sregs);
        printf("=========================PostFork Sregs====================\n");
        print_sregs(sregs2);
    }
    free(sregs2);
    return ret2;
}

int compare_fpu(int vcpufd, struct kvm_fpu *fpu) {
    struct kvm_fpu *fpu2 = malloc(sizeof(struct kvm_fpu));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_FPU, fpu2);
    if (ret < 0) {
        perror("KVM_GET_FPU");
    }
    ret2 = memcmp(fpu, fpu2, sizeof(struct kvm_fpu));
    if (ret2 != 0) {
        printf("KVM_FPU Comparison failed\n");
    }
    free(fpu2);
    return ret2;
}

int compare_msrs(int vcpufd, struct kvm_msrs *msrs) {
    struct kvm_msrs *msrs2 = malloc(sizeof(struct kvm_msrs));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_MSRS, msrs2);
    if (ret < 0) {
        perror("KVM_GET_MSRS");
    }
    ret2 = memcmp(msrs, msrs2, sizeof(struct kvm_msrs));
    if (ret2 != 0) {
        printf("KVM_MSRS Comparisoin failed\n");
    }
    free(msrs2);
    return ret2;
}

int compare_xcrs(int vcpufd, struct kvm_xcrs *xcrs) {
    struct kvm_xcrs *xcrs2 = malloc(sizeof(struct kvm_xcrs));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_XCRS, xcrs2);
    if (ret < 0) {
        perror("KVM_GET_XCRS");
    }
    ret2 = memcmp(xcrs, xcrs2, sizeof(struct kvm_xcrs));
    if (ret2 != 0) {
        printf("KVM_XCRS Comparison failed\n");
    }
    free(xcrs2);
    return ret2;
}

int compare_lapic(int vcpufd, struct kvm_lapic_state *lapic) {
    struct kvm_lapic_state *lapic2 = malloc(sizeof(struct kvm_lapic_state));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_LAPIC, lapic2);
    if (ret < 0) {
        perror("KVM_GET_LAPIC");
    }
    ret2 = memcmp(lapic, lapic2, sizeof(struct kvm_lapic_state));
    if (ret2 != 0) {
        printf("KVM_LAPIC Comparison failed\n");
    }
    free(lapic2);
    return ret2;
}

int compare_xsave(int vcpufd, struct kvm_xsave *xsave) {
    struct kvm_xsave *xsave2 = malloc(sizeof(struct kvm_xsave));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_XSAVE, xsave2);
    if (ret < 0) {
        perror("KVM_GET_XSAVE");
    }
    ret2 = memcmp(xsave, xsave2, sizeof(struct kvm_xsave));
    if (ret2 != 0) {
        printf("KVM_XSAVE Comparison failed\n");
    }
    free(xsave2);
    return ret2;
}

int compare_debugregs(int vcpufd, struct kvm_debugregs *debugregs) {
    struct kvm_debugregs *debugregs2 = malloc(sizeof(struct kvm_debugregs));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_DEBUGREGS, debugregs2);
    if (ret < 0) {
        perror("KVM_GET_DEBUGREGS");
    }
    ret2 = memcmp(debugregs, debugregs2, sizeof(struct kvm_debugregs));
    if (ret2 != 0) {
        printf("KVM_DEBUGREGS Comparison failed\n");
    }
    free(debugregs2);
    return ret2;
}

int compare_mp_state(int vcpufd, struct kvm_mp_state *mp_state) {
    struct kvm_mp_state *mp_state2 = malloc(sizeof(struct kvm_mp_state));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_MP_STATE, mp_state2);
    if (ret < 0) {
        perror("KVM_GET_MP_STATE");
    }
    ret2 = memcmp(mp_state, mp_state2, sizeof(struct kvm_mp_state));
    if (ret2 != 0) {
        printf("KVM_MP_STATE Comparison failed\n");
    }
    free(mp_state2);
    return ret2;
}

int compare_events(int vcpufd, struct kvm_vcpu_events *events) {
    struct kvm_vcpu_events *events2 = malloc(sizeof(struct kvm_vcpu_events));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vcpufd, KVM_GET_VCPU_EVENTS, events2);
    if (ret < 0) {
        perror("KVM_GET_VCPU_EVENTS");
    }
    ret2 = memcmp(events, events2, sizeof(struct kvm_vcpu_events));
    if (ret2 != 0) {
        printf("KVM_VCPU_EVENTS Comparison failed\n");
    }
    free(events2);
    return ret2;
}

int compare_clock_data(int vcpufd, struct kvm_clock_data *clock_data) {
    // struct kvm_clock_data *clock_data2 = malloc(sizeof(struct kvm_clock_data));
    // int ret = 0;
    int ret2 = 0;
    // clock_data2->flags = 0;
    // ret = ioctl(vcpufd, KVM_GET_CLOCK, clock_data2);
    // if (ret < 0) {
    //     perror("KVM_GET_CLOCK");
    // }
    // ret2 = memcmp(clock_data, clock_data2, sizeof(struct kvm_clock_data));
    // if (ret2 != 0) {
    //     printf("KVM_CLOCK_DATA Comparison failed\n");
    // }
    // free(clock_data2);
    return ret2;
}

int compare_pit2(int vmfd, struct kvm_pit_state2 *pit2) {
    struct kvm_pit_state2 *pit22 = malloc(sizeof(struct kvm_pit_state2));
    int ret = 0;
    int ret2 = 0;
    ret = ioctl(vmfd, KVM_GET_PIT2, pit22);
    if (ret < 0) {
        perror("KVM_GET_PIT2");
    }
    ret2 = memcmp(pit2, pit22, sizeof(struct kvm_pit_state2));
    if (ret2 != 0) {
        printf("KVM_PIT2 Comparison failed\n");
    }
    free(pit22);
    return ret2;
}


int compare_irqchip(int vmfd, struct kvm_irqchip *irqchip) {
    return 0;
}