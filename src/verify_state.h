#ifndef VERIFY_STATE_H 
#define VERIFY_STATE_H


#include <asm/kvm.h>
#include "vm.h"

// main comparison function
int compare_state(int vmfd, int vcpufd, pre_fork_state_t *prefork_state);


int compare_regs(int vcpufd, struct kvm_regs *regs);
int compare_sregs(int vcpufd, struct kvm_sregs *sregs);
int compare_xsave(int vcpufd, struct kvm_xsave *xsave);
int compare_msrs(int vcpufd, struct kvm_msrs *msrs);
int compare_xcrs(int vcpufd, struct kvm_xcrs *xcrs);
int compare_lapic(int vcpufd, struct kvm_lapic_state *lapic);
int compare_fpu(int vcpufd, struct kvm_fpu *fpu);
int compare_events(int vcpufd, struct kvm_vcpu_events *events);
int compare_debugregs(int vcpufd, struct kvm_debugregs *debugregs);
int compare_clock_data(int vcpufd, struct kvm_clock_data *clock_data);
int compare_mp_state(int vcpufd, struct kvm_mp_state *mp_state);
int compare_tsc_khz(int vcpufd, uint32_t tsc_khz);

int compare_pit2(int vmfd, struct kvm_pit_state2 *pit2);
int compare_irqchip(int vmfd, struct kvm_irqchip *irqchip);








#endif /* VERIFY_STATE_H */