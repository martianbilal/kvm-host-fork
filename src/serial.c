#include <linux/serial_reg.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "err.h"
#include "serial.h"
#include "utils.h"
#include "vm.h"

#define SERIAL_IRQ 4
#define IO_READ8(data) *((uint8_t *) data)
#define IO_WRITE8(data, value) ((uint8_t *) data)[0] = value

struct serial_dev_priv {
    uint8_t dll;
    uint8_t dlm;
    uint8_t iir;
    uint8_t ier;
    uint8_t fcr;
    uint8_t lcr;
    uint8_t mcr;
    uint8_t lsr;
    uint8_t msr;
    uint8_t scr;

    struct fifo rx_buf;
};

static struct serial_dev_priv serial_dev_priv = {
    .iir = UART_IIR_NO_INT,
    .mcr = UART_MCR_OUT2,
    .lsr = UART_LSR_TEMT | UART_LSR_THRE,
    .msr = UART_MSR_DCD | UART_MSR_DSR | UART_MSR_CTS,
};

/* FIXME: This implementation is incomplete */
static void serial_update_irq(serial_dev_t *s)
{
    struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;
    uint8_t iir = UART_IIR_NO_INT;

    /* If enable receiver data interrupt and receiver data ready */
    if ((priv->ier & UART_IER_RDI) && (priv->lsr & UART_LSR_DR))
        iir = UART_IIR_RDI;
    /* If enable transmiter data interrupt and transmiter empty */
    else if ((priv->ier & UART_IER_THRI) && (priv->lsr & UART_LSR_TEMT))
        iir = UART_IIR_THRI;

    priv->iir = iir | 0xc0;
    // printf("\tserialupdateirq: %d\n", iir);

    /* FIXME: the return error of vm_irq_line should be handled */
    vm_irq_line(container_of(s, vm_t, serial), SERIAL_IRQ,
                iir == UART_IIR_NO_INT ? 0 /* inactive */ : 1 /* active */);
}

static int serial_readable(serial_dev_t *s, int timeout)
{
    struct pollfd pollfd = (struct pollfd){
        .fd = s->infd,
        .events = POLLIN,
    };
    return (poll(&pollfd, 1, timeout) > 0) && (pollfd.revents & POLLIN);
}

#define FREQ_NS ((int) (1.0e6))
#define NS_PER_SEC ((int) (1.0e9))

/* global state to stop the loop of thread */
static volatile bool thread_stop = false;

static void *serial_thread(serial_dev_t *s)
{
    int did_fork = 0;
    int is_child = 0;
    int first_time_after_fork = 1;
    int first_time_after_fork_child = 1;

    ski_forkall_thread_add_self_tid();
    while (!__atomic_load_n(&thread_stop, __ATOMIC_RELAXED)) {
        if(!did_fork) {
            ski_forkall_slave(&did_fork, &is_child);
            for(int i = 0; i < 3000; i++){
                int j = 3 * 4 - 1;
            }
            if (serial_readable(s, 10))
            {
                // sleep(2);
                pthread_kill((pthread_t) s->main_tid, SIGUSR1);

            }
        } else if (did_fork){
            if(!is_child && first_time_after_fork) {
                // wait(NULL);
                // wait_for_child();
                first_time_after_fork = 0;
            } 

            // find the new main tid
            if (is_child && first_time_after_fork_child) {
                printf("child: %d", getpid());
                // s->main_tid = ski_forkall_thread_get_main_tid();
                // s->worker_tid = pthread_self();
                first_time_after_fork_child = 0;
            } 
            if (serial_readable(s, -1))
            {
                // sleep(2);
                pthread_kill((pthread_t) s->main_tid, SIGUSR1);

            }
        }
        
    }

    return NULL;
}

void serial_console(serial_dev_t *s)
{
    struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;

    // printf("[%d]serial_console: %d", getpid(), priv->lsr);
    if (priv->lsr & UART_LSR_DR || !fifo_is_empty(&priv->rx_buf)){
        // printf("returning=--==-==\n");
        return;
    }

    while (!fifo_is_full(&priv->rx_buf) && serial_readable(s, 0)) {
        char c;
        if (read(s->infd, &c, 1) == -1)
            break;
        // printf("read: %c", c);
        if (!fifo_put(&priv->rx_buf, c))
            break;
        // printf("put: %c", c);

        priv->lsr |= UART_LSR_DR;
        
    }
    
    // printf("[%d]serial_console\n", getpid());
    serial_update_irq(s);
}

static void serial_in(serial_dev_t *s, uint16_t offset, void *data)
{
    struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;

    switch (offset) {
    case UART_RX:
        if (priv->lcr & UART_LCR_DLAB) {
            IO_WRITE8(data, priv->dll);
        } else {
            if (fifo_is_empty(&priv->rx_buf))
                break;

            uint8_t value;
            if (fifo_get(&priv->rx_buf, value))
                IO_WRITE8(data, value);

            if (fifo_is_empty(&priv->rx_buf)) {
                priv->lsr &= ~UART_LSR_DR;
                serial_update_irq(s);
            }
        }
        break;
    case UART_IER:
        if (priv->lcr & UART_LCR_DLAB)
            IO_WRITE8(data, priv->dlm);
        else
            IO_WRITE8(data, priv->ier);
        break;
    case UART_IIR:
        IO_WRITE8(data, priv->iir | 0xc0); /* 0xc0 stands for FIFO enabled */
        break;
    case UART_LCR:
        IO_WRITE8(data, priv->lcr);
        break;
    case UART_MCR:
        IO_WRITE8(data, priv->mcr);
        break;
    case UART_LSR:
        IO_WRITE8(data, priv->lsr);
        break;
    case UART_MSR:
        IO_WRITE8(data, priv->msr);
        break;
    case UART_SCR:
        IO_WRITE8(data, priv->scr);
        break;
    default:
        break;
    }
}

static void serial_out(serial_dev_t *s, uint16_t offset, void *data)
{
    struct serial_dev_priv *priv = (struct serial_dev_priv *) s->priv;

    switch (offset) {
    case UART_TX:
        if (priv->lcr & UART_LCR_DLAB) {
            priv->dll = IO_READ8(data);
        } else {
            priv->lsr |= (UART_LSR_TEMT | UART_LSR_THRE); /* flush TX */
            putchar(((char *) data)[0]);
            fflush(stdout);
            serial_update_irq(s);
        }
        break;
    case UART_IER:
        if (!(priv->lcr & UART_LCR_DLAB)) {
            priv->ier = IO_READ8(data);
            serial_update_irq(s);
        } else {
            priv->dlm = IO_READ8(data);
        }
        break;
    case UART_FCR:
        priv->fcr = IO_READ8(data);
        break;
    case UART_LCR:
        priv->lcr = IO_READ8(data);
        break;
    case UART_MCR:
        priv->mcr = IO_READ8(data);
        break;
    case UART_LSR: /* factory test */
    case UART_MSR: /* not used */
        break;
    case UART_SCR:
        priv->scr = IO_READ8(data);
        break;
    default:
        break;
    }
}

void handler(int sig, siginfo_t *si, void *uc) {}

int serial_init(serial_dev_t *s)
{
    sigset_t mask;

    // OLD CODE
    // struct sigaction sa = {.sa_flags = SA_SIGINFO, .sa_sigaction = handler};

    // NEW CODE
    struct sigaction *sp = malloc(sizeof(struct sigaction));
    struct sigaction sa = {.sa_flags = SA_SIGINFO, .sa_sigaction = handler};
    
    sigemptyset(&sa.sa_mask);
    
    memcpy(sp, &sa, sizeof(struct sigaction));
    prefork_state->sigact = sp;

    
    if (sigaction(SIGUSR1, &sa, NULL) == -1)
        return throw_err("Failed to create signal handler");
    

    /* Block timer signal temporarily. */
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1)
        return throw_err("Failed to block timer signal");

    *s = (serial_dev_t){
        .priv = (void *) &serial_dev_priv,
        .main_tid = pthread_self(),
        .infd = STDIN_FILENO,
    };
    // pthread_create(&s->worker_tid, NULL, (void *) serial_thread, (void *) s);
    ski_forkall_pthread_create(&s->worker_tid, NULL, (void *) serial_thread, (void *) s);

    /* Unlock the timer signal, so that timer notification
     * can be delivered.
     */
    if (sigprocmask(SIG_UNBLOCK, &mask, NULL) == -1)
        return throw_err("Failed to unblock timer signal");

    return 0;
}

void serial_handle(serial_dev_t *s, struct kvm_run *r)
{
    void *data = (uint8_t *) r + r->io.data_offset;
    void (*serial_op)(serial_dev_t *, uint16_t, void *) =
        (r->io.direction == KVM_EXIT_IO_OUT) ? serial_out : serial_in;
    // if(r->io.port == 1021 || r->io.port == 1017){
        // printf("serial_handle: port: %d, count: %d, size: %d, direction: %d\n", r->io.port, r->io.count, r->io.size, r->io.direction);
    // }
    uint32_t c = r->io.count;
    for (uint16_t off = r->io.port - COM1_PORT_BASE; c--; data += r->io.size)
        serial_op(s, off, data);
}

void serial_exit(serial_dev_t *s)
{
    __atomic_store_n(&thread_stop, true, __ATOMIC_RELAXED);
    pthread_join(s->worker_tid, NULL);
}
