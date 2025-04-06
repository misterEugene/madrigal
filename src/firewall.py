#!/usr/bin/env python3

from bcc import BPF
import time

# Определяем BPF программу (на C)
# Обратите внимание на использование TEXT_SECTION.  Это важно для корректной работы libbpf.
program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>  /* For struct task_struct */

// Определяем структуру данных, которую хотим передать из ядра в пространство пользователя
struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

// Объявляем BPF хеш-таблицу для передачи данных из ядра в пользовательское пространство
BPF_PERF_OUTPUT(events);

int kprobe__do_sys_openat2(struct pt_regs *ctx, int dirfd, const char *filename, int flags, umode_t mode) {
    // Получаем PID текущего процесса
    u32 pid = bpf_get_current_pid_tgid();

    // Создаем экземпляр нашей структуры данных
    struct data_t data = {};

    // Заполняем структуру данными
    data.pid = pid;
    data.ts = bpf_ktime_get_ns();  // Получаем текущее время в наносекундах
    bpf_get_current_comm(&data.comm, sizeof(data.comm)); // Получаем имя команды (процесса)

    // Копируем имя файла из пространства ядра в нашу структуру
    bpf_probe_read_user_str(data.filename, sizeof(data.filename), (void *)filename);


    // Отправляем данные в пространство пользователя через BPF_PERF_OUTPUT
    events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

# Инициализируем BPF
b = BPF(text=program)

# Определяем функцию для обработки событий
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid} COMM: {event.comm.decode()} FILENAME: {event.filename.decode()}")


# Прикрепляем функцию обработки событий
b["events"].open_perf_buffer(print_event)

# Читаем события бесконечно
try:
    while True:
        b.perf_buffer_poll()
        time.sleep(0.1)
except KeyboardInterrupt:
    pass