#!/usr/bin/env python
from bcc import BPF
import sys
import socket
import struct

# Определения
SOURCE_CODE = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/socket.h>
#include <linux/in.h>

// Хеш-таблица для хранения адресов заблокированных соединений (можно расширить)
BPF_HASH(blocked_connections, struct sock *, u64);

// Функция для извлечения номера порта из sockaddr_in
static inline u16 get_port(struct sockaddr_in *addr) {
    return ntohs(addr->sin_port);
}

// Точка перехвата - inet_csk_reqsk_queue_hashreq() - вызывается при получении запроса на новое соединение TCP
int kprobe__inet_csk_reqsk_queue_hashreq(struct pt_regs *ctx, struct sock *sk, struct request_sock *req) {
    struct sock *sk_node = req->sk;

    // Получаем адрес удаленного сокета
    struct sockaddr_in *remote_addr = (struct sockaddr_in *)&sk_node->sk_addr;
    u16 remote_port = get_port(remote_addr);

    // Получаем адрес локального сокета
    struct sockaddr_in *local_addr = (struct sockaddr_in *)&sk->sk_addr;
    u16 local_port = get_port(local_addr);

    // Фильтруем трафик, разрешаем только HTTP (80) и HTTPS (443)
    if (local_port != 80 && local_port != 443 && remote_port != 80 && remote_port != 443) {
        // Блокируем соединение - сохраняем адрес сокета в хеш-таблице
        u64 timestamp = bpf_ktime_get_ns();
        blocked_connections.insert(sk_node, &timestamp);
        bpf_trace_printk("Blocking connection to port: %d from port: %d\\n", remote_port, local_port);
    }

    return 0;
}

// Точка перехвата - tcp_v4_syn_recv_sock() - вызывается при установке нового соединения TCP
int kretprobe__tcp_v4_syn_recv_sock(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_RC(ctx);

    // Проверяем, заблокировано ли соединение
    u64 *timestamp = blocked_connections.lookup(&sk);
    if (timestamp != NULL) {
        // Если соединение заблокировано, освобождаем сокет (дропаем пакет)
        bpf_trace_printk("Dropping blocked connection\\n");
        bpf_probe_read_kernel((void *)sk->__sk_common.skc_state, sizeof(int), &(int){TCP_CLOSE}); // Устанавливаем состояние TCP_CLOSE
        blocked_connections.delete(&sk); // Удаляем из хеш-таблицы
    }

    return 0;
}
"""

# Загрузка BPF-программы
b = BPF(text=SOURCE_CODE)

# Обработчик событий (опционально - для мониторинга)
def print_event(cpu, data, size):
    event = b["blocked_connections"].event(data)
    print(f"Blocked connection: {event.sock}")

#b["blocked_connections"].open_perf_buffer(print_event) # Раскомментируйте для мониторинга

# Запуск
print("Firewall started. Blocking all traffic except HTTP (80) and HTTPS (443)...")

try:
    while True:
        #b.perf_buffer_poll() # Раскомментируйте для мониторинга
        sys.stdout.flush()
        b.kprobe_poll() # Альтернатива perf_buffer_poll, если perf_buffer не используется
except KeyboardInterrupt:
    print("Firewall stopped.")