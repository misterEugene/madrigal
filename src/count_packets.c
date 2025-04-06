#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define SEC(NAME) attribute((section(NAME), used))

// Определяем карту (map) для хранения счетчика пакетов
struct bpf_map_def SEC("maps") packet_count_map = {
    .type        = BPF_MAP_TYPE_ARRAY,  // Тип карты: массив
    .key_size    = sizeof(int),          // Размер ключа (int)
    .value_size  = sizeof(long long),    // Размер значения (long long)
    .max_entries = 1                     // Максимальное количество элементов (1)
};

// eBPF программа, которая будет выполняться для каждого пакета
SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    int key = 0; // Ключ для доступа к элементу в карте (всегда 0, т.к. max_entries = 1)
    long long *count = bpf_map_lookup_elem(&packet_count_map, &key); // Получаем указатель на значение счетчика

    if (count) {
        (*count)++; // Увеличиваем счетчик
    }

    return XDP_PASS; // Пропускаем пакет
}

char _license[] SEC("license") = "GPL";