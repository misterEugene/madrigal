#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define IFACE "eth0" // Замените на имя вашего интерфейса

static int if_nametoindex_wrapper(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Error getting interface index for %s: %s\n", ifname, strerror(errno));
        exit(EXIT_FAILURE);
    }
    return ifindex;
}

static int create_map(const char *map_name) {
    struct bpf_map_def map_def;
    memset(&map_def, 0, sizeof(map_def));

    if (strcmp(map_name, "packet_count_map") == 0) {
        map_def.type        = BPF_MAP_TYPE_ARRAY;
        map_def.key_size    = sizeof(int);
        map_def.value_size  = sizeof(long long);
        map_def.max_entries = 1;
    } else {
        fprintf(stderr, "Unknown map name: %s\n", map_name);
        return -1;
    }

    return bpf_create_map(map_def.type, map_def.key_size, map_def.value_size,
                         map_def.max_entries, 0);
}


int main() {
    int prog_fd, map_fd, ifindex;
    char bpf_log_buf[BPF_LOG_BUF_SIZE];
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;

    // 1. Загрузка BPF-программы

    // Настройки компилятора libbpf
    struct bpf_prog_load_opts prog_load_opts = {
        .log_level = 0,
        .log_buf = bpf_log_buf,
        .log_size = BPF_LOG_BUF_SIZE,
    };

    // Загрузка BPF-объекта из файла
    obj = bpf_object__open_file("count_packets.o", &prog_load_opts);
    if (!obj) {
        fprintf(stderr, "Error opening BPF object file: %s\n", strerror(errno));
        fprintf(stderr, "BPF log: %s\n", bpf_log_buf); // Вывод лога компиляции
        return EXIT_FAILURE;
    }

    // Фиксируем все read-only переменные внутри BPF-объекта
    bpf_object__for_each_program(prog, obj) {
        bpf_program__set_prog_type(prog, BPF_PROG_TYPE_XDP);
    }
    // Загрузка BPF-объекта в ядро
    int err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error loading BPF object: %s\n", strerror(errno));
        fprintf(stderr, "BPF log: %s\n", bpf_log_buf); // Вывод лога компиляции
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    // Получаем файловый дескриптор программы
    prog = bpf_object__find_program_by_name(obj, "count_packets");
        if (!prog) {
            fprintf(stderr, "Error finding program 'count_packets'\n");
            bpf_object__close(obj);
            return EXIT_FAILURE;
        }

    prog_fd = bpf_program__fd(prog);


    // 2. Получение файлового дескриптора карты (map)
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "packet_count_map");

    if (!map) {
        fprintf(stderr, "Error: Cannot find map 'packet_count_map'\n");
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    map_fd = bpf_map__fd(map);
     if (map_fd < 0) {
        fprintf(stderr, "Error getting map file descriptor: %s\n", strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }

    // 3. Прикрепление XDP-программы к сетевому интерфейсу
    ifindex = if_nametoindex_wrapper(IFACE);


    if (bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_PRESENT, NULL)) {
        fprintf(stderr, "Error attaching XDP program to interface %s: %s\n", IFACE, strerror(errno));
        bpf_object__close(obj);
        return EXIT_FAILURE;
    }
    printf("XDP program attached to interface %s\n", IFACE);

    // 4. Чтение счетчика пакетов из карты (map)
    int key = 0;
    long long count = 0;

    while (1) {
        if (bpf_map_lookup_elem(map_fd, &key, &count) != 0) {
            fprintf(stderr, "Error reading packet count: %s\n", strerror(errno));
            break;
        }

        printf("Packet count: %lld\n", count);
        sleep(1);
    }
    
    // 5. Отсоединение XDP-программы
    if (bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_PRESENT, NULL)) {
        fprintf(stderr, "Error detaching XDP program from interface %s: %s\n", IFACE, strerror(errno));
    }
    printf("XDP program detached from interface %s\n", IFACE);

    // 6. Закрытие файлового дескриптора программы
    bpf_object__close(obj);

    return EXIT_SUCCESS;
}