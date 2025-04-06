import iptc
import yaml
import logging
import time

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_file):
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    return config

def configure_firewall(config):
    table = iptc.Table(iptc.Table.FILTER)
    table.flush()  # Очистить существующие правила

    # Создание цепочки INPUT, если ее не существует
    chain = None
    try:
        chain = iptc.Chain(table, "INPUT")
    except iptc.ChainError:
        chain = table.create_chain("INPUT")

    # Политика по умолчанию: DROP для всего входящего трафика
    chain.set_policy("DROP") # Policy needs to be a string.

    # Разрешить существующие соединения
    rule = iptc.Rule()
    match = rule.create_match("conntrack")
    match.ctstate = "ESTABLISHED,RELATED" # Установка состояний соединения
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target
    chain.insert_rule(rule)

    # # Разрешить трафик на loopback интерфейсе
    rule = iptc.Rule()
    rule.in_interface = "lo"
    target = iptc.Target(rule, "ACCEPT")
    rule.target = target
    chain.insert_rule(rule)

    # Разрешить разрешенные порты (TCP)
    for port in config['allowed_ports']['tcp']:
        
        rule = iptc.Rule()
        rule.protocol = "tcp"
        match = rule.create_match("tcp")
        match.dport = str(port) # iptables требует строку
        rule.add_match(match)
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        chain.insert_rule(rule)
        logging.info(f"Разрешен TCP порт {port}")

    # Разрешить разрешенные порты (UDP)
    for port in config['allowed_ports']['udp']:
        rule = iptc.Rule()
        rule.protocol = "udp"
        match = rule.create_match("udp")
        match.dport = str(port) # iptables требует строку
        rule.add_match(match)
        chain.insert_rule(rule)
        logging.info(f"Разрешен UDP порт {port}")
 
    logging.info("Файрвол настроен")

def main():
    config = load_config("config.yaml")
    setup_logging(config['log_file'])
    configure_firewall(config)
    print("Файрвол запущен. Проверьте firewall.log")

if __name__ == "__main__":
    main()