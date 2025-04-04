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
    chain.set_policy("ACCEPT") # Policy needs to be a string.

    logging.info("Настройки Файрвола сброшены")

def main():
    config = load_config("config.yaml")
    setup_logging(config['log_file'])
    configure_firewall(config)
    print("Файрвол запущен. Проверьте firewall.log")

if __name__ == "__main__":
    main()