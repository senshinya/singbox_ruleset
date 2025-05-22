import csv
import os
import shutil
import logging
import requests
import zipfile
import json
from collections import defaultdict

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

current_dir = os.getcwd()
asn_url = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key={}&suffix=zip'
asn_v4 = defaultdict(list)
asn_v6 = defaultdict(list)

def init():
    # 删除已有文件夹
    dir_path = os.path.join(current_dir, 'rule')
    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        logging.warning('{} exists, delete!', dir_path)
        shutil.rmtree(dir_path)
    os.makedirs(dir_path)

    # 获取 asn 文件
    maxmind_key = os.environ.get('MAXMIND_KEY')
    if not maxmind_key.strip():
        logging.critical('MAXMIND_KEY not set!')
        exit(1)
    logging.info('downloading asn file...')
    zip_path = os.path.join(current_dir, 'asn.zip')
    response = requests.get(asn_url.format(maxmind_key), headers=headers)
    if response.status_code == 200:
        with open(zip_path, 'wb') as file:
            file.write(response.content)
        logging.info('downloading asn file complete')
    else:
        logging.critical(f'downloading asn file error, error code {response.status_code}')
        exit(1)

    # 解压 asn 文件
    asn_folder_path = os.path.join(current_dir, 'asn')
    os.makedirs(asn_folder_path, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        file_list = zip_ref.namelist()
        # 检查 ZIP 文件中是否只有一个文件夹
        outer_folder = file_list[0].split('/')[0]
        for file_name in file_list:
            # 跳过第一层级的文件夹名
            if file_name.startswith(outer_folder + '/'):
                # 去掉第一层级的文件夹名
                file_name_without_outer = file_name[len(outer_folder) + 1:]
                # 设定解压的目标路径
                target_file_path = os.path.join(asn_folder_path, file_name_without_outer)
                # 解压文件到目标路径
                with open(target_file_path, 'wb') as output_file:
                    output_file.write(zip_ref.read(file_name))
        logging.info(f"unzip asn files to {asn_folder_path}")
    
    # 汇总 asn 信息
    asn_v4_file = os.path.join(asn_folder_path, 'GeoLite2-ASN-Blocks-IPv4.csv')
    asn_v6_file = os.path.join(asn_folder_path, 'GeoLite2-ASN-Blocks-IPv6.csv')
    with open(asn_v4_file, mode='r', encoding='utf-8'):
        csv_reader = csv.reader(asn_v4_file, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if not row or len(row) < 2:
                continue
            asn_v4[int(row[1])].append(row[0])
    with open(asn_v6_file, mode='r', encoding='utf-8'):
        csv_reader = csv.reader(asn_v6_file, delimiter=',')
        next(csv_reader)
        for row in csv_reader:
            if not row or len(row) < 2:
                continue
            asn_v4[int(row[1])].append(row[0])
    logging.info('aggregating asn info finishes')

source_repo_url = "https://github.com/blackmatrix7/ios_rule_script/archive/refs/heads/master.zip"
def download_source_repo():
    logging.info('downloading rule source file...')
    source_zip = os.path.join(current_dir, 'ios_rule_script.zip')
    response = requests.get(source_repo_url, headers=headers)
    if response.status_code == 200:
        with open(source_zip, 'wb') as file:
            file.write(response.content)
        logging.info('downloading rule source complete')
    else:
        logging.critical(f'downloading rule source error, error code {response.status_code}')
        exit(1)
    source_folder = os.path.join(current_dir, 'ios_rule_script')
    os.makedirs(source_folder, exist_ok=True)
    with zipfile.ZipFile(source_zip, 'r') as zip_ref:
        zip_ref.extractall(source_folder)
        logging.info(f"unzip asn files to {source_folder}")

class RuleSet(object):
    def __init__(self, domain, domain_keyword, domain_suffix, ip_cidr, process_name):
        self.version = 2
        self.rules = list()
        if len(domain) != 0 or len(domain_keyword) != 0 or len(domain_suffix) != 0 or len(ip_cidr) != 0:
            rule = dict()
            if len(domain) != 0:
                rule['domain'] = list(set(domain))
            if len(domain_keyword) != 0:
                rule['domain_keyword'] = list(set(domain_keyword))
            if len(domain_suffix) != 0:
                rule['domain_suffix'] = list(set(domain_suffix))
            if len(ip_cidr) != 0:
                rule['ip_cidr'] = list(set(ip_cidr))
            self.rules.append(rule)
        if len(process_name) != 0:
            rule = dict()
            rule['process_name'] = list(set(process_name))
            self.rules.append(rule)

subs = ["Assassin'sCreed", "Cloud"]
def translate_rule():
    source_folder = os.path.join(current_dir, 'ios_rule_script/ios_rule_script-master/rule/Clash')
    target_folder = os.path.join(current_dir, 'rule')
    for entry in os.listdir(source_folder):
        if entry == 'CGB':
            continue
        source_dir = os.path.join(source_folder, entry)
        target_dir = os.path.join(target_folder, entry)
        if not os.path.isdir(os.path.join(source_folder, entry)):
            continue
        if entry in subs:
            for subEntry in os.listdir(source_dir):
                sub_source_dir = os.path.join(source_dir, subEntry)
                sub_target_dir = os.path.join(target_folder, subEntry)
                translate_source_to_target(subEntry, sub_source_dir, sub_target_dir)
        else:
            translate_source_to_target(entry, source_dir, target_dir)

    logging.info(f"finish translating clash rules")

def translate_source_to_target(entry, source_dir, target_dir):
    if not os.path.exists(target_dir):
        os.makedirs(target_dir)
    source_file = os.path.join(source_dir, f'{entry}.yaml')
    if os.path.exists(os.path.join(source_dir, f'{entry}_Classical.yaml')):
        source_file = os.path.join(source_dir, f'{entry}_Classical.yaml')
    target_file = os.path.join(target_dir, f'{entry}.json')

    domain = list()
    domain_keyword = list()
    domain_suffix = list()
    ip_cidr = list()
    process_name = list()

    found_payload = False
    with open(source_file, 'r', encoding='utf-8') as file:
        for line in file:
            if 'payload:' in line.strip():
                found_payload = True
                continue
            if not found_payload:
                continue
            splits = line.strip()[2:].split(',')
            rule_type = splits[0]
            rule_content = splits[1]
            if rule_type == 'DOMAIN':
                domain.append(rule_content)
            elif rule_type == 'DOMAIN-SUFFIX':
                domain_suffix.append(rule_content)
            elif rule_type == 'DOMAIN-KEYWORD':
                domain_keyword.append(rule_content)
            elif rule_type == 'IP-CIDR' or rule_type == 'IP-CIDR6':
                ip_cidr.append(rule_content)    
            elif rule_type == 'IP-ASN':
                ip_cidr.extend(asn_v4[int(rule_content)])
                ip_cidr.extend(asn_v6[int(rule_content)])
            elif rule_type == 'PROCESS-NAME':
                process_name.append(rule_content)
            else:
                logging.warning(f'Unknown rule type { rule_type }')

    rule_content = RuleSet(domain, domain_keyword, domain_suffix, ip_cidr, process_name)
    with open(target_file, 'w') as json_file:
        json.dump(rule_content, json_file, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)
    readme_file = os.path.join(target_dir, f'README.md')
    with open(readme_file, 'w') as readme:
        readme.write(f'# {entry}\n\n#### 规则链接\n\n**Github**\nhttps://raw.githubusercontent.com/senshinya/singbox_ruleset/main/rule/{entry}/{entry}.srs\n\n**CDN**\nhttps://cdn.jsdelivr.net/gh/senshinya/singbox_ruleset@main/rule/{entry}/{entry}.srs')

extra_surge_conf = {}
def translate_extra():
    logging.info('translating extra surge rule...')
    target_folder = os.path.join(current_dir, 'rule')
    for k, v in extra_surge_conf.items():
        source_file = os.path.join(current_dir, f'{k}.conf')
        response = requests.get(v, headers=headers)
        if response.status_code == 200:
            with open(source_file, 'wb') as file:
                file.write(response.content)
            logging.info(f'downloading {k}.conf complete')
        else:
            logging.critical(f'downloading {k}.conf error, error code {response.status_code}')
            exit(1)

        domain = list()
        domain_keyword = list()
        domain_suffix = list()
        ip_cidr = list()
        process_name = list()

        with open(source_file, 'r', encoding='utf-8') as file:
            for line in file:
                if len(line.strip()) == 0:
                    continue
                if line.startswith('#'):
                    continue
                splits = line.strip().split(',')
                rule_type = splits[0]
                rule_content = splits[1]
                if rule_type == 'DOMAIN':
                    domain.append(rule_content)
                elif rule_type == 'DOMAIN-SUFFIX':
                    domain_suffix.append(rule_content)
                elif rule_type == 'DOMAIN-KEYWORD':
                    domain_keyword.append(rule_content)
                elif rule_type == 'IP-CIDR' or rule_type == 'IP-CIDR6':
                    ip_cidr.append(rule_content)    
                elif rule_type == 'IP-ASN':
                    ip_cidr.extend(asn_v4[int(rule_content)])
                    ip_cidr.extend(asn_v6[int(rule_content)])
                elif rule_type == 'PROCESS-NAME':
                    process_name.append(rule_content)
                elif rule_type == 'USER-AGENT':
                    pass
                else:
                    logging.warning(f'Unknown rule type { rule_type }')
        os.makedirs(os.path.join(target_folder, k))
        target_dir = os.path.join(target_folder, k) 
        target_file = os.path.join(target_dir, f'{k}.json')        
        rule_content = RuleSet(domain, domain_keyword, domain_suffix, ip_cidr, process_name)
        with open(target_file, 'w') as json_file:
            json.dump(rule_content, json_file, default=lambda obj: obj.__dict__, sort_keys=True, indent=2)
        readme_file = os.path.join(target_dir, f'README.md')
        with open(readme_file, 'w') as readme:
            readme.write(f'# {k}\n\n#### 规则链接\n\n**Github**\nhttps://raw.githubusercontent.com/senshinya/singbox_ruleset/main/rule/{k}/{k}.srs\n\n**CDN**\nhttps://cdn.jsdelivr.net/gh/senshinya/singbox_ruleset@main/rule/{k}/{k}.srs')

def post_clean():
    shutil.rmtree(os.path.join(current_dir, 'asn'))
    shutil.rmtree(os.path.join(current_dir, 'ios_rule_script'))
    os.remove(os.path.join(current_dir, 'asn.zip'))
    os.remove(os.path.join(current_dir, 'ios_rule_script.zip'))
    for key in extra_surge_conf:
        os.remove(os.path.join(current_dir, f'{key}.conf'))

def main():
    init()
    download_source_repo()
    translate_rule()
    translate_extra()
    post_clean()

if __name__ == "__main__":
    main()
