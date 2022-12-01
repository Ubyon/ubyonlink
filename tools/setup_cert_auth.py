"""
Description: This script is to enable certificate based auth on SSH host(Linux server) to be accessed using Ubyon Link
Author: Ubyon Inc
"""
import requests
import os
import sys
import distro
import argparse

ubcookie = None

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--host", default='manage.ubyon.com', help="Ubyon management portal FQDN")
parser.add_argument("-k", "--api-key-id", required=True, help="Ubyon Service account key ID")
parser.add_argument("-n", "--ssh-cert-key-name", required=True, help="SSH certificate key name")
parser.add_argument("-l", "--ssh-login-id", required=True, help="End user's SSH login id")
parser.add_argument("-p", "--ssh-principal", required=True, help="End user's auth principal name")


def login():
    """
    This method logs into the Ubyon system in order to run the REST API
    """
    headers = {
        'X-UBY-APIKEY': args.api_key_id
    }
    url = "https://{}/api/v1/login".format(args.host)
    response = requests.request("POST", url, headers=headers)
    print(response.status_code)
    if response.status_code != 204:
        print("Login failed, exiting")
        exit(1)
    cookie_dict = response.cookies.get_dict()
    ubsession = cookie_dict.get('ubsession')
    ubsession_2 = cookie_dict.get('ubsession_2')
    global ubcookie
    ubcookie = "ubsession={}; ubsession_2={}".format(ubsession, ubsession_2)


def get_ssh_key():
    """
    This method retrieves the SSH certificate's userKey using the REST API provided by Ubyon and writes the same to
    /etc/ssh/ca_cert.pub file
    """
    headers = {
        'Cookie': ubcookie
    }
    url = "https://{}/ssh-ca/v1/signing-keys".format(args.host)
    response = requests.request('GET', url, headers=headers)
    res_json = response.json()
    for key in res_json:
        if key['keyName'] == args.ssh_cert_key_name:
            print(key['keyName'], key['userKey'])
            f = open('/etc/ssh/ca_cert.pub', 'w+')
            f.write(key['userKey'])
            f.close()
        else:
            print("Unable to fetch the SSH keys from Ubyon, please try again after sometime")


def modify_host():
    """
    This method performs the below operations:
    1. Modifies the sshd configuration
    2. Enables the certificate based auth for SSH
    3. Creates mapping of ssh login id to user's auth principal
    4. Restarts ssh service
    :return:
    """
    ssh_cfg_dir = '/etc/ssh'
    ssh_cfg_file = '{}/sshd_config'.format(ssh_cfg_dir)
    auth_principal_dir = '{}/auth_principals'.format(ssh_cfg_dir)
    auth_principal_file = '{}/{}'.format(auth_principal_dir, args.ssh_login_id)
    # Create auth_principals dir and its mapping file
    if not os.path.exists(auth_principal_dir):
        os.mkdir(auth_principal_dir)
    f = open(auth_principal_file, 'a+')
    f.write(args.ssh_principal+'\n')
    f.close()
    # Modify the sshd_config file to enable certificate based auth
    with open(ssh_cfg_file, "r+") as file:
        for line in file:
            if 'TrustedUserCAKeys /etc/ssh/ca_cert.pub' in line:
                print('Certificate auth is already enabled, not going to modifying the sshd_config')
                break
        else:
            file.write('TrustedUserCAKeys /etc/ssh/ca_cert.pub'+'\n')
        for line in file:
            if 'AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u' in line:
                print('Auth principals config present, not going to modifying the sshd_config')
                break
        else:
            file.write('AuthorizedPrincipalsFile /etc/ssh/auth_principals/%u'+'\n')
    # Restart ssh service
    if (distro.id()).lower() == 'ubuntu':
        os.system('sudo systemctl restart ssh')
    elif (distro.id()).lower() == 'centos':
        os.system('sudo service sshd restart')


def main():
    login()
    get_ssh_key()
    modify_host()


if __name__ == '__main__':
    args = parser.parse_args()
    sys.exit(main())

