from pprint import pprint, pformat
import base64
from github3 import login
from github3 import authorize
from urllib2 import urlopen
import random
import string
import os
import K8S_Deploy

class K8S_Tokens(object):
    """
    K8S_Tokens.py
    Package mpw v2.0.12
    """
    gitusername = ''
    gituserpassword = ''
    gitpath = ''
    gitrepo = ''
    gitcredsfile = ''
    apik8suser = ''
    apik8screds = ''
    apik8scert = ''
    AppNamespace = ''
    _config_file_load = ''

    def __init__(self, data, api_key_str, api_host_str, api_port_str, api_ca_cert):
        """
        Initialize the K8S_app_Shell object
        :param data:
        :param api_key_str:
        :param api_host_str:
        :param api_port_str:
        :param api_ca_cert:
        """

        # Retrieve GitHub Token
        # self._list_git_repos()
        # Login into GitHub
        self._repo_login(self.gitusername, self.gituserpassword)
        # Get a new Github token
        self._get_new_git_token(self, self.gitusername, self.gituserpassword)
        # Upload the new GitHub token to a file in the repo
        self._upload_git_token_file(self, self.gitpath, self.gitcredsfile, self.gitusername, self.gitrepo,
                                    'update file: ' + str(self.gitcredsfile))
        # delete creds file from filesystem
        os.remove(self.gitcredsfile)

        # download user token and cert
        # download k8s ca certificate
        self._download_ca_cert_str = self._download_ca_cert(api_ca_cert)
        api_ca_cert = self._download_ca_cert_str
        # download k8s user key bearer token
        self._download_key_str = self._remove_cr_lf(self._download_bearer_token(api_key_str))
        api_key_str = self._download_key_str

        # load kubernetes config and credentials
        # if you are using kubeconfig from ~/.kube directory
        if self._config_file_load == 'True':
            self.extensions_v1beta1 = K8S_Deploy._get_kube_config_from_file()
        # else load the configuration manually
        else:
            # create manual configuration from inputted values
            self.extensions_v1beta1 = K8S_Deploy._create_kube_config_from_inputs(api_key_str, api_host_str,
                                                                           api_port_str, api_ca_cert)
        self._api_user_str = self.apik8suser
        # get secrets list and retrieve newest bearer token
        secret_list = K8S_Deploy.get_secrets_list_for_deployment(self, self._api_user_str)
        print("Secret List for k8s-cls-admin: ")
        # pprint(secret_list)
        print("Namespace: ")
        pprint(secret_list[0][0])
        print("Name: ")
        pprint(secret_list[0][1])
        print("Data: ")
        print("Bearer Token: ")
        pprint(secret_list[0][2]["token"])
        print("CA Certificate: ")
        pprint(secret_list[0][2]["ca.crt"])
        self._retrieved_token = secret_list[0][2]["token"]
        self._retrieved_ca_cert = secret_list[0][2]["ca.crt"]
        # convert bearer token and ca cert to 64 Bit encoded string
        self._api_key_str_b64 = self._remove_cr_lf(self._base64(self._download_key_str))
        self._api_user_str_b64 = self._remove_cr_lf(self._base64(self._api_user_str))
        self._api_ca_cert_str_b64 = self._remove_cr_lf(self._base64(api_ca_cert))

        # check stored token against Token stored in Github
        if self._retrieved_token == self._api_key_str_b64:
            print("********** Tokens Match !......")
        else:
            print("********** Tokens Do Not Match !......")
            self._api_key_str_b64 = self._retrieved_token
            self._get_new_k8s_token(self, self._retrieved_token)
            self._upload_git_token_file(self, self.gitpath, self.apik8screds, self.gitusername, self.gitrepo,
                                        'update file: ' + str(self.apik8screds))

        if self._retrieved_ca_cert == self._api_ca_cert_str_b64:
            print("********** CA Certificates Match !......")
        else:
            print("********** CA Certificate Do Not Match !......")
            self._get_new_k8s_cert(self, self._retrieved_ca_cert)
            self._upload_git_token_file(self, self.gitpath, self.apik8scert, self.gitusername, self.gitrepo,
                                        'update file: ' + str(self.apik8scert))
        # Load openshift API based on manual configuration
        # self.OAPI = self._create_os_config_from_inputs(api_key_str, api_host_str, api_port_str, api_ca_cert)
        self._create_secret_vault()

        # retrieve user token from vault
        self._user_token = K8S_Deploy._get_user_token(self.AppNamespace)
        pass

    def _create_secret_vault(self):
        secret_vault = K8S_Deploy.find_secret(self, 'secret-vault')
        if not secret_vault:
            K8S_Deploy._create_user_secret(self.AppNamespace)
            secret_pod = find_pod(self, 'secret-pod')
            if not secret_pod:
                K8S_Deploy._create_secret_pod(self.AppNamespace)
        pass

    @staticmethod
    def _base64(basestr):
        """
        conversion to Base64 for secret vault
        :param basestr
        :return:
        """
        return base64.encodestring(basestr.encode()).decode()

    @staticmethod
    def _decode_base64(basestr):
        """
        conversion to Base64 for secret vault
        :param basestr
        :return:
        """
        return basestr.decode()

    @staticmethod
    def _isBase64(basestr):
        """
        is a string base 64 encoded
        :param basestr:
        :return:
        """
        try:
            if base64.b64encode(base64.b64decode(basestr)) == basestr:
                return True
        except BaseException:
            pass
        return False


    @staticmethod
    def _upload_git_token_file(self, path, file_name, account, repo, message):
        """
        upload a token file with new git token to Github
        :param path:
        :param file_name:
        :param account:
        :param repo:
        :param message:
        :return:
        """
        repository = self._github_login.repository(account, repo)
        with open(file_name, 'rb') as fd:
            contents = fd.read()
        contents_object = repository.file_contents(path + file_name)
        print('New k8s Token or Cert: ')
        pprint(contents)
        contents_object.update(message, contents)
        pass


    @staticmethod
    def _get_new_git_token(self, user, password):
        """
        Get a newly refreshed token from Github
        :param user:
        :param password:
        :return:
        """
        randstr = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(8))
        note = user + '-token-' + randstr
        note_url = 'https://raw.githubusercontent.com/mpw07458/K8S-Deploy-Shell/master/pure-play/drivers/' \
                    'K8S_App_Shell/src/tokens/'
        scopes = ['user', 'repo']
        auth = authorize(user, password, scopes, note, note_url)
        print('Authorization token: ')
        pprint(auth.token)
        print('Authorization id: ')
        pprint(auth.id)
        strid = str(int(auth.id) + 1)
        print(strid)
        with open(self.gitcredsfile, 'w') as fd:
            fd.seek(0)
            fd.write(auth.token + '\n')
            fd.write(strid)
        pass


    @staticmethod
    def _get_new_k8s_token(self, token):
        """
        write token to k8s token file
        :param token:
        :return:
        """
        with open(self.apik8screds, 'w') as fd:
            token_decoded = self._decode_base64(token)
            fd.seek(0)
            fd.write(token_decoded)
        pass


    @staticmethod
    def _get_new_k8s_cert(self, cert):
        """
        write token to k8s token file
        :param cert:
        :return:
        """
        with open(self.apik8scert, 'w') as fd:
            cert_decoded = self._decode_base64(cert)
            cert_checked = self._check_ca_cert(cert_decoded)
            fd.seek(0)
            fd.write(cert_checked)
        pass

    @staticmethod
    def _download_file_URL(file_url):
        """
        download a file from github or other scm
        :param file_url:
        :return data:
        """
        f = urlopen(file_url)
        data = f.read()
        return data

    @staticmethod
    def _remove_cr_lf(token_str):
        """
        remove CR LF from string
        :param token_str:
        :return:
        """
        return token_str.replace('\n', '').replace('\r', '')

    @staticmethod
    def _list_git_repos():
        """
        List all Github repositories
        :return:
        """
        from github3 import all_repositories
        for repository in all_repositories(number=50):
            print('{0}, id: {0.id}, url: {0.html_url}'.format(repository))
        pass


    def _repo_login(self, username, password):
        """
        Login to repo and retrieve User object
        :param username:
        :param password:
        :return:
        """
        self._github_login = login(username=username, password=password)
        self._login_ID = self._github_login.me()
        # <AuthenticatedUser [mpw07458:Michael P Williams]>
        print(self._login_ID.name)
        # Michael P Williams
        print(self._login_ID.login)
        # mpw07458
        print(self._login_ID.followers_count)
        # 1
        for f in self._login_ID.followers():
            print(str(f))
        # graboskyc = self._github_login.user('graboskyc')
        # <User [kennethreitz:Kenneth Reitz]>
        # print(graboskyc.name)
        # print(graboskyc.login)
        # print(graboskyc.followers_count)
        self._github_login.followers = [str(f) for f in self._login_ID.followers()]
        print(self._github_login.followers)
        pass

    def _download_yaml_data(self, yaml_file_URL):
        """
        download Data from yaml file
        :param yaml_file_URL:
        :return:
        """
        return self._download_file_URL(yaml_file_URL)

    def _download_ca_cert(self, ca_cert):
        """
        download the CA CERT
        :return:
        """
        return self._download_file_URL(ca_cert)

    def _download_bearer_token(self, api_key):
        """
        download the bearer token
        :return:
        """
        return self._download_file_URL(api_key)

    def _check_ca_cert(self, ca_cert):
        """
        Check and validate the CA Cert
        :param ca_cert:
        :return:
        """
        if ca_cert.count("\n") > 15:
            print ("CA Cert is Good")
            return ca_cert
        else:
            print ("CA Cert is Bad")
            new_cacert = self._build_ca_cert(ca_cert)
            return new_cacert

    @staticmethod
    def _prepare_ca_cert(ca_cert):
        """
        split a ca cert into lines
        :param ca_cert:
        :return:
        """
        return ca_cert.splitlines()

    @staticmethod
    def _build_ca_cert(ca_cert):
        """
        Build a CA Cert if the cert will not validate
        :param ca_cert:
        :return:
        """
        built_ca_cert = ca_cert[27:-25]
        n = 64
        list_lines = [built_ca_cert[i:i + n] for i in range(0, len(built_ca_cert), n)]
        built_ca_cert = '-----BEGIN CERTIFICATE-----' + '\n'
        index = 0
        while index < len(list_lines):
            built_ca_cert = built_ca_cert + list_lines[index] + '\n'
            index += 1
        built_ca_cert = built_ca_cert + '-----END CERTIFICATE----'
        return built_ca_cert
